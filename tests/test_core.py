"""Self-contained tests for the DetectLens offline posture engine.

All fixtures are synthetic and defined in this file; nothing depends on
data/seed.  The engine scenario below is hand-computed — the expected
values are derived by hand in the comments, not copied from the
implementation.
"""

import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone

import pytest

from backend.alerts import Alert, count_by_rule, filter_days, load_alerts
from backend.attack_data import TACTICS, Technique, load_attack_subset
from backend.config import AppConfig, config_path, load_config, save_config
from backend.findings import (
    GLOSSARY,
    Finding,
    build_findings,
)
from backend.posture import compute_posture
from backend.redact import RedactionToggles, redact_text
from backend.report import render_markdown_report
from backend.validate import validate_rule_xml
from backend.wazuh_rules import parse_rule_file, parse_ruleset


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RULES_XML = """<group name="test,">
  <rule id="100001" level="3">
    <description>Test rule one</description>
    <group>syslog,</group>
    <mitre>
      <id>T1059</id>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100002" level="10">
    <description>Test rule two</description>
    <group>authentication,</group>
  </rule>
</group>
"""

# Whole-file XML is broken (unclosed <description> in the second block), so
# the parser must fall back to per-block parsing: 1 rule parsed, 1 skipped.
MALFORMED_XML = """<group name="test,">
  <rule id="100001" level="3">
    <description>Valid rule</description>
    <group>syslog,</group>
  </rule>
  <rule id="100002" level="3">
    <description>Broken rule
    <group>syslog,</group>
  </rule>
</group>
"""

OVERRIDE_BASE_XML = """<group name="base,">
  <rule id="9001" level="5">
    <description>base description</description>
    <group>syslog,</group>
  </rule>
</group>
"""

OVERRIDE_LOCAL_XML = """<group name="local,">
  <rule id="9001" level="9">
    <description>local description</description>
    <group>syslog,</group>
  </rule>
</group>
"""


def _make_rules():
    """Hand-computed engine scenario (rules only; mitre ids chosen freely)."""
    from backend.wazuh_rules import Rule

    return [
        Rule(201, 5, "exec alpha", ["syslog"], ["T2001", "T2002"], "r.xml", "<rule/>"),
        Rule(202, 5, "exec alpha backup", ["syslog"], ["T2001"], "r.xml", "<rule/>"),
        Rule(203, 7, "credential dump", ["auth"], ["T2003"], "r.xml", "<rule/>"),
        Rule(204, 3, "generic log line", ["syslog"], [], "r.xml", "<rule/>"),
        Rule(205, 5, "persistence hook", ["syslog"], ["T2004"], "r.xml", "<rule/>"),
    ]


def _make_techniques():
    return [
        Technique("T2001", "Exec Alpha", ["Execution"],
                  ["Process: Process Creation"], "desc"),
        Technique("T2002", "Exec Beta", ["Execution"],
                  ["Process: Process Creation"], "desc"),
        Technique("T2003", "Cred Alpha", ["Credential Access"],
                  ["Logon Session: Logon Session Creation"], "desc"),
        Technique("T2004", "Pers Alpha", ["Persistence"],
                  ["File: File Creation"], "desc"),
        Technique("T2005", "Exfil Alpha", ["Exfiltration"],
                  ["Network Traffic: Network Traffic Content"], "desc"),
    ]


def _make_alerts():
    """201 x5, 202 x0, 203 x120, 204 x3, 205 x0  => 128 alerts total."""
    now = datetime.now(timezone.utc)
    alerts = []

    def add(rule_id, n):
        for _ in range(n):
            alerts.append(
                Alert(now, rule_id, f"alert for {rule_id}", "agent-01",
                      "10.0.0.5", 5)
            )

    add(201, 5)
    add(203, 120)
    add(204, 3)
    return alerts


# Hand-computed expectations for the scenario above:
#
# Technique mapping (exact MITRE id match):
#   T2001 -> rules [201, 202] -> covered,  fire = 5 + 0   = 5
#   T2002 -> rules [201]      -> partial,  fire = 5       = 5
#   T2003 -> rules [203]      -> partial,  fire = 120     = 120
#   T2004 -> rules [205]      -> partial,  fire = 0       = 0
#   T2005 -> rules []         -> uncovered,fire = 0       = 0
#
# Rule health (noisy threshold 100):
#   201 healthy(5), 202 dead(0), 203 noisy(120), 204 healthy(3), 205 dead(0)
#
# Collected data components (union over techniques with >=1 mapped rule):
#   {Process: Process Creation, Logon Session: Logon Session Creation,
#    File: File Creation}
# Missing telemetry: only T2005 — uncovered and its sole data component
#   (Network Traffic: Network Traffic Content) is outside the collected set.
#
# Coverage by tactic:
#   Execution: covered 1, partial 1, uncovered 0, total 2
#   Credential Access: 0/1/0/1 ; Persistence: 0/1/0/1 ; Exfiltration: 0/0/1/1
#   all other tactics: 0/0/0/0
#
# Posture score:
#   coverage_ratio = (1 + 0.5*3) / 5 = 0.5
#   dead_ratio     = 2 / 5           = 0.4
#   noisy_ratio    = 1 / 5           = 0.2
#   score = round(100 * (0.6*0.5 + 0.25*0.6 + 0.15*0.8))
#         = round(100 * (0.30 + 0.15 + 0.12)) = round(57.0) = 57
#
# Totals: rules 5, alerts 128, rules_fired 3 (201, 203, 204).


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


def test_parse_valid_rules(tmp_path):
    p = tmp_path / "rules.xml"
    p.write_text(SAMPLE_RULES_XML)
    rules, warnings = parse_rule_file(p)
    assert len(rules) == 2
    r1, r2 = rules
    assert (r1.id, r1.level) == (100001, 3)
    assert r1.description == "Test rule one"
    assert r1.groups == ["syslog"]
    assert r1.mitre_ids == ["T1059", "T1059.001"]
    assert r1.source_file == str(p)
    assert "<rule" in r1.xml
    assert (r2.id, r2.level) == (100002, 10)
    assert r2.mitre_ids == []


def test_parse_malformed_blocks_skipped_gracefully(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text(MALFORMED_XML)
    rules, warnings = parse_rule_file(p)
    assert len(rules) == 1
    assert rules[0].id == 100001
    assert len(warnings) >= 1  # whole-file failure + skipped block
    assert any("100002" in w or "malformed" in w for w in warnings)


def test_parse_rule_without_id_is_skipped(tmp_path):
    p = tmp_path / "noid.xml"
    p.write_text(
        "<group><rule level=\"3\"><description>x</description></rule></group>"
    )
    rules, warnings = parse_rule_file(p)
    assert rules == []
    assert any("without id" in w for w in warnings)


def test_parse_non_integer_id_is_skipped(tmp_path):
    p = tmp_path / "badid.xml"
    p.write_text(
        "<group><rule id=\"abc\" level=\"3\"><description>x</description></rule></group>"
    )
    rules, warnings = parse_rule_file(p)
    assert rules == []
    assert any("non-integer id" in w for w in warnings)


def test_parse_ruleset_local_rules_override(tmp_path):
    base = tmp_path / "rules"
    base.mkdir()
    (base / "a.xml").write_text(OVERRIDE_BASE_XML)
    local = tmp_path / "local_rules.xml"
    local.write_text(OVERRIDE_LOCAL_XML)
    rules, warnings = parse_ruleset(base, local_rules=local)
    assert len(rules) == 1
    assert rules[0].description == "local description"
    assert rules[0].level == 9
    assert any("overrides" in w for w in warnings)


def test_parse_ruleset_missing_dir_warns(tmp_path):
    rules, warnings = parse_ruleset(tmp_path / "does-not-exist")
    assert rules == []
    assert any("not found" in w for w in warnings)


# ---------------------------------------------------------------------------
# Alerts tests
# ---------------------------------------------------------------------------


def test_load_alerts_and_count(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps([
        {"timestamp": "2026-10-01T08:00:00Z", "rule_id": 1,
         "description": "a", "agent": "ag1", "ip": "10.0.0.1", "level": 5},
        {"timestamp": "2026-10-01T08:01:00+00:00", "rule_id": 1,
         "description": "b", "agent": "ag1", "ip": None, "level": 5},
        # naive timestamp is assumed UTC
        {"timestamp": "2026-10-01T08:02:00", "rule_id": 2,
         "description": "c", "agent": "ag2", "level": 3},
    ]))
    alerts = load_alerts(p)
    assert len(alerts) == 3
    assert all(a.timestamp.tzinfo is not None for a in alerts)
    assert all(a.timestamp.tzinfo == timezone.utc for a in alerts)
    assert count_by_rule(alerts) == {1: 2, 2: 1}


def test_load_alerts_rejects_malformed(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps([{"rule_id": 1}]))  # missing timestamp
    with pytest.raises(ValueError, match="index 0"):
        load_alerts(p)


def test_filter_days():
    now = datetime.now(timezone.utc)
    alerts = [
        Alert(now - timedelta(days=40), 1, "old", "a", None, 3),
        Alert(now - timedelta(hours=1), 1, "new", "a", None, 3),
    ]
    kept = filter_days(alerts, 30)
    assert len(kept) == 1
    assert kept[0].description == "new"


# ---------------------------------------------------------------------------
# ATT&CK data tests
# ---------------------------------------------------------------------------


def test_tactics_canonical_order():
    assert TACTICS == [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion",
        "Credential Access", "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Impact",
    ]


def test_load_attack_subset(tmp_path):
    p = tmp_path / "attack.json"
    p.write_text(json.dumps([
        {"id": "T1059", "name": "Command and Scripting Interpreter",
         "tactics": ["Execution"],
         "data_components": ["Process: Process Creation"],
         "description": "d"},
    ]))
    techs = load_attack_subset(p)
    assert len(techs) == 1
    assert techs[0].id == "T1059"
    assert techs[0].tactics == ["Execution"]
    assert techs[0].data_components == ["Process: Process Creation"]


# ---------------------------------------------------------------------------
# Posture engine tests (hand-computed expectations)
# ---------------------------------------------------------------------------


def test_engine_coverage_map():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    cov = posture.technique_coverage
    assert (cov["T2001"].state, cov["T2001"].rule_ids, cov["T2001"].fire_count) == \
        ("covered", [201, 202], 5)
    assert (cov["T2002"].state, cov["T2002"].rule_ids, cov["T2002"].fire_count) == \
        ("partial", [201], 5)
    assert (cov["T2003"].state, cov["T2003"].rule_ids, cov["T2003"].fire_count) == \
        ("partial", [203], 120)
    assert (cov["T2004"].state, cov["T2004"].rule_ids, cov["T2004"].fire_count) == \
        ("partial", [205], 0)
    assert (cov["T2005"].state, cov["T2005"].rule_ids, cov["T2005"].fire_count) == \
        ("uncovered", [], 0)
    assert (posture.covered, posture.partial, posture.uncovered,
            posture.techniques_total) == (1, 3, 1, 5)


def test_engine_rule_health():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    health = posture.rule_health
    assert (health[201].state, health[201].fire_count) == ("healthy", 5)
    assert (health[202].state, health[202].fire_count) == ("dead", 0)
    assert (health[203].state, health[203].fire_count) == ("noisy", 120)
    assert (health[204].state, health[204].fire_count) == ("healthy", 3)
    assert (health[205].state, health[205].fire_count) == ("dead", 0)


def test_engine_coverage_by_tactic():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    by_tactic = posture.coverage_by_tactic
    assert by_tactic["Execution"] == {"covered": 1, "partial": 1, "uncovered": 0, "total": 2}
    assert by_tactic["Credential Access"] == {"covered": 0, "partial": 1, "uncovered": 0, "total": 1}
    assert by_tactic["Persistence"] == {"covered": 0, "partial": 1, "uncovered": 0, "total": 1}
    assert by_tactic["Exfiltration"] == {"covered": 0, "partial": 0, "uncovered": 1, "total": 1}
    assert by_tactic["Impact"] == {"covered": 0, "partial": 0, "uncovered": 0, "total": 0}
    assert set(by_tactic) == set(TACTICS)


def test_engine_missing_telemetry():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    assert len(posture.missing_telemetry) == 1
    entry = posture.missing_telemetry[0]
    assert entry["technique_id"] == "T2005"
    assert entry["technique_name"] == "Exfil Alpha"
    assert entry["data_components"] == ["Network Traffic: Network Traffic Content"]
    assert "reason" in entry and entry["reason"]


def test_engine_posture_score_and_totals():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    assert posture.posture_score == 57
    assert posture.totals == {"rules": 5, "alerts": 128, "rules_fired": 3}
    assert posture.window_days == 30


def test_engine_empty_inputs_do_not_crash():
    posture = compute_posture([], [], [])
    # Empty input: coverage ratio is defined as 0 (no techniques), while
    # dead/noisy ratios are 0 (no rules) -> 100*(0 + 0.25 + 0.15) = 40.
    assert posture.posture_score == 40
    assert posture.totals == {"rules": 0, "alerts": 0, "rules_fired": 0}


# ---------------------------------------------------------------------------
# Findings tests
# ---------------------------------------------------------------------------


def test_findings_order_ids_and_citations():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    findings = build_findings(posture, _make_rules(), _make_techniques())
    ids = [f.id for f in findings]
    assert ids == [f"F{i:03d}" for i in range(1, len(findings) + 1)]
    assert [f.severity for f in findings] == (
        ["medium"] * 4 + ["low"] + ["info"] * 3
    )
    kinds = [f.kind for f in findings]
    assert kinds[:4] == ["dead_rule", "dead_rule", "noisy_rule", "missing_telemetry"]
    assert kinds[4] == "coverage_gap"
    assert kinds[5:] == ["coverage_gap"] * 3

    dead202 = findings[0]
    assert dead202.rule_ids == [202]
    assert "202" in dead202.explanation and "0 times" in dead202.explanation
    noisy = findings[2]
    assert "203" in noisy.explanation and "120" in noisy.explanation
    telemetry = findings[3]
    assert "T2005" in telemetry.explanation
    gap = findings[4]
    assert "T2005" in gap.explanation

    # every finding has a non-empty explanation and lesson
    for f in findings:
        assert f.explanation.strip()
        assert f.lesson.strip()
        assert f.status == "new"


def test_findings_critical_gap_first_and_stable():
    techs = _make_techniques() + [
        Technique("T2006", "Exec Gamma", ["Execution"],
                  ["Process: Process Creation"], "desc"),
    ]
    posture = compute_posture(_make_rules(), _make_alerts(), techs)
    first = build_findings(posture, _make_rules(), techs)
    second = build_findings(posture, _make_rules(), techs)
    assert first[0].severity == "critical"
    assert first[0].kind == "coverage_gap"
    assert first[0].technique_ids == ["T2006"]
    assert "T2006" in first[0].explanation
    assert [f.id for f in first] == [f.id for f in second]


def test_glossary_has_required_terms():
    required = {"severity", "coverage", "detection gap", "false positive",
                "suppression", "telemetry", "data component", "mitre att&ck",
                "technique", "tactic", "dead rule", "noisy rule",
                "posture score", "dwell"}
    assert required <= set(GLOSSARY)
    for term, definition in GLOSSARY.items():
        assert definition.strip()
        assert definition == definition.strip()


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------

VALID_RULE_XML = (
    '<rule id="100001" level="3">'
    "<description>Valid rule</description>"
    "<group>syslog,</group>"
    "<mitre><id>T1059</id><id>T1059.001</id></mitre>"
    "</rule>"
)


def test_validate_accepts_valid_rule():
    result = validate_rule_xml(VALID_RULE_XML)
    assert result.ok
    assert result.errors == []


def test_validate_rejects_bad_id():
    assert not validate_rule_xml(VALID_RULE_XML.replace('id="100001"', 'id="abc"')).ok
    assert not validate_rule_xml(VALID_RULE_XML.replace('id="100001"', 'id="0"')).ok


def test_validate_rejects_missing_level():
    assert not validate_rule_xml(
        VALID_RULE_XML.replace(' level="3"', "")
    ).ok


def test_validate_rejects_malformed_mitre():
    assert not validate_rule_xml(
        VALID_RULE_XML.replace("<id>T1059</id>", "<id>X1234</id>")
    ).ok
    assert not validate_rule_xml(
        VALID_RULE_XML.replace("<id>T1059</id>", "<id>T12</id>")
    ).ok


def test_validate_rejects_missing_description_and_group():
    no_desc = VALID_RULE_XML.replace(
        "<description>Valid rule</description>", ""
    )
    assert not validate_rule_xml(no_desc).ok
    no_group = VALID_RULE_XML.replace("<group>syslog,</group>", "")
    assert not validate_rule_xml(no_group).ok


def test_validate_rejects_malformed_xml_and_wrong_root():
    assert not validate_rule_xml("<rule><description>oops").ok
    assert not validate_rule_xml("<group></group>").ok
    assert not validate_rule_xml("").ok


# ---------------------------------------------------------------------------
# Redaction tests
# ---------------------------------------------------------------------------


def test_redaction_toggles_on():
    text = (
        "alert from 192.168.1.10 on web-01.corp.example.com, "
        "agent: web-01, user: jdoe, User jdoe logged in, uid=jdoe"
    )
    out = redact_text(text, RedactionToggles())
    assert "[REDACTED_IP]" in out and "192.168.1.10" not in out
    assert "[REDACTED_HOST]" in out
    assert "web-01.corp.example.com" not in out
    assert "agent: [REDACTED_HOST]" in out
    assert "user: [REDACTED_USER]" in out
    assert "User [REDACTED_USER] logged in" in out
    assert "uid=[REDACTED_USER]" in out
    assert "jdoe" not in out


def test_redaction_toggles_off_unchanged():
    text = "from 192.168.1.10 on web-01.corp.example.com user: jdoe"
    toggles = RedactionToggles(ips=False, hostnames=False, usernames=False)
    assert redact_text(text, toggles) == text


def test_redaction_partial_toggles():
    text = "from 192.168.1.10 user: jdoe"
    out = redact_text(text, RedactionToggles(ips=False))
    assert "192.168.1.10" in out  # ip kept
    assert "[REDACTED_USER]" in out
    out = redact_text(text, RedactionToggles(usernames=False))
    assert "[REDACTED_IP]" in out
    assert "jdoe" in out  # username kept


def test_redaction_idempotent():
    text = "alert 10.0.0.1 web-01.example.com user: jdoe"
    once = redact_text(text)
    assert redact_text(once) == once


# ---------------------------------------------------------------------------
# Report tests
# ---------------------------------------------------------------------------


def test_render_markdown_report():
    posture = compute_posture(_make_rules(), _make_alerts(), _make_techniques())
    findings = build_findings(posture, _make_rules(), _make_techniques())
    meta = {
        "title": "Detection Posture Audit",
        "rules_dir": "/var/ossec/etc/rules",
        "alerts_source": "/var/ossec/logs/alerts/alerts.json",
        "technique_names": {t.id: t.name for t in _make_techniques()},
    }
    report = render_markdown_report(posture, findings, _make_rules(), meta)
    assert report.startswith("# Detection Posture Audit")
    assert "Generated:" in report
    assert "**57 / 100**" in report
    assert "| Execution | 1 | 1 | 0 | 2 |" in report
    assert "## Dead rules" in report and "| 202 |" in report
    assert "## Noisy rules" in report and "| 203 |" in report
    assert "### F001" in report
    assert "not attacks blocked" in report
    assert "last 30 days" in report
    assert "`/var/ossec/etc/rules`" in report


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Point HOME at a temp dir so tests never touch the real ~/.detectlens."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for var in ("DETECTLENS_LLM_KEY", "DETECTLENS_PROVIDER", "DETECTLENS_BASE_URL",
                "DETECTLENS_MODEL", "DETECTLENS_LOCAL_ONLY",
                "DETECTLENS_RULES_DIR", "DETECTLENS_ALERTS"):
        monkeypatch.delenv(var, raising=False)
    return home


def test_config_defaults(isolated_home):
    cfg = load_config()
    assert cfg.provider == "none"
    assert cfg.api_key is None
    assert cfg.local_only is True
    assert cfg.redact_ips is True
    assert cfg.window_days == 30


def test_config_env_overrides_file(isolated_home, monkeypatch):
    save_config(AppConfig(provider="ollama", model="file-model", api_key="file-key"))
    monkeypatch.setenv("DETECTLENS_PROVIDER", "openai_compat")
    monkeypatch.setenv("DETECTLENS_MODEL", "env-model")
    monkeypatch.setenv("DETECTLENS_LLM_KEY", "env-key")
    monkeypatch.setenv("DETECTLENS_LOCAL_ONLY", "false")
    monkeypatch.setenv("DETECTLENS_RULES_DIR", "/rules")
    cfg = load_config()
    assert cfg.provider == "openai_compat"
    assert cfg.model == "env-model"
    assert cfg.api_key == "env-key"
    assert cfg.local_only is False
    assert cfg.rules_dir == "/rules"


def test_config_save_uses_0600_and_roundtrips(isolated_home):
    save_config(AppConfig(provider="anthropic", api_key="roundtrip-key"))
    path = config_path()
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    cfg = load_config()
    assert cfg.provider == "anthropic"
    assert cfg.api_key == "roundtrip-key"


def test_config_warns_on_loose_permissions(isolated_home, capsys):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("provider: none\n")
    os.chmod(path, 0o644)
    load_config()
    assert "0600" in capsys.readouterr().err


def test_config_invalid_provider_env_warns(isolated_home, monkeypatch, capsys):
    monkeypatch.setenv("DETECTLENS_PROVIDER", "bogus")
    cfg = load_config()
    assert cfg.provider == "none"
    assert "bogus" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Key hygiene: no secrets committed in the source tree
# ---------------------------------------------------------------------------


def test_no_secrets_in_source_tree():
    """Scan backend/ and tests/ source files for secret-looking patterns.

    The negative fixtures below are built by string concatenation so they
    cannot match the scan themselves.  data/seed is deliberately excluded:
    only source is scanned.
    """
    root = __import__("pathlib").Path(__file__).resolve().parent.parent
    suffixes = {".py", ".yaml", ".yml", ".json", ".txt", ".md",
                ".toml", ".cfg", ".ini", ".env", ".sh"}
    sk_prefix = "sk" + "-"           # would-be OpenAI-style key prefix
    llm_key_assignment = "DETECTLENS_LLM_KEY" + "="  # env var with a value
    private_key_marker = "BEGIN PRIVATE " + "KEY"
    aws_key_prefix = "AK" + "IA"     # would-be AWS access key prefix
    patterns = [
        (re.compile(re.escape(sk_prefix) + r"[A-Za-z0-9]{8,}"), "key-like token"),
        (re.compile(re.escape(llm_key_assignment) + r"\s*['\"]?[^\s'\"]+"),
         "env var with value"),
        (re.compile(re.escape(private_key_marker)), "private key block"),
        (re.compile(re.escape(aws_key_prefix) + r"[A-Z0-9]{16}"), "aws key"),
    ]
    hits = []
    for base in ("backend", "tests"):
        for path in (root / base).rglob("*"):
            if path.is_file() and path.suffix in suffixes:
                text = path.read_text(encoding="utf-8", errors="replace")
                for pattern, label in patterns:
                    if pattern.search(text):
                        hits.append(f"{path}: {label}")
    assert hits == [], f"secret-like patterns found in source: {hits}"
