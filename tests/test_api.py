"""API tests for the DetectLens FastAPI backend.

Uses ``fastapi.testclient.TestClient`` against the real app.  The real
``~/.detectlens/config.yaml`` is never touched: ``backend.config.config_path``
is monkeypatched to a tmp file before the app's lifespan runs.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

import backend.app as appmod
import backend.config as configmod
from backend.alerts import load_alerts
from backend.attack_data import TACTICS, load_attack_subset
from backend.posture import compute_posture
from backend.wazuh_rules import parse_ruleset


SEED = appmod.PROJECT_ROOT / "data" / "seed"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    """TestClient with config redirected to a tmp file (never ~/.detectlens)."""
    fake_cfg = tmp_path / "config.yaml"
    monkeypatch.setattr(configmod, "config_path", lambda: fake_cfg)
    with TestClient(appmod.app) as c:
        yield c
    # No config file should have been created unless a test saved settings.
    assert configmod.config_path() == fake_cfg


def _engine_posture():
    rules, _ = parse_ruleset(SEED / "rules", SEED / "local_rules.xml")
    alerts = load_alerts(SEED / "alerts.json")
    latest = max(a.timestamp for a in alerts)
    windowed = [a for a in alerts if a.timestamp >= latest - timedelta(days=30)]
    techniques = load_attack_subset(appmod.SEED_TECHNIQUES)
    return compute_posture(rules, windowed, techniques, window_days=30)


# ---------------------------------------------------------------------------
# Overview / ground truth
# ---------------------------------------------------------------------------


def test_overview_matches_expected_md(client):
    res = client.get("/api/overview")
    assert res.status_code == 200
    body = res.json()
    totals = body["totals"]
    assert totals["rules"] == 44
    assert totals["alerts"] == 5000
    assert totals["techniques"] == 52
    assert totals["covered"] == 5
    assert totals["partial"] == 20
    assert totals["uncovered"] == 27
    assert totals["dead"] == 3
    assert totals["healthy"] == 38
    assert totals["noisy"] == 3
    assert totals["rules_fired"] == 41
    assert body["window_days"] == 30
    # Posture score is the engine's score verbatim.
    assert body["posture_score"] == _engine_posture().posture_score
    # Per-tactic table matches the engine's coverage_by_tactic.
    tactic = body["coverage_by_tactic"]["Execution"]
    assert tactic == {"covered": 1, "partial": 4, "uncovered": 1, "total": 6}
    assert body["coverage_by_tactic"]["Exfiltration"]["uncovered"] == 3
    # Coverage % = techniques with >=1 mapped rule (covered + partial).
    assert totals["covered"] + totals["partial"] == 25
    # Top findings are full objects.
    assert len(body["top_findings"]) == 5
    assert all(set(f) >= {"id", "severity", "title", "explanation"} for f in body["top_findings"])


def test_rules_health_matches_expected_md(client):
    body = client.get("/api/rules").json()["rules"]
    by_id = {r["id"]: r for r in body}
    assert len(body) == 44
    assert sorted(i for i, r in by_id.items() if r["state"] == "dead") == [50012, 50013, 52011]
    assert sorted(i for i, r in by_id.items() if r["state"] == "noisy") == [50001, 51001, 52007]
    assert by_id[50001]["fire_count"] == 2800
    assert by_id[51001]["fire_count"] == 1400
    assert by_id[52007]["fire_count"] == 600


def test_heatmap(client):
    body = client.get("/api/heatmap").json()
    assert body["tactics"] == TACTICS
    assert len(body["tactics"]) == 14
    cells = body["cells"]
    assert len(cells) == 52
    by_id = {c["technique_id"]: c for c in cells}
    assert by_id["T1059.001"]["state"] == "covered"
    assert by_id["T1059.001"]["tactic"] == "Execution"
    assert by_id["T1059.001"]["rule_count"] >= 1
    assert by_id["T1486"]["state"] == "uncovered"
    assert by_id["T1547.001"]["state"] == "partial"  # mapped once, on a dead rule
    states = {c["state"] for c in cells}
    assert states <= {"covered", "partial", "uncovered"}


# ---------------------------------------------------------------------------
# Findings and rule detail
# ---------------------------------------------------------------------------


def test_findings_list_and_stable_ids(client):
    first = client.get("/api/findings").json()["findings"]
    second = client.get("/api/findings").json()["findings"]
    assert len(first) > 0
    assert [f["id"] for f in first] == [f["id"] for f in second]
    assert [f["id"] for f in first] == [f"F{i:03d}" for i in range(1, len(first) + 1)]


def test_finding_detail_and_404(client):
    res = client.get("/api/findings/F001")
    assert res.status_code == 200
    assert res.json()["finding"]["id"] == "F001"
    res = client.get("/api/findings/NOPE")
    assert res.status_code == 404


def test_rule_detail_xml_and_validation(client):
    res = client.get("/api/rules/50001")
    assert res.status_code == 200
    rule = res.json()["rule"]
    assert rule["id"] == 50001
    assert "<rule" in rule["xml"]
    assert rule["validation"]["ok"] is True
    assert rule["validation"]["errors"] == []
    res = client.get("/api/rules/999999")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Report download
# ---------------------------------------------------------------------------


def test_report_md_download(client):
    res = client.get("/api/report.md")
    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    assert "detectlens-report-" in res.headers["content-disposition"]
    assert "techniques with at least one mapped rule" in res.text
    assert res.text.startswith("# DetectLens Detection Posture Audit")


def test_glossary(client):
    terms = client.get("/api/glossary").json()["terms"]
    assert terms["dead rule"].startswith("a rule that fired zero times")


# ---------------------------------------------------------------------------
# AI endpoints in local mode
# ---------------------------------------------------------------------------


def test_ai_status_local_mode(client):
    body = client.get("/api/ai/status").json()
    assert body["mode"] == "local"
    assert body["provider"] == "none"
    assert body["local_only"] is True
    assert body["redaction"] == {"ips": True, "hostnames": True, "usernames": True}
    assert "api_key" not in json.dumps(body)


def test_ai_test_connection_local_mode(client):
    body = client.post("/api/ai/test-connection").json()
    assert body["ok"] is False
    assert "local mode" in body["message"]


def test_ai_explain_template_fallback(client):
    res = client.post("/api/ai/explain", json={"finding_id": "F001"})
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "template"
    assert body["text"].strip()
    res = client.post("/api/ai/explain", json={"finding_id": "NOPE"})
    assert res.status_code == 404
    res = client.post("/api/ai/explain", json={})
    assert res.status_code == 400


def test_ai_draft_rule_offline_valid_xml(client):
    res = client.post("/api/ai/draft-rule", json={"technique_id": "T1486"})
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "offline"
    assert body["validation"]["ok"] is True
    assert body["validation"]["errors"] == []
    assert "<rule" in body["xml"] and "T1486" in body["xml"]
    assert "detectlens,attack" in body["xml"]
    assert "wazuh-analysisd -t" in body["note"]
    assert "Nothing is auto-applied" in body["note"]
    res = client.post("/api/ai/draft-rule", json={"technique_id": "T9999"})
    assert res.status_code == 404


def test_ai_suppression_offline(client):
    res = client.post("/api/ai/suppression", json={"rule_id": 50001})
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "offline"
    assert body["validation"]["ok"] is True
    assert "<if_sid>50001</if_sid>" in body["xml"]
    assert "<frequency>" in body["xml"]
    assert isinstance(body["plan"], list) and len(body["plan"]) >= 3
    res = client.post("/api/ai/suppression", json={"rule_id": 999999})
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

NDJSON = "\n".join(
    json.dumps(
        {
            "timestamp": ts,
            "rule_id": rid,
            "description": "d",
            "agent": "a1",
            "ip": "10.0.0.1",
            "level": 3,
        }
    )
    for ts, rid in [
        ("2026-09-20T10:00:00Z", 50001),
        ("2026-09-21T10:00:00Z", 51001),
        ("2026-09-22T10:00:00Z", 52007),
    ]
)


def test_upload_alerts_and_reload(client):
    try:
        res = client.post(
            "/api/alerts/upload",
            files={"file": ("test-alerts.json", NDJSON, "application/json")},
        )
        assert res.status_code == 200
        assert res.json() == {"alerts_loaded": 3, "window_days": 30}
        assert client.get("/api/overview").json()["totals"]["alerts"] == 3
        # Reload drops the upload and goes back to the configured seed data.
        res = client.post("/api/reload")
        assert res.status_code == 200
        assert res.json()["alerts"] == 5000
        assert client.get("/api/overview").json()["totals"]["alerts"] == 5000
    finally:
        (appmod.UPLOADS_DIR / "test-alerts.json").unlink(missing_ok=True)


def test_upload_rejects_non_json(client):
    res = client.post(
        "/api/alerts/upload", files={"file": ("notes.txt", b"hello", "text/plain")}
    )
    assert res.status_code == 400


def test_upload_rejects_unparsable_json(client):
    res = client.post(
        "/api/alerts/upload",
        files={"file": ("bad.json", b"this is not json", "application/json")},
    )
    assert res.status_code == 400


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_settings_persist_toggles_and_never_echo_key(client, tmp_path):
    res = client.post(
        "/api/settings",
        json={
            "provider": "none",
            "local_only": True,
            "redact_ips": False,
            "redact_hostnames": True,
            "redact_usernames": False,
            "api_key": "",
        },
    )
    assert res.json() == {"ok": True, "mode": "local"}

    status = client.get("/api/ai/status").json()
    assert status["redaction"] == {"ips": False, "hostnames": True, "usernames": False}

    # Set a key: persisted to the (tmp) config file at 0600, never echoed.
    res = client.post("/api/settings", json={"api_key": "sk-test-secret-123"})
    assert res.status_code == 200
    assert "sk-test-secret-123" not in res.text
    assert "sk-test-secret-123" not in client.get("/api/ai/status").text

    cfg_path = configmod.config_path()
    assert cfg_path.is_file()
    assert cfg_path.stat().st_mode & 0o777 == 0o600
    saved = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert saved["api_key"] == "sk-test-secret-123"
    assert saved["redact_ips"] is False

    # Empty api_key keeps the existing key.
    client.post("/api/settings", json={"api_key": "", "redact_ips": True})
    saved = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert saved["api_key"] == "sk-test-secret-123"
    assert saved["redact_ips"] is True


def test_settings_rejects_bad_provider(client):
    res = client.post("/api/settings", json={"provider": "bogus"})
    assert res.status_code == 400


# ---------------------------------------------------------------------------
# AI adapter paths (stubbed adapter — no network, no key)
# ---------------------------------------------------------------------------


class _StubAdapter:
    name = "stub"

    def __init__(self, fail=False):
        self.fail = fail
        self.seen = []

    def chat(self, messages, max_tokens=1500, timeout=60.0):
        from backend.ai.base import AIError

        if self.fail:
            raise AIError("stub provider exploded")
        self.seen = list(messages)
        return (
            '<rule id="100100" level="7">\n'
            "  <description>Stub drafted rule.</description>\n"
            "  <group>detectlens,attack,</group>\n"
            "  <mitre><id>T1486</id></mitre>\n"
            "</rule>"
        )

    def test_connection(self):
        return (True, "stub ok")


def test_ai_mode_uses_adapter_and_redacts_payload(client, monkeypatch):
    stub = _StubAdapter()
    monkeypatch.setattr(appmod, "_adapter_for", lambda cfg: stub)

    status = client.get("/api/ai/status").json()
    assert status["mode"] == "ai"

    res = client.post("/api/ai/draft-rule", json={"technique_id": "T1486"})
    body = res.json()
    assert body["source"] == "ai"
    assert body["validation"]["ok"] is True
    assert "wazuh-analysisd -t" in body["note"]

    # Suppression prompt carries sample alert IPs -> must be redacted pre-chat.
    client.post("/api/ai/suppression", json={"rule_id": 50001})
    user_text = " ".join(m.content for m in stub.seen if m.role == "user")
    assert "[REDACTED_IP]" in user_text
    assert "10.20.7.7" not in user_text

    assert client.post("/api/ai/test-connection").json() == {
        "ok": True,
        "message": "stub ok",
    }


def test_ai_failure_degrades_to_200_never_500(client, monkeypatch):
    monkeypatch.setattr(appmod, "_adapter_for", lambda cfg: _StubAdapter(fail=True))

    res = client.post("/api/ai/explain", json={"finding_id": "F001"})
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "template"
    assert body["error"] == "AI unavailable: stub provider exploded"
    assert body["text"].strip()

    res = client.post("/api/ai/draft-rule", json={"technique_id": "T1486"})
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "offline"
    assert body["validation"]["ok"] is True  # offline template still delivered
    assert body["error"] == "AI unavailable: stub provider exploded"

    res = client.post("/api/ai/suppression", json={"rule_id": 50001})
    assert res.status_code == 200
    assert res.json()["source"] == "offline"


# ---------------------------------------------------------------------------
# Static frontend + SPA fallback
# ---------------------------------------------------------------------------


def test_frontend_served_and_spa_fallback(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    res = client.get("/css/app.css")
    assert res.status_code == 200
    # Unknown non-API path falls back to index.html (SPA).
    res = client.get("/some/client/route")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    # Unknown API path is a JSON 404, not the SPA.
    res = client.get("/api/nope")
    assert res.status_code == 404
    assert res.json() == {"error": "not found"}


# ---------------------------------------------------------------------------
# Pass-1 review additions: NL query, report narrative, traversal, duplicates
# ---------------------------------------------------------------------------


def test_ai_query_local_mode_template(client):
    res = client.post("/api/ai/query", json={"question": "which rules are dead?"})
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "template"
    assert body["spec"] is None
    assert "filter chips" in body["note"]


def test_ai_query_requires_question(client):
    res = client.post("/api/ai/query", json={"question": "   "})
    assert res.status_code == 400
    res = client.post("/api/ai/query", json={})
    assert res.status_code == 400


def test_ai_report_narrative_template(client):
    res = client.post("/api/ai/report-narrative")
    assert res.status_code == 200
    body = res.json()
    assert body["source"] == "template"
    text = body["text"]
    # Deterministic template must cite the real measured numbers.
    assert "55" in text  # posture score on seed data
    assert "52" in text  # techniques total
    assert "dead" in text.lower()


def test_spa_fallback_blocks_path_traversal(client):
    # Attempt to escape the frontend dir. The traversal must be neutralised:
    # either a 404, or the SPA fallback (index.html). It must NEVER serve
    # /etc/passwd or any other file outside the frontend dir.
    for attempt in ("/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/css/../../app.py"):
        res = client.get(attempt)
        assert "root:" not in res.text, attempt
        assert "import " not in res.text[:200] or "text/html" in res.headers.get("content-type", ""), attempt


def test_duplicate_rule_id_warns(tmp_path):
    from backend.wazuh_rules import parse_ruleset

    d = tmp_path / "rules"
    d.mkdir()
    (d / "a.xml").write_text(
        '<group><rule id="100001" level="5"><description>A</description>'
        "<group>g,</group></rule></group>",
        encoding="utf-8",
    )
    (d / "b.xml").write_text(
        '<group><rule id="100001" level="7"><description>B</description>'
        "<group>g,</group></rule></group>",
        encoding="utf-8",
    )
    rules, warnings = parse_ruleset(d)
    assert len(rules) == 1  # later definition wins
    assert any("duplicate rule id 100001" in w for w in warnings)
