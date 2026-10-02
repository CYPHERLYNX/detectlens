"""DetectLens FastAPI backend.

Serves the posture engine (rules/alerts/ATT&CK coverage), findings, the
markdown audit report and the optional AI layer over HTTP, plus the
bundled single-page frontend.

Coverage definitions (one definition everywhere): the posture engine
(:mod:`backend.posture`) classifies techniques by *static rule count*
(2+ mapped rules = covered, 1 = partial, 0 = uncovered).  The headline
"coverage %" shown on the dashboard, heatmap, findings and report is
``(covered + partial) / total`` — i.e. "techniques with >=1 mapped rule".
It measures detection mapping, never "attacks blocked".  Whether a
mapped rule actually fired is a separate, evidence-joined signal: rules
with 0 fires in the window are flagged dead, and techniques whose only
mapped rules are dead surface as partial-with-no-fires (the static-audit
trap) plus an explicit dead-rule finding.

Alert windowing: the analysis window is anchored at the newest alert in
the loaded data (``max(timestamp) - window_days``), not at wall-clock
now.  For a live, continuously-appended Wazuh alerts.json the two are
equivalent; for a static/demo dataset the now-anchored window would
silently drop everything as the data ages.  This keeps the dashboard
deterministic regardless of when the server runs.

AI behaviour: every AI endpoint degrades to a deterministic offline
response when no adapter is configured or the provider fails.  AI
failures return HTTP 200 with ``source`` set to ``"template"``/``"offline"``
and an ``error`` message — never a 500 and never a dead end.  Prompt
payloads are redacted per the config toggles before any adapter call,
and the API key is never included in any response.
"""

from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from fastapi import Body, FastAPI, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from .ai import get_adapter, prompts
from .ai.base import AIError, ChatMessage, LLMAdapter
from .alerts import Alert, load_alerts
from .attack_data import TACTICS, Technique, load_attack_subset
from .config import (
    VALID_PROVIDERS,
    AppConfig,
    load_config,
    save_config,
)
from .findings import GLOSSARY, Finding, build_findings
from .posture import PostureReport, compute_posture
from .redact import RedactionToggles, redact_text
from .report import render_markdown_report
from .validate import validate_rule_xml
from .wazuh_rules import Rule, parse_ruleset


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
UPLOADS_DIR = PROJECT_ROOT / "uploads"
SEED_RULES_DIR = PROJECT_ROOT / "data" / "seed" / "rules"
SEED_LOCAL_RULES = PROJECT_ROOT / "data" / "seed" / "local_rules.xml"
SEED_ALERTS = PROJECT_ROOT / "data" / "seed" / "alerts.json"
SEED_TECHNIQUES = PROJECT_ROOT / "data" / "attack_subset.json"

MAX_UPLOAD_BYTES = 50 * 1024 * 1024

DRAFT_NOTE = (
    "Validated locally; run wazuh-analysisd -t on your manager before "
    "deploying. Nothing is auto-applied."
)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@dataclass
class State:
    """In-memory snapshot of everything the API serves."""

    config: AppConfig
    rules: list[Rule]
    rules_by_id: dict[int, Rule]
    alerts: list[Alert]  # windowed
    alerts_loaded: int  # before windowing
    techniques: list[Technique]
    tech_by_id: dict[str, Technique]
    technique_names: dict[str, str]
    posture: PostureReport
    findings: list[Finding]
    findings_by_id: dict[str, Finding]
    warnings: list[str]
    alerts_source: str
    rules_dir: str
    loaded_at: str


def _window_filter(alerts: list[Alert], window_days: int) -> list[Alert]:
    """Keep alerts in the last *window_days*, anchored at the newest alert.

    Anchoring at the data's own latest timestamp (instead of wall-clock now)
    keeps the window deterministic for static datasets while matching the
    live case, where the newest alert is effectively now.
    """
    if not alerts:
        return []
    latest = max(a.timestamp for a in alerts)
    cutoff = latest - timedelta(days=window_days)
    return [a for a in alerts if a.timestamp >= cutoff]


def _resolve_paths(cfg: AppConfig) -> tuple[Path, Path | None, Path]:
    """Return ``(rules_dir, local_rules_or_None, alerts_path)``.

    Defaults point at the bundled seed data.  When ``rules_dir`` is
    overridden in config, a ``local_rules.xml`` sitting inside that
    directory is picked up if present.
    """
    rules_dir = Path(cfg.rules_dir) if cfg.rules_dir else SEED_RULES_DIR
    if cfg.rules_dir:
        candidate = rules_dir / "local_rules.xml"
        local_rules = candidate if candidate.is_file() else None
    else:
        local_rules = SEED_LOCAL_RULES if SEED_LOCAL_RULES.is_file() else None
    alerts_path = Path(cfg.alerts_path) if cfg.alerts_path else SEED_ALERTS
    return rules_dir, local_rules, alerts_path


def build_state(cfg: AppConfig, alerts_path: str | Path | None = None) -> State:
    """Load and analyse everything.  Never raises on bad data files: parse
    problems are recorded in ``warnings`` and the offending source is
    treated as empty."""
    rules_dir, local_rules, default_alerts = _resolve_paths(cfg)
    warnings: list[str] = []

    rules, parse_warnings = parse_ruleset(rules_dir, local_rules)
    warnings.extend(parse_warnings)

    alerts_file = Path(alerts_path) if alerts_path else default_alerts
    try:
        loaded_alerts = load_alerts(alerts_file)
    except (ValueError, OSError) as exc:
        warnings.append(f"{alerts_file}: could not load alerts ({exc}); using none")
        loaded_alerts = []
    alerts = _window_filter(loaded_alerts, cfg.window_days)

    try:
        techniques = load_attack_subset(SEED_TECHNIQUES)
    except (ValueError, OSError) as exc:
        warnings.append(f"{SEED_TECHNIQUES}: could not load techniques ({exc})")
        techniques = []

    posture = compute_posture(rules, alerts, techniques, window_days=cfg.window_days)
    findings = build_findings(posture, rules, techniques)

    rules_by_id = {r.id: r for r in rules}
    tech_by_id = {t.id: t for t in techniques}
    return State(
        config=cfg,
        rules=rules,
        rules_by_id=rules_by_id,
        alerts=alerts,
        alerts_loaded=len(loaded_alerts),
        techniques=techniques,
        tech_by_id=tech_by_id,
        technique_names={t.id: t.name for t in techniques},
        posture=posture,
        findings=findings,
        findings_by_id={f.id: f for f in findings},
        warnings=warnings,
        alerts_source=str(alerts_file),
        rules_dir=str(rules_dir),
        loaded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _serialize_finding(f: Finding) -> dict:
    return asdict(f)


def _rule_summary(rule: Rule, state: State) -> dict:
    health = state.posture.rule_health.get(rule.id)
    return {
        "id": rule.id,
        "level": rule.level,
        "description": rule.description,
        "groups": rule.groups,
        "mitre_ids": rule.mitre_ids,
        "state": health.state if health else "unknown",
        "fire_count": health.fire_count if health else 0,
        "source_file": rule.source_file,
    }


def _health_counts(state: State) -> dict[str, int]:
    counts = {"healthy": 0, "dead": 0, "noisy": 0}
    for health in state.posture.rule_health.values():
        if health.state in counts:
            counts[health.state] += 1
    return counts


# ---------------------------------------------------------------------------
# AI helpers
# ---------------------------------------------------------------------------


def _adapter_for(cfg: AppConfig) -> LLMAdapter | None:
    return get_adapter(cfg)


def _mode_for(cfg: AppConfig) -> str:
    return "ai" if _adapter_for(cfg) is not None else "local"


def _toggles_dict(cfg: AppConfig) -> dict:
    return {
        "ips": bool(cfg.redact_ips),
        "hostnames": bool(cfg.redact_hostnames),
        "usernames": bool(cfg.redact_usernames),
    }


def _redact_fn(text: str, toggles: dict) -> str:
    return redact_text(
        text,
        RedactionToggles(
            ips=bool(toggles.get("ips", True)),
            hostnames=bool(toggles.get("hostnames", True)),
            usernames=bool(toggles.get("usernames", True)),
        ),
    )


def _redacted(messages: list[ChatMessage], cfg: AppConfig) -> list[ChatMessage]:
    toggles = _toggles_dict(cfg)
    return [
        ChatMessage(
            role=m.role,
            content=prompts.redact_prompt_payload(m.content, toggles, _redact_fn),
        )
        for m in messages
    ]


def _safe_ai_error(exc: BaseException) -> str:
    # AIError messages are key-safe by adapter contract; anything else is
    # reduced to its class name so no unexpected text leaks out.
    detail = str(exc) if isinstance(exc, AIError) else exc.__class__.__name__
    return f"AI unavailable: {detail}"


def _next_rule_id(existing_ids: list[int]) -> int:
    """Next unused rule id >= 100100 (mirrors ai.prompts._next_rule_id)."""
    taken = set(existing_ids or [])
    candidate = max([100100] + [i + 1 for i in taken if i >= 100100])
    while candidate in taken:
        candidate += 1
    return candidate


def _offline_draft_xml(tech: Technique, existing_ids: list[int]) -> str:
    new_id = _next_rule_id(existing_ids)
    return (
        f'<rule id="{new_id}" level="7">\n'
        f"  <description>DetectLens: detect {_xml_escape(tech.name)} "
        f"({_xml_escape(tech.id)}) \u2014 review and tune before use.</description>\n"
        "  <group>detectlens,attack,</group>\n"
        "  <mitre>\n"
        f"    <id>{_xml_escape(tech.id)}</id>\n"
        "  </mitre>\n"
        "</rule>"
    )


def _offline_suppression_xml(rule: Rule, fires: int, existing_ids: list[int]) -> tuple[str, int]:
    new_id = _next_rule_id(existing_ids)
    frequency = max(10, fires // 24)  # ~one expected hourly burst, floor of 10
    xml = (
        f'<rule id="{new_id}" level="{rule.level}">\n'
        f"  <if_sid>{rule.id}</if_sid>\n"
        f"  <frequency>{frequency}</frequency>\n"
        "  <timeframe>3600</timeframe>\n"
        f"  <description>DetectLens: aggregate burst alerts from rule {rule.id} "
        f"({_xml_escape(rule.description)}) \u2014 tune before use.</description>\n"
        "  <group>detectlens,tuning,</group>\n"
        "</rule>"
    )
    return xml, frequency


def _offline_suppression_plan(rule: Rule, fires: int, frequency: int) -> list[str]:
    return [
        f"Keep rule {rule.id} enabled: it still provides detection coverage, "
        f"it fired {fires} times in the window and the goal is fidelity, not silence.",
        "Add the frequency-threshold rule below: instead of one alert per hit, "
        f"Wazuh emits a single aggregated alert once rule {rule.id} fires "
        f"{frequency} times within an hour.",
        "Tune frequency/timeframe against the estate's real baseline first "
        "(check which agents and hours dominate the volume).",
        "Prefer adding match conditions (agent, user, path) over raising the "
        "threshold if a subset of the traffic is clearly benign.",
        "Validate with wazuh-analysisd -t and watch the aggregated alert for "
        "a day before widening the threshold. Nothing is auto-applied.",
    ]


_RULE_XML_RE = re.compile(r"<rule\b.*?</rule\s*>", re.DOTALL | re.IGNORECASE)
_RULE_OPEN_RE = re.compile(r"<rule\b[^>]*>", re.IGNORECASE)


def _extract_rule_xml(text: str) -> str | None:
    match = _RULE_XML_RE.search(text or "")
    return match.group(0) if match else None


def _inherited_group_name(source_file: str, rule_id: int) -> str | None:
    """Find the enclosing file-level ``<group name="...">`` for a rule.

    Wazuh lets rules inherit the group of the ``<group>`` element wrapping
    them, so seed rules carry no inline ``<group>`` child.  Returns the
    comma-joined ancestor group names, or None when they cannot be
    determined.
    """
    from xml.etree import ElementTree as ET

    try:
        text = Path(source_file).read_text(encoding="utf-8", errors="replace")
        # Seed files hold several top-level <group> elements, which is not
        # a single XML document; wrap them so the tree parses.
        root = ET.fromstring(f"<root>{text}</root>")
    except (OSError, ET.ParseError):
        return None

    found: list[str] = []

    def walk(elem: ET.Element, groups: list[str]) -> None:
        if found:
            return
        tag = elem.tag
        child_groups = groups
        if tag == "group" and elem.get("name"):
            child_groups = groups + [elem.get("name").strip()]
        elif tag == "rule":
            try:
                if int(elem.get("id")) == rule_id:
                    found.extend(child_groups)
                    return
            except (TypeError, ValueError):
                pass
        for child in elem:
            walk(child, child_groups)

    walk(root, [])
    names = [n for n in found if n]
    return ", ".join(names) if names else None


def _validate_rule_for_detail(rule: Rule):
    """Validate a rule the way Wazuh sees it.

    A bare ``<rule>`` block without an inline ``<group>`` is incomplete as
    a standalone snippet, but it is valid when the enclosing file-level
    ``<group name="...">`` provides the group (the seed ruleset's normal
    shape).  When the *only* snippet errors are the missing group, the
    inherited group name is injected for validation purposes; the raw
    ``xml`` returned to the caller is never modified.
    """
    direct = validate_rule_xml(rule.xml)
    if direct.ok:
        return direct
    group_only = direct.errors and all("group" in e for e in direct.errors)
    if group_only:
        inherited = _inherited_group_name(rule.source_file, rule.id)
        opening = _RULE_OPEN_RE.match(rule.xml.lstrip())
        if inherited and opening:
            effective = (
                rule.xml[: opening.end()]
                + f"<group>{_xml_escape(inherited)}</group>"
                + rule.xml[opening.end():]
            )
            return validate_rule_xml(effective)
    return direct


def _sample_alerts(state: State, rule_id: int, limit: int = 5) -> list[dict]:
    out = []
    for a in state.alerts:
        if a.rule_id == rule_id:
            out.append(
                {
                    "agent": a.agent,
                    "srcip": a.ip or "unknown",
                    "user": "unknown",
                    "description": a.description,
                }
            )
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


def ensure_uploads_dir() -> None:
    """Create <project>/uploads (git-ignored via the shipped .gitignore)."""
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


state: State | None = None


def _state() -> State:
    if state is None:  # pragma: no cover - startup always builds it
        raise RuntimeError("server state not initialised")
    return state


@asynccontextmanager
async def lifespan(app: FastAPI):
    global state
    ensure_uploads_dir()
    state = build_state(load_config())
    yield


app = FastAPI(title="DetectLens", version="0.1.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


@app.post("/api/reload")
def reload() -> dict:
    """Recompute everything from the current config paths."""
    global state
    state = build_state(load_config())
    s = _state()
    return {
        "ok": True,
        "rules": len(s.rules),
        "alerts": len(s.alerts),
        "findings": len(s.findings),
        "loaded_at": s.loaded_at,
    }


@app.get("/api/overview")
def overview() -> dict:
    s = _state()
    hc = _health_counts(s)
    p = s.posture
    return {
        "posture_score": p.posture_score,
        "window_days": p.window_days,
        "totals": {
            "techniques": p.techniques_total,
            "covered": p.covered,
            "partial": p.partial,
            "uncovered": p.uncovered,
            "rules": p.totals["rules"],
            "healthy": hc["healthy"],
            "dead": hc["dead"],
            "noisy": hc["noisy"],
            "alerts": p.totals["alerts"],
            "rules_fired": p.totals["rules_fired"],
        },
        "coverage_by_tactic": p.coverage_by_tactic,
        "top_findings": [_serialize_finding(f) for f in s.findings[:5]],
    }


@app.get("/api/heatmap")
def heatmap() -> dict:
    s = _state()
    cells = []
    for tech in s.techniques:
        cov = s.posture.technique_coverage.get(tech.id)
        rule_ids = cov.rule_ids if cov else []
        fire_count = cov.fire_count if cov else 0
        cells.append(
            {
                "technique_id": tech.id,
                "name": tech.name,
                "tactic": tech.tactics[0] if tech.tactics else "",
                "state": cov.state if cov else "uncovered",
                "rule_count": len(rule_ids),
                "fire_count": fire_count,
            }
        )
    return {"tactics": list(TACTICS), "cells": cells}


@app.get("/api/findings")
def findings() -> dict:
    s = _state()
    return {"findings": [_serialize_finding(f) for f in s.findings]}


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: str) -> dict:
    s = _state()
    finding = s.findings_by_id.get(finding_id)
    if finding is None:
        return JSONResponse(status_code=404, content={"error": "finding not found"})
    return {"finding": _serialize_finding(finding)}


@app.get("/api/rules")
def rules() -> dict:
    s = _state()
    return {
        "rules": [_rule_summary(r, s) for r in sorted(s.rules, key=lambda r: r.id)]
    }


@app.get("/api/rules/{rule_id}")
def rule_detail(rule_id: int) -> dict:
    s = _state()
    rule = s.rules_by_id.get(rule_id)
    if rule is None:
        return JSONResponse(status_code=404, content={"error": "rule not found"})
    summary = _rule_summary(rule, s)
    validation = _validate_rule_for_detail(rule)
    summary["xml"] = rule.xml
    summary["validation"] = {"ok": validation.ok, "errors": validation.errors}
    return {"rule": summary}


@app.post("/api/alerts/upload")
async def upload_alerts(file: UploadFile = File(...)) -> JSONResponse:
    s = _state()
    filename = (file.filename or "").strip()
    if not filename.lower().endswith(".json"):
        return JSONResponse(status_code=400, content={"error": "only .json files are accepted"})
    # Stream the upload in chunks so the 50 MB cap is enforced without
    # ever holding an oversized file in memory.
    chunks: list[bytes] = []
    total = 0
    while True:
        piece = await file.read(1024 * 1024)
        if not piece:
            break
        total += len(piece)
        if total > MAX_UPLOAD_BYTES:
            return JSONResponse(status_code=400, content={"error": "file too large (50 MB limit)"})
        chunks.append(piece)
    data = b"".join(chunks)
    if not data.strip():
        return JSONResponse(status_code=400, content={"error": "empty file"})
    ensure_uploads_dir()
    safe_name = Path(filename).name or "upload.json"
    dest = UPLOADS_DIR / safe_name
    dest.write_bytes(data)
    try:
        load_alerts(dest)
    except (ValueError, OSError) as exc:
        dest.unlink(missing_ok=True)
        return JSONResponse(
            status_code=400, content={"error": f"could not parse alerts: {exc}"}
        )
    global state
    state = build_state(s.config, alerts_path=dest)
    s = _state()
    return JSONResponse(
        {"alerts_loaded": len(s.alerts), "window_days": s.posture.window_days}
    )


@app.get("/api/report.md")
def report_md() -> PlainTextResponse:
    s = _state()
    meta = {
        "title": "DetectLens Detection Posture Audit",
        "rules_dir": s.rules_dir,
        "alerts_source": s.alerts_source,
        "technique_source": str(SEED_TECHNIQUES),
        "technique_names": s.technique_names,
    }
    body = render_markdown_report(s.posture, s.findings, s.rules, meta)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return PlainTextResponse(
        body,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="detectlens-report-{date}.md"'
        },
    )


@app.get("/api/glossary")
def glossary() -> dict:
    return {"terms": dict(GLOSSARY)}


# ---------------------------------------------------------------------------
# AI API
# ---------------------------------------------------------------------------


@app.get("/api/ai/status")
def ai_status() -> dict:
    s = _state()
    cfg = s.config
    return {
        "mode": _mode_for(cfg),
        "provider": cfg.provider,
        "model": cfg.model,
        "redaction": _toggles_dict(cfg),
        "local_only": bool(cfg.local_only),
    }


@app.post("/api/ai/test-connection")
def ai_test_connection() -> dict:
    s = _state()
    adapter = _adapter_for(s.config)
    if adapter is None:
        return {"ok": False, "message": "AI not configured \u2014 running in local mode"}
    try:
        ok, message = adapter.test_connection()
    except Exception as exc:  # test_connection must never raise, belt and braces
        return {"ok": False, "message": _safe_ai_error(exc)}
    return {"ok": bool(ok), "message": str(message)}


@app.post("/api/ai/explain")
def ai_explain(payload: dict = Body(...)) -> dict:
    s = _state()
    finding_id = payload.get("finding_id")
    if not finding_id:
        return JSONResponse(status_code=400, content={"error": "finding_id is required"})
    finding = s.findings_by_id.get(str(finding_id))
    if finding is None:
        return JSONResponse(status_code=404, content={"error": "finding not found"})

    adapter = _adapter_for(s.config)
    if adapter is None:
        return {"text": finding.explanation, "source": "template"}
    try:
        messages = _redacted(
            prompts.explain_finding(asdict(finding), s.technique_names), s.config
        )
        return {"text": adapter.chat(messages), "source": "ai"}
    except Exception as exc:
        return {
            "text": finding.explanation,
            "source": "template",
            "error": _safe_ai_error(exc),
        }


@app.post("/api/ai/explain-rule")
def ai_explain_rule(payload: dict = Body(...)) -> dict:
    """Explain what one rule actually does, in plain English.

    Local mode degrades to a deterministic template summary (never a dead
    end); AI mode redacts the rule XML before sending it.
    """
    s = _state()
    rule_id = payload.get("rule_id")
    if rule_id is None:
        return JSONResponse(status_code=400, content={"error": "rule_id is required"})
    try:
        rule_id = int(rule_id)
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "rule_id must be an integer"})
    rule = s.rules_by_id.get(rule_id)
    if rule is None:
        return JSONResponse(status_code=404, content={"error": "rule not found"})

    health = s.posture.rule_health.get(rule.id)
    fires = health.fire_count if health else 0
    template = (
        f"Rule {rule.id} (level {rule.level}) — {rule.description or 'no description'}. "
        f"Groups: {', '.join(rule.groups) if rule.groups else 'none inline (Wazuh inherits the file-level group)'}. "
        f"MITRE: {', '.join(rule.mitre_ids) or 'not tagged'}. "
        f"Fired {fires} times in the last {s.posture.window_days} days."
    )

    adapter = _adapter_for(s.config)
    if adapter is None:
        return {"text": template, "source": "template"}
    try:
        messages = _redacted(
            prompts.explain_rule(
                {
                    "id": rule.id,
                    "level": rule.level,
                    "description": rule.description,
                    "groups": rule.groups,
                    "mitre_ids": rule.mitre_ids,
                    "xml": rule.xml,
                    "fire_count": fires,
                }
            ),
            s.config,
        )
        return {"text": adapter.chat(messages), "source": "ai"}
    except Exception as exc:
        return {"text": template, "source": "template", "error": _safe_ai_error(exc)}


@app.post("/api/ai/draft-rule")
def ai_draft_rule(payload: dict = Body(...)) -> dict:
    s = _state()
    technique_id = payload.get("technique_id")
    if not technique_id:
        return JSONResponse(status_code=400, content={"error": "technique_id is required"})
    tech = s.tech_by_id.get(str(technique_id))
    if tech is None:
        return JSONResponse(status_code=404, content={"error": "technique not found"})

    existing_ids = [r.id for r in s.rules]

    def offline() -> dict:
        xml = _offline_draft_xml(tech, existing_ids)
        validation = validate_rule_xml(xml)
        return {
            "xml": xml,
            "validation": {"ok": validation.ok, "errors": validation.errors},
            "source": "offline",
            "note": DRAFT_NOTE,
        }

    adapter = _adapter_for(s.config)
    if adapter is None:
        return offline()
    try:
        sample = next((r.xml for r in s.rules if r.mitre_ids), s.rules[0].xml if s.rules else "")
        messages = _redacted(
            prompts.draft_rule(
                {
                    "id": tech.id,
                    "name": tech.name,
                    "tactics": tech.tactics,
                    "description": tech.description,
                },
                existing_ids,
                sample,
            ),
            s.config,
        )
        raw = adapter.chat(messages)
        xml = _extract_rule_xml(raw) or raw.strip()
        validation = validate_rule_xml(xml)
        return {
            "xml": xml,
            "validation": {"ok": validation.ok, "errors": validation.errors},
            "source": "ai",
            "note": DRAFT_NOTE,
        }
    except Exception as exc:
        result = offline()
        result["error"] = _safe_ai_error(exc)
        return result


@app.post("/api/ai/suppression")
def ai_suppression(payload: dict = Body(...)) -> dict:
    s = _state()
    rule_id = payload.get("rule_id")
    if rule_id is None:
        return JSONResponse(status_code=400, content={"error": "rule_id is required"})
    try:
        rule_id = int(rule_id)
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "rule_id must be an integer"})
    rule = s.rules_by_id.get(rule_id)
    if rule is None:
        return JSONResponse(status_code=404, content={"error": "rule not found"})

    health = s.posture.rule_health.get(rule.id)
    fires = health.fire_count if health else 0
    existing_ids = [r.id for r in s.rules]

    def offline() -> dict:
        xml, frequency = _offline_suppression_xml(rule, fires, existing_ids)
        validation = validate_rule_xml(xml)
        return {
            "xml": xml,
            "validation": {"ok": validation.ok, "errors": validation.errors},
            "plan": _offline_suppression_plan(rule, fires, frequency),
            "source": "offline",
        }

    adapter = _adapter_for(s.config)
    if adapter is None:
        return offline()
    try:
        messages = _redacted(
            prompts.suppression_proposal(
                {"id": rule.id, "description": rule.description, "level": rule.level},
                _sample_alerts(s, rule.id),
                fires,
            ),
            s.config,
        )
        raw = adapter.chat(messages)
        extracted = _extract_rule_xml(raw)
        if extracted and validate_rule_xml(extracted).ok:
            xml = extracted
        else:
            xml, _ = _offline_suppression_xml(rule, fires, existing_ids)
        validation = validate_rule_xml(xml)
        plan_text = raw.replace(extracted, "", 1) if extracted else raw
        plan = [ln.strip() for ln in plan_text.splitlines() if ln.strip()]
        if not plan:
            plan = _offline_suppression_plan(rule, fires, max(10, fires // 24))
        return {
            "xml": xml,
            "validation": {"ok": validation.ok, "errors": validation.errors},
            "plan": plan,
            "source": "ai",
        }
    except Exception as exc:
        result = offline()
        result["error"] = _safe_ai_error(exc)
        return result


_QUERY_SCHEMA_SUMMARY = (
    "findings: fields id, kind (dead_rule|noisy_rule|coverage_gap|missing_telemetry), "
    "severity (critical|high|medium|low|info), rule_ids (list of ints), "
    "technique_ids (list of strings). "
    "rules: fields id, level, state (healthy|dead|noisy), fire_count, "
    "mitre_ids (list of strings). "
    "techniques: fields id, state (covered|partial|uncovered), tactic, "
    "rule_count, fire_count. "
    "operators: eq, neq, in, gt, lt, contains."
)


@app.post("/api/ai/query")
def ai_query(payload: dict = Body(...)) -> dict:
    """Turn a natural-language posture question into an explicit filter spec.

    The spec is returned for the UI to show (editable) BEFORE anything is
    filtered — the client applies it locally.  Local mode degrades to a
    template response pointing at the manual filter chips; never a dead end.
    """
    s = _state()
    question = (payload.get("question") or "").strip()
    if not question:
        return JSONResponse(status_code=400, content={"error": "question is required"})
    adapter = _adapter_for(s.config)
    if adapter is None:
        return {
            "spec": None,
            "source": "template",
            "note": (
                "NL queries need a connected AI provider. In local mode, use "
                "the severity/kind filter chips on the Findings view."
            ),
        }
    try:
        messages = _redacted(
            prompts.nl_posture_query(question, _QUERY_SCHEMA_SUMMARY), s.config
        )
        raw = adapter.chat(messages)
        spec = json.loads(raw)  # prompt contract requires pure JSON output
        if not isinstance(spec, dict):
            raise ValueError("filter spec is not a JSON object")
        return {"spec": spec, "source": "ai"}
    except Exception as exc:
        return {
            "spec": None,
            "source": "template",
            "error": _safe_ai_error(exc),
            "note": "Could not generate a filter spec; use the manual filter chips.",
        }


def _offline_narrative(s: State) -> str:
    """Deterministic 2-paragraph executive summary (local-mode equivalent of
    the AI report narrative)."""
    p = s.posture
    total_t = p.techniques_total
    covered_t = p.covered + p.partial
    cov_pct = (covered_t / total_t * 100) if total_t else 0.0
    dead = sum(1 for h in p.rule_health.values() if h.state == "dead")
    noisy = sum(1 for h in p.rule_health.values() if h.state == "noisy")
    crit = [f for f in s.findings if f.severity == "critical"][:3]
    gaps = ", ".join(
        tid for f in crit for tid in f.technique_ids
    ) or "none in the critical set"
    return (
        f"Detection posture scores {p.posture_score} out of 100 over the last "
        f"{p.window_days} days. {covered_t} of {total_t} ATT&CK techniques "
        f"({cov_pct:.1f}%) have at least one mapped Wazuh rule, with "
        f"{p.covered} fully covered by two or more independent rules. "
        f"{dead} rules fired zero times in the window and contribute nothing "
        f"while still being evaluated; {noisy} rules are noisy enough that "
        "their alerts are likely being ignored."
        f"\n\nThe highest-priority gaps are the critical blind spots: {gaps}. "
        "Closing them means writing or enabling rules that fire on each "
        "technique's observable behaviour, after confirming the underlying "
        "telemetry is actually collected. Dead rules should each get a "
        "decision — fix, scope, or remove — rather than being left in place."
    )


@app.post("/api/ai/report-narrative")
def ai_report_narrative() -> dict:
    """Executive summary for the audit report.  AI mode uses the grounded
    narrative prompt; local mode returns the deterministic template above."""
    s = _state()
    p = s.posture
    summary = {
        "score": p.posture_score,
        "techniques_covered": p.covered + p.partial,
        "techniques_total": p.techniques_total,
        "dead_rules": sum(1 for h in p.rule_health.values() if h.state == "dead"),
        "noisy_rules": sum(1 for h in p.rule_health.values() if h.state == "noisy"),
        "top_gaps": [
            tid for f in s.findings if f.severity == "critical"
            for tid in f.technique_ids
        ][:5],
    }
    adapter = _adapter_for(s.config)
    if adapter is None:
        return {"text": _offline_narrative(s), "source": "template"}
    try:
        messages = _redacted(prompts.report_narrative(summary), s.config)
        return {"text": adapter.chat(messages), "source": "ai"}
    except Exception as exc:
        return {
            "text": _offline_narrative(s),
            "source": "template",
            "error": _safe_ai_error(exc),
        }


@app.post("/api/settings")
def update_settings(payload: dict = Body(...)) -> JSONResponse:
    s = _state()
    cfg = s.config
    new = AppConfig(
        provider=cfg.provider,
        base_url=cfg.base_url,
        model=cfg.model,
        api_key=cfg.api_key,
        redact_ips=cfg.redact_ips,
        redact_hostnames=cfg.redact_hostnames,
        redact_usernames=cfg.redact_usernames,
        local_only=cfg.local_only,
        rules_dir=cfg.rules_dir,
        alerts_path=cfg.alerts_path,
        window_days=cfg.window_days,
    )

    provider = payload.get("provider")
    if provider is not None:
        if provider not in VALID_PROVIDERS:
            return JSONResponse(
                status_code=400,
                content={"error": f"unknown provider {provider!r}; expected one of {VALID_PROVIDERS}"},
            )
        new.provider = provider
    for key in ("base_url", "model"):
        if payload.get(key) is not None:
            setattr(new, key, payload[key])
    api_key = payload.get("api_key")
    # Empty string (or absent) keeps the existing key; it is never echoed back.
    if api_key:
        new.api_key = api_key
    for key in ("redact_ips", "redact_hostnames", "redact_usernames", "local_only"):
        if key in payload:
            value = payload[key]
            if not isinstance(value, bool):
                return JSONResponse(
                    status_code=400, content={"error": f"{key} must be a boolean"}
                )
            setattr(new, key, value)
    # Data-source paths (optional; empty string clears back to bundled seed).
    for key in ("rules_dir", "alerts_path"):
        if key in payload:
            value = payload[key]
            if not isinstance(value, str):
                return JSONResponse(
                    status_code=400, content={"error": f"{key} must be a string"}
                )
            candidate = Path(value.strip()) if value.strip() else None
            if candidate is not None and not candidate.exists():
                return JSONResponse(
                    status_code=400, content={"error": f"{key}: path does not exist"}
                )
            setattr(new, key, value.strip() or (None if key == "alerts_path" else ""))
    if "window_days" in payload:
        try:
            days = int(payload["window_days"])
        except (TypeError, ValueError):
            return JSONResponse(
                status_code=400, content={"error": "window_days must be an integer"}
            )
        if not 1 <= days <= 365:
            return JSONResponse(
                status_code=400, content={"error": "window_days must be 1..365"}
            )
        new.window_days = days

    save_config(new)
    global state
    state = build_state(load_config())
    return JSONResponse({"ok": True, "mode": _mode_for(state.config)})


# ---------------------------------------------------------------------------
# Static frontend + SPA fallback (registered last)
# ---------------------------------------------------------------------------


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/{path:path}")
def spa_fallback(path: str):
    if path.startswith("api/"):
        return JSONResponse(status_code=404, content={"error": "not found"})
    # Resolve against the frontend dir and refuse anything that escapes it
    # (blocks ".." traversal attempts such as /../../etc/passwd).
    candidate = (FRONTEND_DIR / path).resolve()
    try:
        candidate.relative_to(FRONTEND_DIR.resolve())
    except ValueError:
        return JSONResponse(status_code=404, content={"error": "not found"})
    if candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(FRONTEND_DIR / "index.html")
