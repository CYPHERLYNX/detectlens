"""Markdown audit-report renderer.

Produces a dated, human-readable detection-posture audit: title, UTC
generation timestamp, posture score, per-tactic coverage table, dead and
noisy rule tables, the prioritised findings list, the uncovered-technique
list, method notes, and data sources plus the analysis window.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .attack_data import TACTICS
from .findings import Finding
from .posture import PostureReport
from .wazuh_rules import Rule


def _esc(text: str) -> str:
    """Escape pipe characters so values do not break Markdown tables."""
    return str(text).replace("|", "\\|")


def render_markdown_report(
    posture: PostureReport,
    findings: list[Finding],
    rules: list[Rule],
    meta: dict,
) -> str:
    """Render a Markdown audit report.

    ``meta`` may carry ``title`` (default "Detection Posture Audit"),
    ``rules_dir``, ``alerts_source``, ``technique_source`` and
    ``technique_names`` (technique_id -> display name) for richer output.
    """
    title = str(meta.get("title", "Detection Posture Audit"))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rules_by_id = {r.id: r for r in rules}
    technique_names: dict = meta.get("technique_names", {}) or {}

    def tname(tid: str) -> str:
        name = technique_names.get(tid)
        return f"{tid} ({name})" if name else tid

    lines: list[str] = [f"# {title}", "", f"Generated: {generated}", ""]

    # Score + summary.
    lines.append("## Posture score")
    lines.append("")
    lines.append(f"**{posture.posture_score} / 100**")
    lines.append("")
    lines.append(
        f"Techniques: {posture.techniques_total} total — {posture.covered} covered, "
        f"{posture.partial} partial, {posture.uncovered} uncovered."
    )
    lines.append(
        f"Rules: {posture.totals['rules']} total, "
        f"{posture.totals['rules_fired']} fired at least once in the window."
    )
    lines.append(f"Alerts analysed: {posture.totals['alerts']}.")
    lines.append("")

    # Coverage by tactic.
    lines.append("## Coverage by tactic")
    lines.append("")
    lines.append("| Tactic | Covered | Partial | Uncovered | Total |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for tactic in TACTICS:
        cell = posture.coverage_by_tactic.get(tactic, {})
        if not cell.get("total"):
            continue
        lines.append(
            f"| {tactic} | {cell['covered']} | {cell['partial']} | "
            f"{cell['uncovered']} | {cell['total']} |"
        )
    lines.append("")

    # Uncovered techniques.
    uncovered = sorted(
        tid
        for tid, cov in posture.technique_coverage.items()
        if cov.state == "uncovered"
    )
    lines.append("## Uncovered techniques")
    lines.append("")
    if uncovered:
        for tid in uncovered:
            lines.append(f"- {tname(tid)}")
    else:
        lines.append("None — every technique in the subset has at least one mapped rule.")
    lines.append("")

    # Dead rules table.
    dead = sorted(
        (h for h in posture.rule_health.values() if h.state == "dead"),
        key=lambda h: h.rule_id,
    )
    lines.append("## Dead rules")
    lines.append("")
    if dead:
        lines.append("| Rule ID | Description | Fires |")
        lines.append("| ---: | --- | ---: |")
        for h in dead:
            rule = rules_by_id.get(h.rule_id)
            desc = rule.description if rule and rule.description else "—"
            lines.append(f"| {h.rule_id} | {_esc(desc)} | {h.fire_count} |")
    else:
        lines.append("None — every rule fired at least once in the window.")
    lines.append("")

    # Noisy rules table.
    noisy = sorted(
        (h for h in posture.rule_health.values() if h.state == "noisy"),
        key=lambda h: h.rule_id,
    )
    lines.append("## Noisy rules")
    lines.append("")
    if noisy:
        lines.append("| Rule ID | Description | Fires |")
        lines.append("| ---: | --- | ---: |")
        for h in noisy:
            rule = rules_by_id.get(h.rule_id)
            desc = rule.description if rule and rule.description else "—"
            lines.append(f"| {h.rule_id} | {_esc(desc)} | {h.fire_count} |")
    else:
        lines.append("None — no rule reached the noise threshold.")
    lines.append("")

    # Findings.
    lines.append("## Findings")
    lines.append("")
    if findings:
        for f in findings:
            lines.append(f"### {f.id} — {f.title} [{f.severity}]")
            lines.append("")
            lines.append(f.explanation)
            lines.append("")
            lines.append(f"**Lesson:** {f.lesson}")
            lines.append("")
    else:
        lines.append("No findings.")
        lines.append("")

    # Method notes.
    lines.append("## Method notes")
    lines.append("")
    lines.append(
        "- Coverage % means the share of techniques with at least one mapped "
        "rule (covered or partial). It measures detection mapping, **not "
        "attacks blocked**."
    )
    lines.append(
        "- A technique is covered with 2+ mapped rules, partial with 1, "
        "uncovered with 0. A technique whose only mapped rules never fired "
        "is still partial by count, and surfaces separately as a dead-rule "
        "finding (the static-audit trap)."
    )
    lines.append(
        "- A rule is dead with 0 fires in the window, noisy at or above the "
        "noise threshold, healthy otherwise."
    )
    lines.append(
        "- Missing telemetry is a heuristic: an uncovered technique whose "
        "data components are observed by no mapped detection probably lacks "
        "the underlying log collection. It is inferred from detection "
        "mappings, not measured from log sources."
    )
    lines.append(
        "- The posture score blends coverage (60%), dead-rule ratio (25%) "
        "and noisy-rule ratio (15%)."
    )
    lines.append("")

    # Data sources + window.
    lines.append("## Data sources")
    lines.append("")
    lines.append(f"- Analysis window: last {posture.window_days} days")
    if meta.get("rules_dir"):
        lines.append(f"- Rules directory: `{meta['rules_dir']}`")
    if meta.get("alerts_source"):
        lines.append(f"- Alerts source: `{meta['alerts_source']}`")
    if meta.get("technique_source"):
        lines.append(f"- Technique subset: `{meta['technique_source']}`")
    lines.append("")

    return "\n".join(lines)
