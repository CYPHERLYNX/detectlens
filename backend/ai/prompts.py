"""Grounded prompt templates for DetectLens.

Every system message enforces the same grounding contract:

- Ground EVERY claim in the provided evidence.
- Cite rule IDs (e.g. ``rule 100002``) and technique IDs (e.g. ``T1059.001``)
  and exact counts taken verbatim from the evidence block.
- NEVER invent rule IDs, technique IDs, or numbers.
- Say "unknown" when the evidence does not contain the answer.
- Use terse sentence-case plain English. No marketing copy.

Redaction is applied by the caller before the evidence block is embedded:
use :func:`redact_prompt_payload` / :func:`build_redacted_context` with a
caller-supplied redaction callable (do not import redact.py here).
"""

from __future__ import annotations

from typing import Callable, Optional

from .base import ChatMessage


_GROUNDING = (
    "You are a security analyst assistant inside DetectLens, a Wazuh-native "
    "detection posture management tool.\n\n"
    "Grounding rules (follow strictly):\n"
    "- Ground EVERY claim in the evidence provided below.\n"
    "- Cite rule IDs (e.g. rule 100002) and technique IDs (e.g. T1059.001) "
    "exactly as they appear in the evidence.\n"
    "- NEVER invent rule IDs, technique IDs, or numbers.\n"
    "- If the evidence does not contain the answer, say \"unknown\".\n"
    "- Use terse sentence-case plain English. No marketing copy."
)

RedactFn = Callable[[str, dict], str]


def redact_prompt_payload(text: str, toggles: dict,
                          redact_fn: Optional[RedactFn] = None) -> str:
    """Apply a caller-supplied redaction callable to ``text``.

    ``redact_fn`` is duck-typed: any callable ``(text, toggles) -> str``,
    e.g. the redaction logic from redact.py wrapped as
    ``lambda t, tg: redactor.redact(t, tg)``. When ``redact_fn`` is None the
    text is returned unchanged.
    """
    if redact_fn is None:
        return text
    return redact_fn(text, toggles)


def build_redacted_context(parts: list[str], toggles: dict,
                            redact_fn: Optional[RedactFn] = None) -> str:
    """Redact each part and join them into one evidence block."""
    return "\n\n".join(redact_prompt_payload(p, toggles, redact_fn) for p in parts)


def _fmt_ids(prefix: str, ids: list) -> str:
    return ", ".join(f"{prefix} {i}" for i in ids) if ids else "none"


def explain_finding(finding: dict, technique_names: dict) -> list[ChatMessage]:
    """Rewrite a finding explanation for a junior analyst."""
    title = finding.get("title", "untitled finding")
    severity = finding.get("severity", "unknown")
    rule_ids = finding.get("rule_ids", [])
    technique_ids = finding.get("technique_ids", [])
    counts = finding.get("counts", {})

    lines = [
        f"title: {title}",
        f"severity: {severity}",
        f"rules: {_fmt_ids('rule', rule_ids)}",
        "techniques: " + (
            ", ".join(f"{tid} ({technique_names.get(tid, 'unknown technique')})"
                      for tid in technique_ids) if technique_ids else "none"),
        "counts: " + (", ".join(f"{k}: {v}" for k, v in counts.items())
                      if counts else "none"),
    ]
    evidence = "\n".join(lines)
    user = (
        "Explain the following finding for a junior SOC analyst.\n\n"
        f"Evidence:\n{evidence}\n\n"
        "Requirements: include the finding title, severity, every rule ID, "
        "every technique ID with its name, and every count exactly as shown. "
        "Explain what the finding means, why it matters, and what to check "
        "first. Do not add claims beyond the evidence."
    )
    return [ChatMessage(role="system", content=_GROUNDING),
            ChatMessage(role="user", content=user)]


def _next_rule_id(existing_rule_ids: list[int]) -> int:
    taken = set(existing_rule_ids or [])
    candidate = max([100100] + [i + 1 for i in taken if i >= 100100] or [100100])
    while candidate in taken:
        candidate += 1
    return candidate


def draft_rule(technique: dict, existing_rule_ids: list[int],
               sample_xml: Optional[str]) -> list[ChatMessage]:
    """Draft ONE Wazuh <rule> XML block for a MITRE technique."""
    tid = technique.get("id", "unknown")
    tname = technique.get("name", "unknown technique")
    tactics = technique.get("tactics", [])
    desc = technique.get("description", "")
    new_id = _next_rule_id(existing_rule_ids)
    taken_str = ", ".join(str(i) for i in sorted(set(existing_rule_ids or []))) or "none"

    evidence = "\n".join([
        f"technique: {tid} ({tname})",
        f"tactics: {', '.join(tactics) if tactics else 'unknown'}",
        f"description: {desc or 'unknown'}",
        f"rule IDs already in use: {taken_str}",
        f"assigned new rule id: {new_id} (unused, >= 100100)",
        "sample of existing rule style: " + (sample_xml or "none provided"),
    ])
    user = (
        "Draft ONE Wazuh <rule> XML block covering the technique below.\n\n"
        f"Evidence:\n{evidence}\n\n"
        "Requirements:\n"
        f"- Use rule id {new_id} (it is unused and >= 100100; do not pick any other id).\n"
        "- Include level, description, group, and a <mitre><id> block with the technique ID.\n"
        "- Match the style of the sample if one was provided.\n"
        "- Output ONLY the XML block. No prose, no code fences, no explanation.\n\n"
        "This draft must be locally validated (e.g. wazuh-logtest) before any "
        "use, and it must NEVER be auto-applied to a live manager."
    )
    return [ChatMessage(role="system", content=_GROUNDING),
            ChatMessage(role="user", content=user)]


def suppression_proposal(rule: dict, sample_alerts: list[dict], fires: int) -> list[ChatMessage]:
    """Propose a conservative tuning/suppression plan for a noisy rule."""
    rid = rule.get("id", "unknown")
    rdesc = rule.get("description", "")
    rlevel = rule.get("level", "unknown")
    alert_lines = []
    for a in (sample_alerts or [])[:5]:
        alert_lines.append(
            f"- agent={a.get('agent', 'unknown')} srcip={a.get('srcip', 'unknown')} "
            f"user={a.get('user', 'unknown')} desc={a.get('description', '')}".strip())
    evidence = "\n".join([
        f"rule: {rid} (level {rlevel})",
        f"description: {rdesc or 'unknown'}",
        f"total fires in window: {fires}",
        "sample alerts:",
        "\n".join(alert_lines) if alert_lines else "none provided",
    ])
    user = (
        "Propose a conservative tuning or suppression approach for this noisy rule.\n\n"
        f"Evidence:\n{evidence}\n\n"
        "Requirements:\n"
        "- Output a short plan (numbered steps) followed by ONE XML snippet.\n"
        "- Prefer raising the level, adding an <if_sid> / field match, or a "
        "frequency threshold (<frequency>/<timeframe>) over removing coverage.\n"
        "- Be conservative: NEVER suggest disabling the rule or dropping its "
        "level without human review.\n"
        "- Reference the rule ID and the exact fire count in the plan."
    )
    return [ChatMessage(role="system", content=_GROUNDING),
            ChatMessage(role="user", content=user)]


def nl_posture_query(question: str, schema_summary: str) -> list[ChatMessage]:
    """Turn a natural-language question into an explicit filter spec (JSON)."""
    user = (
        "Convert the natural-language posture question into an explicit filter "
        "spec over findings, rules, and techniques.\n\n"
        f"Question: {question}\n\n"
        f"Available fields:\n{schema_summary}\n\n"
        "Requirements:\n"
        "- Output ONLY a JSON object. No prose, no code fences.\n"
        "- Keys: entity (findings|rules|techniques), filters (object with "
        "field/operator/value triples), sort, limit.\n"
        "- Use only fields listed above. Unknown fields -> omit and note in "
        "an \"assumptions\" array.\n"
        "- The JSON is shown to the user before it is run, so keep it readable."
    )
    return [ChatMessage(role="system", content=_GROUNDING),
            ChatMessage(role="user", content=user)]


def explain_rule(rule: dict) -> list[ChatMessage]:
    """Explain what a Wazuh rule actually does, in plain English."""
    rid = rule.get("id", "unknown")
    rlevel = rule.get("level", "unknown")
    rdesc = rule.get("description", "")
    xml = rule.get("xml", "")
    evidence = "\n".join([
        f"rule: {rid} (level {rlevel})",
        f"description: {rdesc or 'unknown'}",
        "xml:",
        xml or "not provided",
    ])
    user = (
        "Explain what this detection actually does.\n\n"
        f"Evidence:\n{evidence}\n\n"
        "Requirements:\n"
        "- In plain English, say what activity the rule catches and which "
        "match conditions trigger it.\n"
        "- List the most likely false positives given the XML.\n"
        "- Reference the rule ID. Do not invent capabilities not visible in "
        "the XML; say \"unknown\" where the XML is ambiguous."
    )
    return [ChatMessage(role="system", content=_GROUNDING),
            ChatMessage(role="user", content=user)]


def report_narrative(summary: dict) -> list[ChatMessage]:
    """Write a 2-3 paragraph executive summary from a posture summary."""
    score = summary.get("score", "unknown")
    covered = summary.get("techniques_covered", "unknown")
    total_t = summary.get("techniques_total", "unknown")
    dead = summary.get("dead_rules", "unknown")
    noisy = summary.get("noisy_rules", "unknown")
    top_gaps = summary.get("top_gaps", [])
    evidence = "\n".join([
        f"posture score: {score}",
        f"techniques covered: {covered} of {total_t}",
        f"dead rules: {dead}",
        f"noisy rules: {noisy}",
        "top gaps: " + (", ".join(str(g) for g in top_gaps) if top_gaps else "none listed"),
    ])
    user = (
        "Write a 2-3 paragraph executive summary for a CISO.\n\n"
        f"Evidence:\n{evidence}\n\n"
        "Requirements:\n"
        "- Cover the posture score, coverage counts, dead and noisy rule "
        "counts, and the top gaps.\n"
        "- Use only the numbers given above. Do not invent any numbers.\n"
        "- Plain English, no marketing copy."
    )
    return [ChatMessage(role="system", content=_GROUNDING),
            ChatMessage(role="user", content=user)]
