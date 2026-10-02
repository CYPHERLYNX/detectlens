"""Prioritised, analyst-readable findings built from a PostureReport.

Findings are sorted by severity (critical, high, medium, low, info) and
assigned stable ids ``F001``, ``F002``, ... in that order.  "Stable" means the
ids are a deterministic function of the input: the same posture report always
produces the same ids, so findings can be referenced across runs.

Priority groups, in order:

1. ``coverage_gap`` with severity **critical**: uncovered techniques in the
   high-value tactics (Execution, Persistence, Privilege Escalation, Defense
   Evasion, Credential Access, Lateral Movement) with zero mapped rules.
2. ``dead_rule`` — severity **medium**.
3. ``noisy_rule`` — severity **high** when fire count exceeds 1000, else
   **medium**.
4. ``missing_telemetry`` — severity **medium**.
5. Other ``coverage_gap``: uncovered techniques outside the high-value
   tactics — severity **low**; partial coverage — severity **info**.

Every explanation is a plain-English template citing rule ids, technique ids
and exact fire counts.  Every lesson is one paragraph teaching a single SOC
concept.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .attack_data import Technique
from .posture import PostureReport
from .wazuh_rules import Rule


# Tactics where a blind spot is treated as critical.
HIGH_VALUE_TACTICS = {
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Lateral Movement",
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Secondary ordering inside a severity: critical gaps, dead rules, noisy
# rules, missing telemetry, then the remaining coverage gaps.
_GROUP_RANK = {
    "coverage_gap_critical": 0,
    "dead_rule": 1,
    "noisy_rule": 2,
    "missing_telemetry": 3,
    "coverage_gap_other": 4,
}


@dataclass
class Finding:
    """One prioritised, human-readable posture finding."""

    id: str  # stable: F001, F002, ...
    kind: str  # "dead_rule" | "noisy_rule" | "coverage_gap" | "missing_telemetry"
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    title: str
    explanation: str  # plain-English, cites rule/technique ids and fire counts
    lesson: str  # one paragraph teaching one SOC concept
    rule_ids: list[int] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    status: str = "new"


LESSONS = {
    "coverage_gap": (
        "A detection gap is the difference between what an attacker can do "
        "and what your monitoring can see. Every ATT&CK technique your estate "
        "cannot detect is a technique an intruder can use freely: it raises "
        "their chance of success and stretches the time between compromise "
        "and discovery. Closing gaps means writing or enabling a rule that "
        "fires on the technique's observable behaviour — not buying more "
        "tools, but covering the specific behaviour you are currently blind "
        "to."
    ),
    "dead_rule": (
        "A dead rule is a rule that fired zero times in the whole window. It "
        "still costs something: it is parsed on every event, it adds noise "
        "to reviews and audits, and it creates a false sense of coverage "
        "('we have a rule for that'). Dead rules usually mean one of three "
        "things: the rule's conditions can never match, the telemetry it "
        "watches is not being collected, or the attack it targets simply "
        "never happens in this environment. Each case deserves a decision — "
        "fix it, scope it, or remove it — rather than letting it sit."
    ),
    "noisy_rule": (
        "A noisy rule fires so often that analysts stop reading its alerts, "
        "which is how real incidents hide inside alert fatigue. Noise is not "
        "just an annoyance: every false positive trains the team to ignore "
        "the rule, so the one true positive it eventually produces gets "
        "missed too. The fix is rarely to delete the rule — it is to raise "
        "its fidelity: tighten the conditions, require corroborating "
        "signals, or convert repeated firings into a single aggregated "
        "alert."
    ),
    "missing_telemetry": (
        "Telemetry is the raw event data your detections reason about — "
        "process creations, logons, file writes, network flows. A rule cannot "
        "fire on data that never arrives: if the agent or log source does "
        "not ship the relevant events to Wazuh, no rule, however well "
        "written, can detect the technique. Missing telemetry is therefore a "
        "collection problem, not a detection problem, and the fix happens at "
        "the source — enable the log, deploy the agent module, or forward "
        "the feed — before any rule can help."
    ),
}


def build_findings(
    posture: PostureReport,
    rules: list[Rule],
    techniques: list[Technique],
    noisy_min_alerts: int = 100,
) -> list[Finding]:
    """Build prioritised findings from a posture report.

    ``noisy_min_alerts`` should match the threshold used in
    :func:`posture.compute_posture` so explanations quote the right number.
    """
    rules_by_id = {r.id: r for r in rules}
    tech_by_id = {t.id: t for t in techniques}

    def tech_name(tid: str) -> str:
        tech = tech_by_id.get(tid)
        return tech.name if tech else "unknown technique"

    def rule_desc(rid: int) -> str:
        rule = rules_by_id.get(rid)
        return rule.description if rule and rule.description else "no description"

    draft: list[tuple[tuple, Finding]] = []

    # 1. Critical coverage gaps: uncovered + high-value tactic + zero rules.
    for tid in sorted(posture.technique_coverage):
        cov = posture.technique_coverage[tid]
        tech = tech_by_id.get(tid)
        tactics = tech.tactics if tech else []
        if cov.state != "uncovered":
            continue
        if any(t in HIGH_VALUE_TACTICS for t in tactics):
            tactic_list = ", ".join(sorted(set(tactics) & HIGH_VALUE_TACTICS))
            draft.append(
                (
                    (_SEVERITY_RANK["critical"], _GROUP_RANK["coverage_gap_critical"], tid),
                    Finding(
                        id="",
                        kind="coverage_gap",
                        severity="critical",
                        title=f"No detection for {tid} ({tech_name(tid)})",
                        explanation=(
                            f"Technique {tid} ({tech_name(tid)}) has 0 mapped "
                            f"rules and 0 fires in the last "
                            f"{posture.window_days} days. It sits in the "
                            f"{tactic_list} tactic, where a blind spot lets an "
                            "attacker operate with no chance of being seen. "
                            "This is the highest-priority gap in the report."
                        ),
                        lesson=LESSONS["coverage_gap"],
                        rule_ids=[],
                        technique_ids=[tid],
                        counts={"mapped_rules": 0, "fire_count": cov.fire_count},
                    ),
                )
            )

    # 2. Dead rules.
    for rid in sorted(posture.rule_health):
        health = posture.rule_health[rid]
        if health.state != "dead":
            continue
        draft.append(
            (
                (_SEVERITY_RANK["medium"], _GROUP_RANK["dead_rule"], rid),
                Finding(
                    id="",
                    kind="dead_rule",
                    severity="medium",
                    title=f"Dead rule {rid}: {rule_desc(rid)}",
                    explanation=(
                        f"Rule {rid} ('{rule_desc(rid)}') fired 0 times in the "
                        f"last {posture.window_days} days. A rule that never "
                        "fires contributes nothing to detection while still "
                        "being evaluated on every matching event."
                    ),
                    lesson=LESSONS["dead_rule"],
                    rule_ids=[rid],
                    technique_ids=[],
                    counts={"fire_count": 0},
                ),
            )
        )

    # 3. Noisy rules.
    for rid in sorted(posture.rule_health):
        health = posture.rule_health[rid]
        if health.state != "noisy":
            continue
        severity = "high" if health.fire_count > 1000 else "medium"
        draft.append(
            (
                (_SEVERITY_RANK[severity], _GROUP_RANK["noisy_rule"], rid),
                Finding(
                    id="",
                    kind="noisy_rule",
                    severity=severity,
                    title=f"Noisy rule {rid}: {rule_desc(rid)}",
                    explanation=(
                        f"Rule {rid} ('{rule_desc(rid)}') fired "
                        f"{health.fire_count} times in the last "
                        f"{posture.window_days} days, at or above the noisy "
                        f"threshold of {noisy_min_alerts} alerts. At this "
                        "volume the alerts are almost certainly being "
                        "ignored, which also buries any genuine incident the "
                        "rule might catch."
                    ),
                    lesson=LESSONS["noisy_rule"],
                    rule_ids=[rid],
                    technique_ids=[],
                    counts={"fire_count": health.fire_count},
                ),
            )
        )

    # 4. Missing telemetry.
    for entry in sorted(posture.missing_telemetry, key=lambda e: e["technique_id"]):
        tid = entry["technique_id"]
        dcs = ", ".join(entry["data_components"])
        draft.append(
            (
                (_SEVERITY_RANK["medium"], _GROUP_RANK["missing_telemetry"], tid),
                Finding(
                    id="",
                    kind="missing_telemetry",
                    severity="medium",
                    title=f"Telemetry likely not collected for {tid} ({entry['technique_name']})",
                    explanation=(
                        f"Technique {tid} ({entry['technique_name']}) is "
                        f"uncovered and its data components ({dcs}) are not "
                        "observed by any mapped detection, with 0 mapped "
                        "rules and 0 fires in the window. The estate is "
                        "probably not shipping this telemetry to Wazuh at "
                        "all, so writing a rule alone would not help."
                    ),
                    lesson=LESSONS["missing_telemetry"],
                    rule_ids=[],
                    technique_ids=[tid],
                    counts={
                        "mapped_rules": 0,
                        "fire_count": 0,
                        "data_components": len(entry["data_components"]),
                    },
                ),
            )
        )

    # 5. Remaining coverage gaps: uncovered outside the high-value tactics
    #    (low), partial coverage (info).
    for tid in sorted(posture.technique_coverage):
        cov = posture.technique_coverage[tid]
        if cov.state == "covered":
            continue
        tech = tech_by_id.get(tid)
        tactics = tech.tactics if tech else []
        high_value = any(t in HIGH_VALUE_TACTICS for t in tactics)
        if cov.state == "uncovered" and high_value:
            continue  # already reported as critical above
        if cov.state == "uncovered":
            severity = "low"
            explanation = (
                f"Technique {tid} ({tech_name(tid)}) has 0 mapped rules and "
                f"0 fires in the last {posture.window_days} days. It is "
                "outside the highest-risk tactics, so it ranks below the "
                "critical gaps, but it is still a complete blind spot."
            )
        else:
            severity = "info"
            rids = ", ".join(str(r) for r in cov.rule_ids)
            explanation = (
                f"Technique {tid} ({tech_name(tid)}) has only 1 mapped rule "
                f"(rule {rids}), which fired {cov.fire_count} times in the "
                f"last {posture.window_days} days. Thin but non-zero "
                "coverage; consider a second, independent detection for "
                "defence in depth."
            )
        draft.append(
            (
                (_SEVERITY_RANK[severity], _GROUP_RANK["coverage_gap_other"], tid),
                Finding(
                    id="",
                    kind="coverage_gap",
                    severity=severity,
                    title=f"{cov.state.capitalize()} coverage for {tid} ({tech_name(tid)})",
                    explanation=explanation,
                    lesson=LESSONS["coverage_gap"],
                    rule_ids=list(cov.rule_ids),
                    technique_ids=[tid],
                    counts={
                        "mapped_rules": len(cov.rule_ids),
                        "fire_count": cov.fire_count,
                    },
                ),
            )
        )

    draft.sort(key=lambda item: item[0])
    findings = []
    for i, (_, finding) in enumerate(draft, start=1):
        finding.id = f"F{i:03d}"
        findings.append(finding)
    return findings


GLOSSARY: dict[str, str] = {
    "severity": "how urgently a finding needs attention: critical, high, medium, low, or info.",
    "coverage": "the share of ATT&CK techniques that have at least one detection rule mapped to them.",
    "detection gap": "an attacker technique with no rule watching for it; a blind spot in monitoring.",
    "false positive": "an alert that fired on benign activity rather than a real threat.",
    "suppression": "deliberately reducing or hiding alerts from a rule, usually to control noise.",
    "telemetry": "the raw event data (logs, process events, network flows) that detections reason about.",
    "data component": "an ATT&CK label for a specific kind of telemetry, e.g. process creation or logon sessions.",
    "mitre att&ck": "a public catalogue of adversary tactics and techniques, used here as the coverage map.",
    "technique": "one specific adversary method in ATT&CK, e.g. T1059 command and scripting interpreter.",
    "tactic": "the attacker's goal at a stage of an intrusion, e.g. execution or persistence; ATT&CK groups techniques under tactics.",
    "dead rule": "a rule that fired zero times in the analysis window.",
    "noisy rule": "a rule whose fire count reached the noise threshold, so its alerts are likely being ignored.",
    "posture score": "a 0-100 number blending technique coverage, dead-rule ratio and noisy-rule ratio.",
    "dwell": "the time between an attacker gaining access and being detected; gaps in coverage lengthen it.",
}
