"""Detection-posture engine: coverage, rule health and missing telemetry.

Pure functions, zero network access.  The engine maps parsed Wazuh rules to
ATT&CK techniques through the rules' MITRE ids, counts how often each rule
fired in the alert window, and derives a posture score plus supporting
detail.

Decision rules (all documented here and applied verbatim by
:func:`compute_posture`):

- Technique coverage: a technique is **covered** when 2 or more rules map to
  it, **partial** when exactly 1 rule maps to it, and **uncovered** when no
  rule maps to it.
- Rule health: a rule is **dead** when it fired 0 times in the window,
  **noisy** when its fire count is at or above ``noisy_min_alerts``, and
  **healthy** otherwise.  A rule that is both dead and noisy cannot exist
  (0 < ``noisy_min_alerts``); dead is checked first.
- Technique fire count = sum of the fire counts of the rules mapped to it.
- Collected data components = union of the ``data_components`` of every
  technique that has at least one mapped rule.  This is a heuristic proxy
  for "telemetry the estate actually collects", inferred from what the
  deployed detections look at.
- Missing telemetry: an **uncovered** technique whose data components are
  *all* outside the collected set is reported as missing telemetry.  The
  reasoning is heuristic: if no deployed detection observes any of the
  technique's data components, the estate is probably not collecting that
  telemetry at all.  Techniques with an empty data-component list are never
  flagged (there is nothing to compare).
- Posture score: ``round(clamp(0..100, 100 * (0.6 * coverage_ratio
  + 0.25 * (1 - dead_ratio) + 0.15 * (1 - noisy_ratio))))`` where
  ``coverage_ratio = (covered + 0.5 * partial) / techniques_total``,
  ``dead_ratio = dead_rules / rules_total`` and
  ``noisy_ratio = noisy_rules / rules_total``.  Empty denominators are treated
  as 0 so the function never divides by zero.

MITRE id matching between rules and techniques is exact string matching
(e.g. ``"T1059.001"`` only maps to a technique literally listed under that
id).  Alerts are expected to be pre-filtered to the analysis window (see
:func:`alerts.filter_days`); ``window_days`` is recorded as metadata.
"""

from __future__ import annotations

from dataclasses import dataclass

from .alerts import count_by_rule, Alert
from .attack_data import TACTICS, Technique
from .wazuh_rules import Rule


@dataclass
class TechniqueCoverage:
    """Coverage state of one ATT&CK technique."""

    technique_id: str
    state: str  # "covered" | "partial" | "uncovered"
    rule_ids: list[int]  # rules mapped to this technique, sorted
    fire_count: int  # sum of mapped-rule fires in the window


@dataclass
class RuleHealth:
    """Health state of one rule over the analysis window."""

    rule_id: int
    state: str  # "healthy" | "dead" | "noisy"
    fire_count: int


@dataclass
class PostureReport:
    """Full posture analysis result."""

    posture_score: int
    window_days: int
    techniques_total: int
    covered: int
    partial: int
    uncovered: int
    coverage_by_tactic: dict  # tactic -> {"covered","partial","uncovered","total"}
    technique_coverage: dict  # technique_id -> TechniqueCoverage
    rule_health: dict  # rule_id -> RuleHealth
    missing_telemetry: list  # [{"technique_id","technique_name","data_components","reason"}]
    totals: dict  # {"rules","alerts","rules_fired"}


def compute_posture(
    rules: list[Rule],
    alerts: list[Alert],
    techniques: list[Technique],
    window_days: int = 30,
    noisy_min_alerts: int = 100,
) -> PostureReport:
    """Compute the detection posture over the given rules, alerts and
    techniques.  See the module docstring for the exact decision rules."""
    fires = count_by_rule(alerts)

    # Map technique id -> sorted list of mapped rule ids (exact MITRE id match).
    tech_rules: dict[str, list[int]] = {}
    for rule in rules:
        for mitre_id in rule.mitre_ids:
            tech_rules.setdefault(mitre_id, []).append(rule.id)
    for rule_ids in tech_rules.values():
        rule_ids[:] = sorted(set(rule_ids))

    technique_coverage: dict[str, TechniqueCoverage] = {}
    for tech in techniques:
        rule_ids = tech_rules.get(tech.id, [])
        fire_count = sum(fires.get(rid, 0) for rid in rule_ids)
        if len(rule_ids) >= 2:
            state = "covered"
        elif len(rule_ids) == 1:
            state = "partial"
        else:
            state = "uncovered"
        technique_coverage[tech.id] = TechniqueCoverage(
            technique_id=tech.id,
            state=state,
            rule_ids=rule_ids,
            fire_count=fire_count,
        )

    rule_health: dict[int, RuleHealth] = {}
    for rule in rules:
        fire_count = fires.get(rule.id, 0)
        if fire_count == 0:
            state = "dead"
        elif fire_count >= noisy_min_alerts:
            state = "noisy"
        else:
            state = "healthy"
        rule_health[rule.id] = RuleHealth(
            rule_id=rule.id, state=state, fire_count=fire_count
        )

    # Heuristic collected-telemetry set: union of data components over
    # techniques that have at least one mapped rule.
    collected: set[str] = set()
    for tech in techniques:
        if technique_coverage[tech.id].rule_ids:
            collected.update(tech.data_components)

    missing_telemetry: list[dict] = []
    for tech in techniques:
        cov = technique_coverage[tech.id]
        if (
            cov.state == "uncovered"
            and tech.data_components
            and all(dc not in collected for dc in tech.data_components)
        ):
            missing_telemetry.append(
                {
                    "technique_id": tech.id,
                    "technique_name": tech.name,
                    "data_components": list(tech.data_components),
                    "reason": (
                        "No deployed rule maps to this technique and none of "
                        "its data components are observed by any mapped "
                        "detection, so the estate is probably not collecting "
                        "the telemetry needed to see it. (Heuristic: inferred "
                        "from detection mappings, not measured from log "
                        "sources.)"
                    ),
                }
            )

    coverage_by_tactic: dict[str, dict] = {}
    for tactic in TACTICS:
        covered = partial = uncovered = 0
        for tech in techniques:
            if tactic in tech.tactics:
                state = technique_coverage[tech.id].state
                if state == "covered":
                    covered += 1
                elif state == "partial":
                    partial += 1
                else:
                    uncovered += 1
        coverage_by_tactic[tactic] = {
            "covered": covered,
            "partial": partial,
            "uncovered": uncovered,
            "total": covered + partial + uncovered,
        }

    covered_n = sum(1 for c in technique_coverage.values() if c.state == "covered")
    partial_n = sum(1 for c in technique_coverage.values() if c.state == "partial")
    uncovered_n = sum(1 for c in technique_coverage.values() if c.state == "uncovered")
    techniques_total = len(techniques)

    dead_n = sum(1 for h in rule_health.values() if h.state == "dead")
    noisy_n = sum(1 for h in rule_health.values() if h.state == "noisy")
    rules_total = len(rules)

    coverage_ratio = (covered_n + 0.5 * partial_n) / techniques_total if techniques_total else 0.0
    dead_ratio = dead_n / rules_total if rules_total else 0.0
    noisy_ratio = noisy_n / rules_total if rules_total else 0.0
    raw = 100.0 * (
        0.6 * coverage_ratio + 0.25 * (1.0 - dead_ratio) + 0.15 * (1.0 - noisy_ratio)
    )
    posture_score = int(round(max(0.0, min(100.0, raw))))

    totals = {
        "rules": rules_total,
        "alerts": len(alerts),
        "rules_fired": sum(1 for r in rules if fires.get(r.id, 0) > 0),
    }

    return PostureReport(
        posture_score=posture_score,
        window_days=window_days,
        techniques_total=techniques_total,
        covered=covered_n,
        partial=partial_n,
        uncovered=uncovered_n,
        coverage_by_tactic=coverage_by_tactic,
        technique_coverage=technique_coverage,
        rule_health=rule_health,
        missing_telemetry=missing_telemetry,
        totals=totals,
    )
