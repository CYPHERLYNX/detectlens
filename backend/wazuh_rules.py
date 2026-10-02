"""Lenient parser for Wazuh 4.x ruleset XML files.

Wazuh rule files are XML documents whose root is normally ``<group>`` and
which contain one or more ``<rule id=".." level="..">`` elements.  Real-world
rule files sometimes contain malformed blocks (unescaped ampersands, missing
closing tags, bad entities).  This parser therefore works in two passes:

1. Try to parse the whole file with :mod:`xml.etree.ElementTree`.  If that
   succeeds, every ``<rule>`` element is extracted from the tree.
2. If the whole-file parse fails, fall back to regex-extracting individual
   ``<rule ...>...</rule>`` blocks and parse each block on its own.  Blocks
   that still fail are skipped with a warning.

The parser never raises on malformed input: every problem is recorded in the
returned ``warnings`` list.  Only the standard library is used (no lxml).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET


@dataclass
class Rule:
    """A single parsed Wazuh detection rule."""

    id: int
    level: int
    description: str
    groups: list[str]  # comma-separated <group> entries, split and stripped
    mitre_ids: list[str]  # e.g. ["T1059", "T1059.001"]
    source_file: str
    xml: str  # raw <rule>...</rule> block as found in the file
    raw_attrs: dict = field(default_factory=dict)  # other attributes on <rule>


# Matches one <rule ...>...</rule> block even when the rest of the file is
# broken XML.  Wazuh rule elements are not nested inside each other.
RULE_BLOCK_RE = re.compile(r"<rule\b[^>]*>.*?</rule\s*>", re.DOTALL | re.IGNORECASE)


def _element_text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return "".join(elem.itertext()).strip()


def _parse_rule_element(
    elem: ET.Element, raw_xml: str, source_file: str, warnings: list[str]
) -> Rule | None:
    """Convert one <rule> element into a Rule.  Returns None (with a warning)
    when the block is unusable."""
    rid_raw = elem.get("id")
    if rid_raw is None:
        warnings.append(f"{source_file}: <rule> block without id attribute; skipped")
        return None
    try:
        rid = int(rid_raw)
    except (TypeError, ValueError):
        warnings.append(
            f"{source_file}: <rule> with non-integer id {rid_raw!r}; skipped"
        )
        return None

    level_raw = elem.get("level")
    if level_raw is None:
        level = 0
    else:
        try:
            level = int(level_raw)
        except (TypeError, ValueError):
            warnings.append(
                f"{source_file}: rule {rid} has non-integer level {level_raw!r}; "
                "using 0"
            )
            level = 0

    description = _element_text(elem.find("description"))
    groups = [
        g.strip()
        for g in _element_text(elem.find("group")).split(",")
        if g.strip()
    ]
    mitre_ids: list[str] = []
    for mitre in elem.iter("mitre"):
        for mid in mitre.findall("id"):
            text = (mid.text or "").strip()
            if text:
                mitre_ids.append(text)

    return Rule(
        id=rid,
        level=level,
        description=description,
        groups=groups,
        mitre_ids=mitre_ids,
        source_file=source_file,
        xml=raw_xml,
        raw_attrs={k: v for k, v in elem.attrib.items() if k not in ("id", "level")},
    )


def parse_rule_file(path: str | Path) -> tuple[list[Rule], list[str]]:
    """Parse one Wazuh rules file.

    Returns ``(rules, warnings)``.  Malformed ``<rule>`` blocks are skipped
    with a warning; the function never raises on bad XML.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    rules: list[Rule] = []
    warnings: list[str] = []

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        warnings.append(
            f"{path}: whole-file XML parse failed ({exc}); "
            "falling back to per-block parsing"
        )
        root = None

    if root is not None:
        for elem in root.iter("rule"):
            raw = ET.tostring(elem, encoding="unicode")
            rule = _parse_rule_element(elem, raw, str(path), warnings)
            if rule is not None:
                rules.append(rule)
        return rules, warnings

    # Fallback: extract each <rule>...</rule> block individually.
    for match in RULE_BLOCK_RE.finditer(text):
        block = match.group(0)
        try:
            elem = ET.fromstring(block)
        except ET.ParseError as exc:
            snippet = block[:80].replace("\n", " ")
            warnings.append(
                f"{path}: skipping malformed <rule> block ({exc}): {snippet!r}..."
            )
            continue
        if elem.tag != "rule":
            continue
        rule = _parse_rule_element(elem, block, str(path), warnings)
        if rule is not None:
            rules.append(rule)
    return rules, warnings


def parse_ruleset(
    rules_dir: str | Path, local_rules: str | Path | None = None
) -> tuple[list[Rule], list[str]]:
    """Parse every ``*.xml`` file in *rules_dir* (sorted by name).

    If *local_rules* is given (path to a local_rules.xml-style file), rules
    from it override base rules with the same id — mirroring how Wazuh gives
    local rules precedence.  Returns ``(rules, warnings)``.
    """
    rules_dir = Path(rules_dir)
    rules: list[Rule] = []
    warnings: list[str] = []
    if not rules_dir.is_dir():
        warnings.append(f"{rules_dir}: rules directory not found; no rules parsed")
        return rules, warnings

    by_id: dict[int, Rule] = {}
    for xml_file in sorted(rules_dir.glob("*.xml")):
        file_rules, file_warnings = parse_rule_file(xml_file)
        warnings.extend(file_warnings)
        for rule in file_rules:
            if rule.id in by_id:
                warnings.append(
                    f"{xml_file.name}: duplicate rule id {rule.id} "
                    f"(first seen in {Path(by_id[rule.id].source_file).name}); "
                    "later definition wins"
                )
            by_id[rule.id] = rule

    if local_rules is not None:
        local_path = Path(local_rules)
        if not local_path.is_file():
            warnings.append(f"{local_path}: local rules file not found; skipping")
        else:
            local_parsed, local_warnings = parse_rule_file(local_path)
            warnings.extend(local_warnings)
            for rule in local_parsed:
                if rule.id in by_id:
                    warnings.append(
                        f"{local_path}: local rule {rule.id} overrides base rule"
                    )
                by_id[rule.id] = rule

    return list(by_id.values()), warnings
