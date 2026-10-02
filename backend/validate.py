"""Offline validator for a single Wazuh ``<rule>`` XML snippet.

Checks, in order:

- the text is well-formed XML;
- the document has a single ``<rule>`` root element (a bare fragment such as
  ``<rule ...>...</rule>`` is acceptable);
- ``id`` is present, an integer, and in the range 1..999999 (Wazuh rule ids
  are positive and six digits at most in practice);
- ``level`` is present, an integer, and in the range 0..16 (Wazuh's severity
  scale);
- ``<description>`` exists and is non-empty;
- ``<group>`` exists and is non-empty;
- when ``<mitre>`` is present, every ``<id>`` inside it matches
  ``^T\\d{4}(\\.\\d{3})?$`` (e.g. ``T1059`` or ``T1059.001``).

Validation is structural only: it does not check Wazuh decoder
compatibility, rule logic, or whether referenced MITRE ids exist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class ValidationResult:
    """Outcome of validating one rule snippet."""

    ok: bool
    errors: list[str] = field(default_factory=list)


def validate_rule_xml(xml_text: str) -> ValidationResult:
    """Validate one ``<rule>`` XML snippet; never raises."""
    errors: list[str] = []
    text = (xml_text or "").strip()
    if not text:
        return ValidationResult(ok=False, errors=["empty input"])

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return ValidationResult(ok=False, errors=[f"malformed XML: {exc}"])

    if root.tag != "rule":
        return ValidationResult(
            ok=False,
            errors=[f"expected a single <rule> root element, found <{root.tag}>"],
        )

    rid = root.get("id")
    if rid is None:
        errors.append("missing id attribute")
    else:
        try:
            n = int(rid)
            if not 1 <= n <= 999999:
                errors.append(f"id {n} is outside the allowed range 1..999999")
        except (TypeError, ValueError):
            errors.append(f"id {rid!r} is not an integer")

    level = root.get("level")
    if level is None:
        errors.append("missing level attribute")
    else:
        try:
            n = int(level)
            if not 0 <= n <= 16:
                errors.append(f"level {n} is outside the Wazuh range 0..16")
        except (TypeError, ValueError):
            errors.append(f"level {level!r} is not an integer")

    description = root.find("description")
    if description is None or not "".join(description.itertext()).strip():
        errors.append("missing or empty <description>")

    group = root.find("group")
    if group is None or not (group.text or "").strip():
        errors.append("missing or empty <group>")

    for mitre in root.iter("mitre"):
        for mid in mitre.findall("id"):
            value = (mid.text or "").strip()
            if not value:
                errors.append("empty <mitre><id> element")
            elif not MITRE_ID_RE.match(value):
                errors.append(
                    f"malformed MITRE id {value!r}; expected T1234 or T1234.001"
                )

    return ValidationResult(ok=not errors, errors=errors)
