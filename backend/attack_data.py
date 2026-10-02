"""MITRE ATT&CK technique data.

DetectLens ships an offline subset of the ATT&CK enterprise matrix.  The
expected JSON shape is a list of objects with ``id`` (e.g. ``"T1059"``),
``name``, ``tactics`` (list of tactic display names), ``data_components``
(list of display names such as ``"Process: Process Creation"``) and
``description``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


# The 14 ATT&CK enterprise tactics in canonical matrix order.
TACTICS: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class Technique:
    """One ATT&CK technique from the offline subset."""

    id: str  # e.g. "T1059" or "T1059.001"
    name: str
    tactics: list[str]  # tactic display names, subset of TACTICS
    data_components: list[str]  # telemetry the technique is observable through
    description: str


def load_attack_subset(path: str | Path) -> list[Technique]:
    """Load the offline ATT&CK technique subset from a JSON file.

    Accepts either a bare JSON list of technique objects or a JSON object
    with a ``techniques`` key holding that list (the shape DetectLens
    ships in ``data/attack_subset.json``, which also carries attribution
    metadata at the top level).

    Raises ``ValueError`` when the file contains neither shape, or when a
    record is missing its ``id``.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("techniques")
    if not isinstance(raw, list):
        raise ValueError(
            f"{path}: expected a JSON list of techniques "
            "(or an object with a 'techniques' key)"
        )
    techniques: list[Technique] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or "id" not in item:
            raise ValueError(f"{path}: technique at index {i} is missing its id")
        techniques.append(
            Technique(
                id=str(item["id"]),
                name=str(item.get("name", "")),
                tactics=list(item.get("tactics", []) or []),
                data_components=list(item.get("data_components", []) or []),
                description=str(item.get("description", "")),
            )
        )
    return techniques
