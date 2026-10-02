"""Loading and filtering of Wazuh alert data.

Alerts are expected as either a JSON list of alert objects or
newline-delimited JSON (one object per line, like the real Wazuh
``alerts.json``).  The format is sniffed from the first non-whitespace
character: ``[`` means a JSON list, anything else means NDJSON.  Alert
objects carry the keys ``timestamp`` (ISO 8601), ``rule_id``,
``description``, ``agent``, ``ip`` and ``level`` — a deliberately small
subset of the Wazuh alerts.json schema, just enough for posture analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class Alert:
    """One Wazuh alert, normalised."""

    timestamp: datetime  # always timezone-aware (UTC)
    rule_id: int
    description: str
    agent: str
    ip: str | None
    level: int


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp; naive values are assumed to be UTC."""
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"unparseable timestamp {value!r}: {exc}") from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def load_alerts(path: str | Path) -> list[Alert]:
    """Load alerts from a JSON file.

    Accepts two formats, sniffed from the first non-whitespace character:
    a JSON list (``[``) or newline-delimited JSON (any other character,
    one alert object per line — the format the real Wazuh ``alerts.json``
    uses).

    Raises ``ValueError`` if a record is malformed (bad timestamp, non-integer
    rule id); the error message names the offending record index (list) or
    line number (NDJSON).
    """
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped.startswith("["):
        raw = json.loads(text)
        if not isinstance(raw, list):
            raise ValueError(f"{path}: expected a JSON list of alerts")
        records: list[tuple[int, object]] = list(enumerate(raw))
        label = "index"
    else:
        raw = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}: malformed NDJSON at line {line_no}: {exc}"
                ) from exc
        records = list(zip(range(1, len(raw) + 1), raw))
        label = "line"
    alerts: list[Alert] = []
    for i, item in records:
        try:
            alerts.append(
                Alert(
                    timestamp=_parse_timestamp(str(item["timestamp"])),
                    rule_id=int(item["rule_id"]),
                    description=str(item.get("description", "")),
                    agent=str(item.get("agent", "")),
                    ip=item.get("ip"),
                    level=int(item.get("level", 0)),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{path}: malformed alert at {label} {i}: {exc}") from exc
    return alerts


def filter_days(alerts: list[Alert], days: int) -> list[Alert]:
    """Keep only alerts from the last *days* days relative to now (UTC)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return [a for a in alerts if a.timestamp >= cutoff]


def count_by_rule(alerts: list[Alert]) -> dict[int, int]:
    """Map each rule id to the number of alerts it fired."""
    counts: dict[int, int] = {}
    for alert in alerts:
        counts[alert.rule_id] = counts.get(alert.rule_id, 0) + 1
    return counts
