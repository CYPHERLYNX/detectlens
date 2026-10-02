"""PII redaction for text that may be sent to an external LLM.

Heuristics (documented honestly, with known limits):

- IP addresses: dotted-quad tokens ``\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b`` are
  replaced with ``[REDACTED_IP]``.  IPv6, CIDR notation and octets above 255
  are NOT validated or matched — the pattern is deliberately loose to catch
  anything that looks like an IPv4 address.
- Hostnames: FQDN-shaped tokens (two or more dot-separated labels ending in
  a letter-only TLD, e.g. ``web-01.corp.example.com``) become
  ``[REDACTED_HOST]``; so do bare tokens after ``agent:``/``host:``/
  ``hostname:``/``host=`` style keys (e.g. ``agent: web-01``).
- Usernames: values after ``user:``/``username:``/``account:`` (also ``=``
  forms), the phrase ``User <name> logged``, and ``uid=<name>`` become
  ``[REDACTED_USER]``.

Known limits: redaction is pattern-based, not semantic — unusual log
formats, usernames inside free text without a cue word, and single-label
hostnames without an ``agent:``-style key are missed.  FQDN matching can
over-redact dotted tokens such as ``app.config``.  It is a best-effort
privacy layer for optional LLM features, not a guarantee.  Redaction is
idempotent: redacting twice gives the same result as redacting once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class RedactionToggles:
    """Which redaction classes are applied.  Any toggle set to False leaves
    that class of text unchanged."""

    ips: bool = True
    hostnames: bool = True
    usernames: bool = True


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# "agent: web-01", "host=server02", "hostname: db-01.corp.example.com"
_HOST_VALUE = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?"
HOST_KV_RE = re.compile(
    rf"\b(?:agent|host|hostname)\s*[:=]\s*({_HOST_VALUE})\b", re.IGNORECASE
)

# "web-01.corp.example.com" — final label must be letters only so bare
# IPv4 quads are not matched here.
FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)

# "user: jdoe", "username=jdoe", "account: svc-backup"
_USER_VALUE = r"[A-Za-z0-9._-]+"
USER_KV_RE = re.compile(
    rf"\b(?:user|username|account)\s*[:=]\s*({_USER_VALUE})", re.IGNORECASE
)
# "User jdoe logged in"
USER_LOGGED_RE = re.compile(rf"\bUser\s+({_USER_VALUE})\s+logged\b")
# "uid=jdoe"
UID_RE = re.compile(rf"\buid=({_USER_VALUE})")


def _replace_group1(pattern: re.Pattern, text: str, token: str) -> str:
    """Replace only capture group 1 of each match, keeping the surrounding
    key text (e.g. ``user: ``) intact."""

    def _repl(match: re.Match) -> str:
        full = match.group(0)
        start, end = match.start(1) - match.start(0), match.end(1) - match.start(0)
        return full[:start] + token + full[end:]

    return pattern.sub(_repl, text)


def redact_text(text: str, toggles: RedactionToggles | None = None) -> str:
    """Redact IPs, hostnames and usernames from *text* per *toggles*.

    With all toggles off the text is returned unchanged.  ``toggles=None``
    uses the defaults (everything on).
    """
    if toggles is None:
        toggles = RedactionToggles()
    out = text
    if toggles.ips:
        out = IP_RE.sub("[REDACTED_IP]", out)
    if toggles.usernames:
        # Usernames before FQDNs so that "user: j.doe" is treated as a
        # username rather than a hostname.
        out = _replace_group1(USER_KV_RE, out, "[REDACTED_USER]")
        out = _replace_group1(USER_LOGGED_RE, out, "[REDACTED_USER]")
        out = _replace_group1(UID_RE, out, "[REDACTED_USER]")
    if toggles.hostnames:
        out = _replace_group1(HOST_KV_RE, out, "[REDACTED_HOST]")
        out = FQDN_RE.sub("[REDACTED_HOST]", out)
    return out
