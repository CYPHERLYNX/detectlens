# DetectLens

**Wazuh-native Detection Posture Management.** Point it at your deployed Wazuh
ruleset and alert history, and it answers: *what do my detections actually
cover, which rules are dead, which are pure noise, and what am I blind to?*

It attacks alert fatigue **at the source** — fix the rules, don't just triage
faster.

## What it does

- **Ruleset inventory** — parses your real Wazuh rules (`rules/*.xml` +
  `local_rules.xml`): rule IDs, levels, groups, `<mitre>` tags. Lenient
  parser built for real-world 4.x files (multiple top-level groups,
  malformed blocks skipped with warnings, never a crash).
- **ATT&CK coverage heatmap** — tactics × techniques from a bundled 52-technique
  MITRE ATT&CK subset (attributed, Apache-2.0), joined with your rules.
  Covered = 2+ mapped rules, partial = 1, uncovered = 0.
- **Dead / noisy rule findings** — joins your real alert history (OpenSearch
  `wazuh-alerts-*` or an `alerts.json` upload): dead = 0 fires in the window,
  noisy = at/above the volume threshold.
- **Missing-telemetry findings** — flags uncovered techniques whose required
  data components no mapped detection observes (a stated heuristic, not a
  measurement of your log sources).
- **Plain-English explanations + lesson cards** — every finding ships a
  junior-readable explanation citing rule/technique IDs and exact fire
  counts, plus a one-paragraph SOC lesson. In-app glossary on every jargon
  term.
- **AI Studio (optional, key required)** — provider-agnostic AI core
  (OpenAI-compatible, Anthropic, or local Ollama) that explains findings,
  drafts Wazuh XML for coverage gaps, and proposes suppression tuning.
  Every AI output is evidence-graded (must cite rule/technique IDs and
  counts); every drafted rule is **locally validated** before you see it;
  nothing is ever auto-applied.
- **Audit-ready reports** — dated Markdown coverage reports: posture score,
  per-tactic coverage, dead/noisy tables, findings with IDs, method notes.
- **Dark, keyboard-first console** — dense rows, `j/k` + `Enter` + `/` + `?`
  flows, severity triple-coded (color + shape + label) everywhere.

## 5-minute quickstart

```bash
git clone https://github.com/CYPHERLYNX/detectlens.git detectlens && cd detectlens
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 — it boots with a realistic synthetic dataset
(44 rules, 30 days / 5,000 alerts) so every screen works with zero
infrastructure. Take the first-run tour, open your first finding, then
upload your own data in **Settings** (or set `DETECTLENS_RULES_DIR` /
`DETECTLENS_ALERTS`).

Run the tests:

```bash
.venv/bin/python -m pytest tests/ -q   # 103 tests
```

Measured on the seed data (this box): ruleset parse **5.4 ms** (44 rules),
alert load **101 ms** (5,000 alerts), posture compute **12.8 ms**.

## How coverage is defined (read this before quoting numbers)

- **Coverage %** = techniques with ≥1 mapped rule ÷ techniques in the subset.
  On the seed data: 25/52 = **48.1%**. It measures *detection mapping* —
  never "attacks blocked".
- **Posture score** (0–100) = 60% coverage ratio + 25% (1 − dead-rule ratio)
  + 15% (1 − noisy-rule ratio). Seed data scores **55**.
- **Dead** = 0 fires in the analysis window (default 30 days, anchored at
  your newest alert). **Noisy** = fires ≥ threshold (default 100/window).
- **Missing telemetry** is inferred from detection mappings, not measured
  from your log pipeline — the report says so explicitly.

## What data leaves your network

**Default: nothing.** Local-only mode is the default — the complete posture
audit (parse → coverage → findings → report) runs fully offline with zero
network calls. AI features are locked behind an explicit provider
configuration and show "Requires AI key" instead of failing silently.

When you enable a provider, only the *explicitly sent* payload leaves, per
action:

| Action | Sent | Never sent by default |
|---|---|---|
| Explain finding | finding title, severity, rule/technique IDs, fire counts | raw alert logs |
| Draft rule | technique ID/name, existing rule IDs, one sample rule's XML | alert contents |
| Propose suppression | rule XML snippet, aggregated fire count, 5 sample alert summaries | full alert history |
| NL posture query | your question + the filter-field schema | any estate data |
| Executive summary | posture score, coverage counts, dead/noisy counts, top gap IDs | raw alert logs |
| Test connection | provider handshake only | — |

Field-level redaction (default **on**) strips IP addresses, hostnames, and
usernames before any prompt is built. The Ollama adapter keeps everything
on your network. API keys live only in `DETECTLENS_LLM_KEY` or
`~/.detectlens/config.yaml` (0600) — never in the repo, never in logs,
never in API responses. DetectLens collects no telemetry itself.

## Honest prior art

Searched 2026-09-30 and 2026-10-02 (web + GitHub + Product Hunt). No
standalone Wazuh-native detection-posture product found in open source.
The closest things, and exactly how DetectLens differs:

- **[Kjean13/rulescope](https://github.com/Kjean13/rulescope)** — a *governance
  CLI for Sigma detection catalogs*: quality scoring, duplicate detection,
  CI gates for detection-content PRs. Sigma-focused, CLI-only, content
  governance — not Wazuh-native, not joined with live fire history, not a
  console product.
- **[saidhfm/aisoc](https://github.com/saidhfm/aisoc)** (AI-SOC platform) —
  ships a free *browser-based* ATT&CK coverage grader among other utilities
  at tryaisoc.com/tools. A utility inside a larger triage/investigation
  platform — not Wazuh-native, not a continuous audit of a deployed
  ruleset, no dead/noisy/telemetry findings from real fire history.
- **Cribl Detect** (commercial, launched 2026-09-29) — detection posture
  management with ATT&CK-mapped gaps and broken/noisy rule detection.
  Paid, cloud, pipeline-native — not Wazuh-native, not self-hosted OSS,
  not offline-capable.
- Also adjacent, not equivalent: `wazuh/integrations/wazuh_decoder_rule_tool`
  (official Wazuh repo — generates decoder/rule XML from a pasted log, a
  single-shot generator, not a posture auditor); `gensecaihq/wazuh-autopilot`
  (13-agent triage/investigation swarm, no coverage product); `purpleloop` /
  `aria` (Sentinel/Splunk-only).

Differentiation in one line: DetectLens is the only **Wazuh-native,
self-hosted, offline-first** detection-posture auditor that joins your
**deployed ruleset with your real fire history** and reasons over that
evidence with an optional, grounded AI core.

## AI providers

| Provider | Config | Notes |
|---|---|---|
| OpenAI-compatible (default) | `openai_compat`, base URL + model + key | also covers local OpenAI-compatible servers |
| Anthropic | `anthropic`, model + key | — |
| Ollama / local | `ollama`, base URL + model | data never leaves your network |

Keys via `DETECTLENS_LLM_KEY` env or Settings (stored 0600). No key, or
local-only on (the default), = full offline product. Test the connection
from Settings before relying on AI features.

## Safety notes

- Drafted XML is validated locally for well-formedness and Wazuh sanity
  (id range, level, group, `<mitre>` format) — but **`wazuh-analysisd -t`
  on your manager remains the final gate**. Nothing is auto-applied, ever.
- No write-back to a live Wazuh manager (explicitly out of scope).
- No authentication in this release — bind to `127.0.0.1` or put it behind
  your own reverse proxy.
- MITRE ATT&CK content © MITRE Corporation, used under Apache License 2.0
  ([attack.mitre.org](https://attack.mitre.org)); bundled subset attributed
  in `data/attack_subset.json`.

## Project layout

```
backend/        FastAPI app + offline engine (rules/alerts/posture/findings/validate/redact/report/config)
backend/ai/     provider adapters (base, openai_compat, anthropic, ollama) + grounded prompts
frontend/       vanilla-JS SPA, hand-rolled dark design tokens, zero chart deps
data/           ATT&CK subset + seed ruleset/alerts + EXPECTED.md ground truth
tests/          103 tests: parser, engine, validation, redaction, adapters (mocked), API, key hygiene
```

## License

MIT — see [LICENSE](LICENSE).
