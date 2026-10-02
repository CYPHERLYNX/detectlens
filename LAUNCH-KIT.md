# DetectLens — Launch Kit (local only, do NOT commit)

Copy-paste drafts for the user to post from their own accounts. Never posted by the agent.

## Show HN
Title: `Show HN: DetectLens – Wazuh-native detection posture management (open source)`
Comment draft:
```
I run Wazuh and could never answer "what do our detections actually cover?"
without a spreadsheet. So I built DetectLens: point it at your ruleset
(rules/*.xml + local_rules.xml) and alert history, and it builds a rule
inventory with MITRE tags, joins real fire counts, and renders an ATT&CK
coverage heatmap plus a findings queue — dead rules (0 fires in N days),
noisiest rules, uncovered techniques, missing telemetry.

Fully offline by default; an optional AI mode (OpenAI-compatible, Anthropic,
or Ollama) explains findings in plain English and drafts Wazuh XML for gaps,
but every AI output is evidence-graded (cites rule/technique IDs and counts)
and every drafted rule is locally validated before you see it. Nothing is
auto-applied.

Honest scope: coverage % means "techniques with ≥1 mapped rule", not "attacks
blocked". Validated XML still needs wazuh-analysisd -t on your manager.

Repo: <repo-url> — feedback welcome, especially from Wazuh operators.
```

## Product Hunt
Tagline: `See what your Wazuh detections actually cover — dead rules, noise, gaps`
Description:
```
DetectLens audits your deployed Wazuh detection posture continuously: ATT&CK
coverage heatmap from your real rules, dead and noisy rules from your real
alert history, missing-telemetry findings — then explains each gap in plain
English and drafts validated Wazuh XML to close it. Offline-first, MIT-licensed.
```

## Reddit — r/SideProject
Title: `I built an open-source Wazuh detection posture auditor (dead rules, noise, ATT&CK gaps)`
Body:
```
After one too many "why is nobody looking at this rule" moments, I built
DetectLens: a Wazuh-native detection posture tool. It parses your deployed
ruleset XML, joins your alert history, and tells you which rules are dead,
which are pure noise, which ATT&CK techniques you have zero coverage for,
and where you're probably not even collecting the right telemetry.

There's an optional AI mode (any OpenAI-compatible endpoint, Anthropic, or
local Ollama) that explains findings for junior analysts and drafts Wazuh XML
for gaps — but the offline core is the complete product, and every AI output
cites the rule/technique IDs and counts it was derived from.

MIT licensed, dark SOC-style UI, 5-minute quickstart with synthetic seed data
so you can try it with zero infrastructure. Would love feedback from anyone
running Wazuh in production.
```

## Reddit — r/opensource
Title: `DetectLens — open-source detection posture management for Wazuh (MIT)`
Body: same core as above, lead with: offline-first, no telemetry, keys via env only, Apache-2.0-attributed ATT&CK subset bundled.

## X / LinkedIn (short)
1. `Shipped DetectLens: point it at your Wazuh ruleset + alert history and it shows you which rules are dead, which are noise, and which ATT&CK techniques you're blind to. Offline-first, open source.`
2. `The scariest Wazuh finding isn't a critical alert — it's a rule that hasn't fired in 90 days and nobody noticed. DetectLens finds those automatically.`
3. `Built a Wazuh-native detection posture auditor: real coverage heatmap from your deployed rules, dead/noisy rule detection from real fire history, AI-drafted (locally validated) XML for gaps. MIT licensed.`
