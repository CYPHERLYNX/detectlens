# DetectLens seed data — expected outcomes

All numbers below were computed mechanically from the shipped data files
(`attack_subset.json`, the four rule files, `alerts.json`). They are the
ground truth for verifying DetectLens behavior. No git repo was created;
no generator scripts are retained (alerts were built with a deterministic
`random.seed(42)` script that has been deleted).

## Inventory

| File | Size | Contents |
|---|---|---|
| `../attack_subset.json` | 14,790 B | 52 hand-curated MITRE ATT&CK techniques across all 14 tactics |
| `seed/rules/0500-win_security.xml` | 4,888 B | 14 Windows rules (ids 50001-50014) |
| `seed/rules/0510-linux_auth.xml` | 3,426 B | 12 Linux rules (ids 51001-51012) |
| `seed/rules/0520-web_ids.xml` | 3,697 B | 14 web rules (ids 52001-52014) |
| `seed/local_rules.xml` | 1,239 B | 4 custom local rules (ids 100001-100004) |
| `seed/alerts.json` | 866,719 B | 5,000 alerts, newline-delimited JSON (one object per line, like real Wazuh `alerts.json`) |

**Total rules: 44** (40 in `rules/` + 4 local). **Total alerts: 5,000.**
Alert window: `2026-09-02T00:09:16.307Z` -> `2026-10-01T23:41:33.508Z` (30 days).
Every alert's `rule_id` exists in the rules, and every alert's `level` and
`description` match its rule exactly.

## Noisy rules (top 3 by volume)

| Rule | Description | Fires |
|---|---|---|
| 50001 | Windows: Successful account logon (EventID 4624). | 2,800 |
| 51001 | sshd: Failed password authentication attempt. | 1,400 |
| 52007 | Web: Burst of HTTP 404 responses, possible directory probing. | 600 |

Subtotal: 4,800 alerts (96.0%). The remaining 200 alerts are spread over the
other 38 firing rules (2-60 fires each, clustered in 1-3 burst days).

## Dead rules (0 fires)

| Rule | Description | Why it is dead in this window |
|---|---|---|
| 50012 | Windows: Kerberos pre-authentication failure, possible Kerberoasting (EventID 4768). | No Kerberos pre-auth failures observed |
| 50013 | Windows: Registry Run key modified (EventID 4657). | Registry auditing is rarely enabled on these hosts |
| 52011 | Web: Possible XML external entity (XXE) injection. | No XXE payloads observed |

## Rules with no `<mitre>` tags (8 of 44)

`50009` (account lockout), `50014` (RDP session reconnect),
`51010` (sshd reverse-DNS mismatch), `51011` (sudo session closed),
`52007` (404 probing burst — noisy but untagged), `52013` (invalid HTTP method),
`100003` (USB inserted), `100004` (disk space threshold).

Note the deliberate trap: rule 52007 fires 600 times yet maps to zero
techniques — high volume with zero technique attribution.

## Per-rule fire counts

Windows: 50001=2800, 50002=24, 50003=8, 50004=5, 50005=4, 50006=2,
50007=3, 50008=9, 50009=6, 50010=3, 50011=2, 50012=0, 50013=0, 50014=4.

Linux: 51001=1400, 51002=10, 51003=18, 51004=15, 51005=5, 51006=2,
51007=3, 51008=4, 51009=3, 51010=6, 51011=4, 51012=2.

Web: 52001=3, 52002=4, 52003=3, 52004=2, 52005=2, 52006=6, 52007=600,
52008=5, 52009=4, 52010=2, 52011=0, 52012=2, 52013=8, 52014=3.

Local: 100001=4, 100002=3, 100003=2, 100004=5.

Sum: 5000. Firing rules: 41. Dead rules: 3.

## Technique coverage vs `attack_subset.json` (52 techniques)

Definitions used (the engine's single definition, also used by the API,
heatmap, findings and report — no second definition anywhere):
- **Covered** — 2+ rules tag the technique in `<mitre>`.
- **Partial** — exactly 1 rule tags the technique.
- **Uncovered** — no rule tags the technique at all.
- Headline "coverage %" = techniques with >=1 mapped rule
  (covered + partial) = 25/52 = **48.1%**. It measures detection mapping,
  never "attacks blocked". Whether a mapped rule actually fired is a
  separate signal (dead = 0 fires in the window).

| Status | Count | Share |
|---|---|---|
| Covered | 5 | 9.6% |
| Partial | 20 | 38.5% |
| Uncovered | 27 | 51.9% |

Covered (5): T1059.001, T1078, T1110, T1136.001, T1190.

Partial (20): T1003.001, T1005, T1021.004, T1027, T1036, T1053.003,
T1053.005, T1059.003, T1059.004, T1068, T1070.001, T1083, T1105, T1133,
T1543.003, T1547.001, T1558.003, T1562.001, T1569.002, T1595.002.

Uncovered (27): T1587.001, T1047, T1546.003, T1574.002, T1055, T1134,
T1127, T1003.003, T1040, T1018, T1057, T1082, T1021.001, T1021.002,
T1570, T1039, T1113, T1071.001, T1095, T1573.002, T1008, T1048, T1041,
T1567.002, T1486, T1490, T1565.001.

## Coverage by tactic (covered / partial / uncovered)

| Tactic | C | P | U | Total |
|---|---|---|---|---|
| Reconnaissance | 0 | 1 | 0 | 1 |
| Resource Development | 0 | 0 | 1 | 1 |
| Initial Access | 2 | 1 | 0 | 3 |
| Execution | 1 | 4 | 1 | 6 |
| Persistence | 1 | 3 | 2 | 6 |
| Privilege Escalation | 0 | 1 | 2 | 3 |
| Defense Evasion | 0 | 4 | 1 | 5 |
| Credential Access | 1 | 2 | 2 | 5 |
| Discovery | 0 | 1 | 3 | 4 |
| Lateral Movement | 0 | 1 | 3 | 4 |
| Collection | 0 | 1 | 2 | 3 |
| Command and Control | 0 | 1 | 4 | 5 |
| Exfiltration | 0 | 0 | 3 | 3 |
| Impact | 0 | 0 | 3 | 3 |

## Missing-telemetry examples (for gap narratives)

- **Exfiltration is fully blind:** T1048, T1041, T1567.002 have no rules at
  all — the ruleset cannot see data leaving the network.
- **Impact is fully blind:** T1486 (ransomware encryption), T1490, T1565.001
  have no rules; a destructive attack would fire nothing.
- **C2 is nearly blind:** only T1105 has a rule (partial — 1 mapped rule);
  T1071.001, T1095, T1573.002, T1008 have none.
- **Dead-rule traps:** T1547.001 and T1558.003 are tagged on rules 50013 and
  50012, which fired zero alerts in 30 days — DetectLens reports them as
  partial-by-count plus explicit dead-rule findings, never as healthy
  coverage.
- **Noisy-but-untagged:** rule 52007 (600 fires) contributes zero technique
  coverage; volume must not be confused with posture.
- **Untagged lateral movement:** rule 50014 sees RDP reconnects but carries
  no T1021.001 tag, so RDP lateral movement is uncovered despite telemetry.

## Data conventions

- `alerts.json` is newline-delimited JSON (one alert object per line),
  mirroring the real Wazuh `alerts.json` format.
- Alert schema: `{"timestamp","rule_id","description","agent","ip","level"}`.
- `ip` semantics: for host/auth alerts it is the agent's internal IP
  (`10.20.0.0/16` — present for redaction tests); for brute-force and web
  attack alerts it is the attacker source IP, drawn from the documentation
  ranges `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24` (no real
  infrastructure is referenced).
- Agents: `ws-fin-014`, `ws-fin-022` (Windows workstations), `laptop-hr-07`,
  `laptop-eng-03`, `dc-corp-01` (domain controller), `srv-web-02`,
  `srv-db-01`, `bastion-01`, `waf-edge-01`.
- Noisy rule 50001 follows a diurnal pattern (business hours weighted);
  51001 is uniform (bots don't sleep); 52007 arrives in bot waves on 8 days.
- The generator script was deterministic and has been deleted; only the
  data files above are retained.
