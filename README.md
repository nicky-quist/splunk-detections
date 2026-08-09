# Splunk Detections (SPL)

SOC-style detections written in Splunk SPL with:
- purpose + data requirements
- investigation pivots
- MITRE ATT&CK mapping
- tuning / false positive notes

Every detection here is validated against real (or safely simulated) event data, not just written and left untested — see each detection's `evidence/` folder for proof it actually fires.

## Detections
| Detection | Technique | Validated with |
|---|---|---|
| [`password-spray-4625`](detections/password-spray-4625) | T1110.003 — Password Spraying | Simulated 4625 events via Splunk HEC |
| [`suspicious-powershell`](detections/suspicious-powershell) | T1059.001 — PowerShell | Live Sysmon EID 1 process-create event |
| [`local-admin-creation`](detections/local-admin-creation) | T1136.001 — Create Local Account | Live 4720/4732/4624 sequence |

## Structure
- `detections/<detection-name>/`
  - `README.md` — what it detects, why it matters, data required
  - `query.spl` — the SPL correlation search
  - `logic.md` — detection logic + field quirks
  - `mitre.md` — MITRE ATT&CK mapping
  - `tuning.md` — false-positive sources + tuning knobs
  - `evidence/` — validation screenshots and notes

## Roadmap (next)
- Service creation persistence (user-writable paths, uncommon binaries)
- Multiple failed logons → success (credential-stuffing follow-through, distinct from password spray)
- Suspicious outbound DNS (rare domains, high NXDOMAIN rate)
