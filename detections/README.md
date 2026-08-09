# Detections

Each detection lives in its own folder and includes:
- SPL query (`query.spl`)
- detection logic + assumptions (`logic.md`)
- MITRE mapping (`mitre.md`)
- tuning / false positives (`tuning.md`)
- validation evidence (`evidence/`)

Validated on Splunk Enterprise (Free) against WinEventLog/Sysmon XML sources, with fields normalized via `coalesce()` and `rex` for portability across environments.
