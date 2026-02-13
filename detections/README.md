# Detections

Each detection lives in its own folder and includes:
- SPL query (`query.spl`)
- detection logic + assumptions (`logic.md`)
- MITRE mapping (`mitre.md`)
- tuning / false positives (`tuning.md`)
- optional test data (`test-data/`)

“Validated on Splunk Free + Sysmon XML via WinEventLog; fields extracted with rex from _raw.”
