# Splunk Detections (SPL)

SOC-style detections written in Splunk SPL with:
- purpose + data requirements
- investigation pivots
- MITRE ATT&CK mapping
- tuning / false positive notes

## Structure
- `detections/<detection-name>/`
  - `README.md`
  - `query.spl`
  - `logic.md`
  - `mitre.md`
  - `tuning.md`
  - `test-data/`

## Roadmap (next)
- Suspicious PowerShell (encoded/obfuscated)
- Local admin creation + first logon correlation
- Service creation persistence (unusual binary paths)
