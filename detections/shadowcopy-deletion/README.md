# Shadow Copy Deletion (Ransomware Precursor)

Detects attempts to delete Volume Shadow Copies on Windows using common utilities:
- vssadmin.exe
- wbadmin.exe
- wmic.exe
- PowerShell (e.g., WMI/CIM shadowcopy deletion)

Shadow copy deletion is frequently seen as a precursor to ransomware encryption because it reduces the victim’s ability to recover.

## What this detects
High-confidence commands such as:
- `vssadmin delete shadows /all /quiet`
- `wbadmin delete catalog -quiet`
- `wmic shadowcopy delete`
- PowerShell executing WMI/CIM shadowcopy deletion actions

## Data required
- Sysmon Event ID 1 (Process Create) recommended
- Windows Security 4688 (Process Creation) works too (field names may vary)
- Splunk TA for Sysmon / Windows recommended for best field extraction

## How to validate (safe)
Run ONE of the following on a test VM (admin required):
- `vssadmin delete shadows /all /quiet`
- `wmic shadowcopy delete`

Expected:
- Detection fires on process creation containing shadow copy deletion keywords.
- Parent process may indicate how it was launched (cmd, powershell, remote tool, etc.).

## Files in this detection package
- logic.md — detection logic + matching conditions
- mitre.md — MITRE mapping + rationale
- tuning.md — false positives + allowlist patterns
- query.spl — SPL for normalized process fields (recommended)
- query_sysmon_xml.spl — SPL for raw Sysmon XML process creation fields
- evidence/ — screenshots or sample events from validation
