# Evidence

This folder contains validation artifacts that prove the **Suspicious PowerShell** detection works end-to-end in a real Splunk + Sysmon lab.

## What this evidence demonstrates
- Sysmon **Event ID 1 (Process Create)** is being ingested into Splunk (`Microsoft-Windows-Sysmon/Operational`).
- The detection query successfully extracts process fields from Sysmon XML (`User`, `ParentImage`, `Image`, `CommandLine`).
- The detection logic correctly labels suspicious PowerShell activity using:
  - `reason` — why the event matched
  - `severity` — how the event should be prioritized

## Files
- `splunk-hit.png`
  - Screenshot of Splunk results showing the detection firing on a PowerShell process-create event.
  - The screenshot should include the command line and the computed `reason` + `severity` fields.

## How the screenshot was generated (lab validation)
1. Ensure Sysmon is running and logging to:
   - `Microsoft-Windows-Sysmon/Operational`
2. In Splunk, run the Sysmon XML detection query:
   - `../query_sysmon_xml.spl`
3. Trigger a test event on the host:
   ```powershell
   powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Write-Host test"
