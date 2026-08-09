# Suspicious PowerShell — Encoded / Obfuscated / Download Cradle

## Why this matters
PowerShell is frequently abused for initial execution and payload retrieval (fileless activity). This detection looks for common high-signal flags used in malicious PowerShell such as encoded commands, hidden windows, bypassed execution policy, and download cradles.

## Evidence
Validation screenshot and reproduction notes live here:
- `evidence/README.md`
- `evidence/splunk-hit.png`
  
## Data requirements
One of the following (best → acceptable):
- Sysmon Event ID 1 (Process Create) with command line
- Windows Security 4688 (Process Create) with command line enabled
- EDR process telemetry (process + parent + command line)

## What this detection looks for
- `-enc` / `-encodedcommand` (Base64 payloads)
- `-nop` / `-noprofile` (reduces artifacts)
- `-w hidden` / `-windowstyle hidden`
- `-exec bypass` / `-executionpolicy bypass`
- Download cradles: `IEX`, `Invoke-Expression`, `DownloadString`, `WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`

## Recommended investigation pivots
- Parent process (who launched PowerShell?)
- User + host (is this expected admin activity?)
- Network connections shortly after execution (proxy/DNS/EDR net events)
- Subsequent child processes (cmd.exe, rundll32, mshta, regsvr32, wscript/cscript)
- File writes (Downloads/Temp/AppData) and persistence events

## Response guidance
If suspicious and not expected admin automation:
- Contain host (EDR isolate) and capture volatile details if possible
- Collect script block logs if enabled, and full process tree
- Hunt same command line patterns across environment

## Quick start
- Splunk + Sysmon XML lab: run `query_sysmon_xml.spl`
- Normalized fields / CIM environments: run `query.spl`

