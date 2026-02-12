# Detection Logic — Suspicious PowerShell (Encoded/Obfuscated/Download)

## Summary
This detection flags PowerShell executions with combinations of high-signal command-line indicators associated with malicious activity:
- encoded payloads (`-enc`, `-EncodedCommand`)
- execution policy bypass (`-ep bypass`)
- hidden window (`-w hidden`, `-WindowStyle Hidden`)
- profile bypass (`-nop`, `-NoProfile`)
- download / execute patterns (IEX + WebClient/IWR/IRM/BITS)

## Why a score-based approach
Single flags can be noisy (admins use `-NoProfile`; automation might use `-ExecutionPolicy Bypass`).
By scoring multiple indicators, we reduce false positives while keeping coverage for common attacker tradecraft.

### Scoring
- Encoded command: **+3** (strongest signal; often used to hide payloads)
- ExecutionPolicy bypass: **+2**
- Hidden window: **+2**
- IEX / Invoke-Expression: **+2**
- Web download indicators: **+2**
- NoProfile: **+1**

Alert threshold: `score >= 3`

## Required telemetry
Best sources:
- Sysmon EID 1 (Process Create) with Image + CommandLine
- Security 4688 (Process Create) with command line enabled
- EDR process telemetry

The SPL uses `coalesce()` across common field names to be more portable.

## Analyst validation checklist (triage)
1. Confirm process is `powershell.exe` or `pwsh.exe`
2. Review **parent process**:
   - suspicious: `winword.exe`, `excel.exe`, `outlook.exe`, browsers, `wscript/cscript`, `mshta`, `rundll32`, `regsvr32`
3. Inspect the command line for:
   - encoded payloads, remote URLs, staging behavior
4. Pivot:
   - same user/host over last 24h
   - any network connections shortly after execution (proxy/DNS/EDR net events)
   - child processes spawned by PowerShell
5. If confirmed malicious:
   - isolate host, collect process tree, preserve script artifacts/logs if available
