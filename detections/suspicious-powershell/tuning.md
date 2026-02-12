# Tuning Notes — Suspicious PowerShell

## Expected false positives (common benign)
These patterns are often legitimate depending on your environment:
- IT/admin automation using `-NoProfile` or `-ExecutionPolicy Bypass`
- Software deployment tools invoking PowerShell:
  - SCCM/ConfigMgr, Intune, PDQ Deploy, Tanium, BigFix, etc.
- Remote management:
  - `powershell.exe` launched by `wmiprvse.exe`, `psexecsvc.exe`, `services.exe` in admin contexts
- Developer workflows/scripts that use `Invoke-WebRequest` / `irm` to pull packages (PowerShellGet, installers)

## High-confidence suspicious combos (prioritize)
Escalate faster when you see:
- `-enc` AND (`IEX` OR `DownloadString` OR `iwr/irm`)
- `-w hidden` AND `-enc`
- Parent process is Office app (`winword.exe`, `excel.exe`, `outlook.exe`) OR browser
- PowerShell spawns LOLBins or suspicious children:
  - `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `cmd.exe`
- Network activity to new/rare external domains shortly after execution

## Practical allowlisting strategy (safe approach)
Do NOT blanket-exclude PowerShell. Instead allowlist by **known-good parents**, **known automation accounts**, and **known management tooling paths**.

### Examples (edit to fit your environment)
- Known admin accounts:
  - allowlist service accounts used for automation
- Known parent processes (if consistent in your org):
  - software deployment agent executables
- Known script locations:
  - signed scripts under controlled directories

## SPL tuning ideas (drop-in edits)
### 1) Exclude known-good hosts or accounts (start small)
Add after the `where score >= 3` line:
- `| where user NOT IN ("svc_patching","svc_deploy")`
- `| where host NOT IN ("SCCM01","INTUNE01")`

### 2) Focus on external download behavior
If you have too many hits, raise threshold OR require web indicators:
- change `| where score >= 3` to `| where score >= 4`
OR
- require web/download: `| where score >= 3 AND (web_download=1 OR iex=1)`

### 3) Require suspicious parent process (high signal)
If your environment is very admin-heavy:
- add: `| where NOT match(lower(parent_process), ".*\\\\(explorer|mmc|powershell_ise)\\.exe$")`
(only do this if it reduces noise without hiding real attacks)

## Validation checklist (before you call it “good”)
- Run for 7 days: identify top parents/users gene
