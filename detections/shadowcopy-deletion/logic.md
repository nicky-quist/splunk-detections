# Detection logic

## Core idea
Flag process creation events where the process name is a known utility used to delete shadow copies
AND the command line indicates deletion behavior.

## Matching logic (high-signal)
Trigger when ANY of the following are true:

A) vssadmin shadow deletion
- process ends with: vssadmin.exe
- command line contains: "delete" AND "shadows"
- optional strong indicators: "/all", "/quiet"

B) wbadmin catalog/systemstate deletion
- process ends with: wbadmin.exe
- command line contains: "delete" AND ("catalog" OR "systemstatebackup")
- optional strong indicator: "-quiet"

C) wmic shadowcopy deletion
- process ends with: wmic.exe
- command line contains: "shadowcopy" AND "delete"

D) PowerShell shadow copy deletion patterns (more variable)
- process ends with: powershell.exe OR pwsh.exe
- command line contains indicators of WMI/CIM shadowcopy deletion, such as:
  - "Win32_ShadowCopy"
  - "Delete()"
  - "Get-CimInstance" + "Win32_ShadowCopy"
  - "Get-WmiObject" + "Win32_ShadowCopy"

## Why this works
Most legitimate admin workflows do not frequently delete ALL shadow copies quietly.
Attackers do this to prevent rollback and recovery.

## Severity guidance
- vssadmin delete shadows /all /quiet => HIGH
- wmic shadowcopy delete => HIGH
- wbadmin delete catalog -quiet => HIGH
- PowerShell WMI/CIM shadowcopy deletion => MED-HIGH (tune per environment)
