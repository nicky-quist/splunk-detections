# MITRE ATT&CK Mapping — Suspicious PowerShell

## Primary technique
- **T1059.001 — Command and Scripting Interpreter: PowerShell**

## Common related techniques (context-dependent)
These depend on what the PowerShell command is doing:

- **T1027 — Obfuscated/Compressed Files and Information**
  - Encoded command lines (`-enc`, Base64) are often used to hide intent.

- **T1105 — Ingress Tool Transfer**
  - Web download cradles (`DownloadString`, `WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`) are often used to pull payloads.

- **T1059 — Command and Scripting Interpreter (general)**
  - PowerShell frequently chains into other interpreters or LOLBins.

- **T1562.001 — Impair Defenses: Disable or Modify Tools**
  - Execution policy bypass can be used to evade script controls (context matters; admins may also do this).

## Notes for analysts
Always validate:
- Parent process and user context
- Whether the command contacts external infrastructure
- Whether follow-on execution/persistence occurs
