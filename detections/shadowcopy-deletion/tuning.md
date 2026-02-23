# Tuning & False Positives

## Common legitimate causes
- IT staff performing disk cleanup / backup maintenance
- Backup software invoking vssadmin or wbadmin
- Golden image / VDI preparation scripts
- Incident response remediation scripts

## Recommended tuning approach
1) Start with HIGH-confidence patterns only:
   - vssadmin + "delete shadows" + "/all" (and optionally "/quiet")
   - wmic + "shadowcopy" + "delete"
   - wbadmin + "delete catalog" + "-quiet"

2) Build allowlists based on:
   - Known admin hostnames (e.g., SCCM/backup servers)
   - Known service accounts
   - Known parent processes (backup agent executables)
   - Maintenance windows (time-based filters)

## Practical allowlist examples
- Allow if user is a known backup service account
- Allow if parent_process is a known backup agent binary
- Allow if host is in a backup management subnet

## Escalation guidance
Escalate immediately when:
- Command includes "/all" AND "/quiet"
- Executed by a standard user (not admin/IT)
- Occurs on multiple endpoints in a short time window
- Parent process is suspicious (e.g., rundll32, wscript, mshta, office apps)
