# Password Spray Detection (Windows 4625 Correlation)

Detects likely password spraying based on bursts of failed logons (Event ID 4625) from a single source IP
attempting multiple usernames within a short time window.

This detection focuses on correlation logic (time-window + thresholds) rather than single-event matching.

## What this detects
- One source IP generates failed logons for many distinct users within N minutes
- Optional: highlights when attempts spread across multiple hosts

## Why it matters
Password spraying is common because it avoids account lockouts by trying a small number of passwords
across many accounts. Early detection can prevent account compromise.

## Data required
- Windows Security Event ID 4625 (failed logon)
- Fields commonly used:
  - src_ip (Source Network Address / IpAddress)
  - user (TargetUserName / Account Name)
  - host (destination)
  - LogonType, FailureReason/Status/SubStatus (optional context)

## How to validate (safe)
Generate a handful of failed logons against multiple test accounts from one source:
- RDP attempts to a VM
- SMB auth attempts
- Local script that tries multiple usernames with a wrong password

You do NOT need to lock accounts; keep counts small and use lab accounts.

## Files in this detection package
- logic.md — thresholds + correlation approach
- mitre.md — MITRE mapping + rationale
- tuning.md — reduce noise (service accounts, scanners, misconfigs)
- query.spl — SPL correlation search
- query_sysmon_xml.spl — not applicable (Sysmon) / placeholder note
- evidence/ — screenshots + validation notes
