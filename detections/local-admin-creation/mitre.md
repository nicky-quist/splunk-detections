# MITRE ATT&CK Mapping
## Technique
T1136.001 - Create Account: Local Account
## Rationale
Adversaries create local accounts and add them to privileged groups to maintain access
that doesn't rely on domain credentials and often draws less scrutiny than domain
account creation. A create -> add to admins -> first logon sequence within a short
window is a common indicator of this behavior versus routine provisioning.
