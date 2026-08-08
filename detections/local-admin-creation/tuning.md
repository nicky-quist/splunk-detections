## Validation notes
Tested against live Sysmon + Security event data (Splunk Free, manual
account creation -> elevation -> logon). Observed real span of 16 minutes
between account creation and first logon, correctly classified as
severity=medium under default thresholds (<=15min=high, <=30min=medium).
