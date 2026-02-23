# Validation Notes – Password Spray (Windows 4625)

## Date
YYYY-MM-DD

## Environment
Splunk: Splunk Enterprise (Free) on nqlaptop  
Ingest Method: HTTP Event Collector (HEC)  
Indexer Acknowledgement: Enabled (required X-Splunk-Request-Channel header)

## Simulation Method
Generated simulated Windows Security 4625-style events via HEC to safely validate correlation logic.
Events represented failed logons from a single source IP across multiple usernames within a 10-minute window.

## Parameters Used
Source IP: 10.0.0.50  
Users: 10 usernames  
Failures per user: 2  
Targets: WIN10-LAB1, WIN10-LAB2, WIN10-LAB3  
Total events: 20

## Expected Result
Correlation search should return results where:
- failures >= 8
- distinct_users >= 6
- grouped by source IP within 10 minutes

## Observed Result
Detection triggered successfully.
Correlation output showed a single source IP with elevated failures and high distinct user count.
Supporting screenshots are included in this folder.

## Notes
This validation uses simulated events for repeatability and to avoid impacting real authentication systems.
