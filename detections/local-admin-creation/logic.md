## Known field quirks (validated against live test data)
- 4732 (added to group) often does NOT populate MemberName reliably;
  only MemberSid is guaranteed. Correlation must join on SID, not username.
- A single account can trigger multiple 4732 events - one for each
  default/explicit group membership change (e.g. Users group on creation,
  then Administrators group on explicit elevation). Filter to
  TargetSid="S-1-5-32-544" specifically to isolate the Administrators
  group and avoid false correlation on the default Users group add.
