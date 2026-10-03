default_repair: none
decisions: 46
user_sees: Nothing visible: programs run normally.
means: The control that stops untrusted programs is off.
evidence: fapolicyd is in permissive mode or not running.
repair: No automatic repair. Tell the ISSO, then turn enforcement back on (permissive = 0) and restart fapolicyd.
if_wrong: Leaving it off lets any program run.
rollback: Nothing is changed by this tool.
say_no_if: It was switched off for a documented, time-limited reason.
---
fapolicyd is permissive (it logs but does not block) or not running, so untrusted programs run unchecked. No repair exists (ISSO row 46): the ISSO decides; enforcement is restored by setting permissive = 0 in /etc/fapolicyd/fapolicyd.conf and restarting fapolicyd.
