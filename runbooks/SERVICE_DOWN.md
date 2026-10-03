default_repair: none
decisions:
user_sees: Whatever the stopped service provides fails: logins, certificate renewal, or checks.
means: A service the identity system needs is not running.
evidence: A required service is not active on this host.
repair: No automatic repair. Read the service's log first to learn why it stopped, then restart it.
if_wrong: Restarting without reading the log hides the cause, and the service is likely to stop again.
rollback: Nothing is changed by this tool.
say_no_if: The service was stopped deliberately for maintenance.
---
A required unit is not active. Read its journal before restarting it; restarting hides the cause.
