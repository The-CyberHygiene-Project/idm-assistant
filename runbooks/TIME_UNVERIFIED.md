default_repair: none
decisions: 30
user_sees: Usually nothing yet; the tool holds back its certificate checks.
means: The clock cannot be trusted, so the tool cannot tell whether certificates have expired.
evidence: The time service has no confirmed reading, or is not synchronized.
repair: No automatic repair. Check that the time service is running and can reach its time source.
if_wrong: Setting the clock without a trusted source can set it wrong and break logins.
rollback: Nothing is changed by this tool.
say_no_if: Someone proposes setting the clock by hand without a trusted time source.
---
chrony has not confirmed this host's clock (no reading, or not synchronised). Certificate-expiry verdicts are suppressed until it has. Check that chronyd runs and can reach its source.
