default_repair: time-resync
decisions: 30
user_sees: Authenticator codes are rejected on this workstation, and some secure connections fail.
means: People who log in with an authenticator code are locked out of this machine until its clock is right.
evidence: This host's clock differs from the time source by more than 30 seconds.
repair: Set this workstation's clock to the time source now, once, with your approval.
if_wrong: If the time source itself is wrong, the clock moves to the wrong time. The repair refuses to run without a reachable source.
rollback: Cannot be undone, and does not need to be: the old time was wrong. Without this step the clock corrects itself in about two hours.
say_no_if: The time source itself is in doubt (other machines show clock problems too).
---
This host's clock differs from the time source by more than the 30-second authenticator-code window, so one-time codes fail and certificate checks are unreliable. ISSO decision #30 keeps chrony's gradual correction (a large offset takes about two hours) and raises an alert past 30 seconds. A person may approve a one-time step of the clock (time-resync) to restore logins at once; it is never done automatically.
