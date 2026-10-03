default_repair: time-resync
---
This host's clock differs from the time source by more than the 30-second authenticator-code window, so one-time codes fail and certificate checks are unreliable. ISSO decision #30 keeps chrony's gradual correction (a large offset takes about two hours) and raises an alert past 30 seconds. A person may approve a one-time step of the clock (time-resync) to restore logins at once; it is never done automatically.
