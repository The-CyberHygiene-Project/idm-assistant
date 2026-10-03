default_repair: none
---
The account's expiry time has passed, so Kanidm refuses every login. Expiry is usually deliberate (off-boarding, a contractor's end date). This tool never re-enables an account. ISSO decision #32: only the ISSO or a delegate named in the site file may approve it, with a written reason, using chp-site unexpire, which records both in the audit log.
