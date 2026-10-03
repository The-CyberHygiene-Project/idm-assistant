default_repair: none
decisions: 32
user_sees: One person's logins are all refused, on every machine.
means: That person cannot work until someone with authority re-enables the account.
evidence: The account's expiry date has passed.
repair: No automatic repair. If re-enabling is right, the ISSO or a named delegate does it with chp-site unexpire and a written reason.
if_wrong: Re-enabling an account closed on purpose (someone who left, a contract that ended) gives access back to a person who should not have it.
rollback: Nothing is changed by this tool. chp-site unexpire records who approved it and why.
say_no_if: The expiry was deliberate, or you are not the ISSO or a named delegate.
---
The account's expiry time has passed, so Kanidm refuses every login. Expiry is usually deliberate (off-boarding, a contractor's end date). This tool never re-enables an account. ISSO decision #32: only the ISSO or a delegate named in the site file may approve it, with a written reason, using chp-site unexpire, which records both in the audit log.
