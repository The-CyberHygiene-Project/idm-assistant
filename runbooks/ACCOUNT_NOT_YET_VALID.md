default_repair: none
decisions:
user_sees: A new person's logins are refused everywhere.
means: The person cannot work until their account's start date.
evidence: The account is set to become valid at a future date and time.
repair: No automatic repair. Check the start date with whoever requested the account; change it in Kanidm only if it was entered wrong.
if_wrong: Moving the start date earlier gives access before onboarding (training, agreements) is complete.
rollback: Nothing is changed by this tool.
say_no_if: The start date is correct and simply has not arrived.
---
The account has a valid-from time in the future, so Kanidm refuses logins until then. This is normally set on purpose for a start date.
