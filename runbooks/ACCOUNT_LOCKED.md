default_repair: faillock-reset
decisions: 44
user_sees: One person can't log in to this workstation, even with the right password; other people can.
means: That person is shut out of this machine for up to 15 minutes after their last failed try.
evidence: Five failed logins in a row locked the account on this workstation (the CUI lockout rule).
repair: Clear that person's failed-login count on this workstation, so they can try again now.
if_wrong: If the failures were someone guessing the password, clearing the count gives them five more tries.
rollback: The count is saved first; undo puts it back, which locks the account again.
say_no_if: The failures came from an address or at a time you don't recognize, or several accounts are locked at once.
---
The account reached this workstation's failed-login limit (pam_faillock; 5 tries and a 15-minute lock in the CUI profile). A wrong authenticator code counts as a failure, so a skewed clock or a mislabelled token file locks out people who type everything right. If TOTP_TIME_SKEW, TIME_UNVERIFIED or SELINUX_LABEL_WRONG is also present, fix that first: faillock-reset refuses until then (ISSO row 44). Failures from unknown sources, or several locked accounts, suggest password guessing rather than mistakes.
