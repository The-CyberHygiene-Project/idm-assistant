default_repair: selinux-restorecon
decisions: 12
user_sees: Logins or the login service fail on this workstation, often with no entry in the security log.
means: The security system silently blocks the login service because some of its files carry the wrong security labels.
evidence: Identity-related files on this host carry a security label different from the one the policy defines.
repair: Put back the security labels the policy defines, only on the identity files that differ.
if_wrong: Little risk: it restores only the labels the installed policy defines, on a fixed list of identity paths.
rollback: The current labels are recorded first and put back if the check afterwards fails.
say_no_if: Those labels were set on purpose as a documented exception.
---
Files carry the wrong SELinux type, so confined services are refused silently: denials for this are not audited, so there may be no AVC at all. restorecon puts back the labels the policy defines.
