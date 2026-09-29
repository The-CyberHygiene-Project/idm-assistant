default_repair: selinux-restorecon
---
Files carry the wrong SELinux type, so confined services are refused silently: denials for this are not audited, so there may be no AVC at all. restorecon puts back the labels the policy defines.
