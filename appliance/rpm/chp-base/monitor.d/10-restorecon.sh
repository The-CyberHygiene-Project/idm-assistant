#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 10-restorecon: identity paths whose SELinux labels differ from policy (dry run; a mislabel fails logins with no AVC).
drift=""
for p in /etc/chp /etc/kanidm /etc/pki/kanidm /etc/ssh-ca /var/lib/ssh-ca /etc/step-ca /etc/idm-collect /var/lib/kanidm-unixd /run/kanidm-unixd; do
  if [ -e "$p" ]; then drift="$drift$(restorecon -nRv "$p" 2>/dev/null)"; fi
done
if [ -n "$drift" ]; then echo "ALERT SELinux labels drifted on identity paths: $(printf '%s' "$drift" | head -c 300)"; else echo "OK SELinux labels"; fi
