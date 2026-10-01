#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 53-ga: the second factor is still wired in (rows 11, 36): the GA line in system-auth AND password-auth, the token
# directory 700 root root, every token owner-only root (0400 as the PAM module writes it, or 0600) and labelled as policy.
M=/var/lib/chp/firstboot; D=/var/lib/google-authenticator
if [ ! -e "$M/client.done" ]; then echo "OK GA (not enrolled yet)"; exit 0; fi
for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
  grep -q "pam_google_authenticator.so secret=$D/\${USER} user=root" "$f" || { echo "ALERT GA: $f has no pam_google_authenticator line (second factor off)"; exit 0; }
done
[ "$(stat -c '%a %U %G' "$D" 2>/dev/null)" = "700 root root" ] || { echo "ALERT GA: $D is '$(stat -c '%a %U %G' "$D" 2>&1)', expected 700 root root"; exit 0; }
for t in "$D"/*; do
  [ -e "$t" ] || continue
  case "$(stat -c '%a %U %G' "$t")" in 400\ root\ root|600\ root\ root) ;; *) echo "ALERT GA: token ${t##*/} is '$(stat -c '%a %U %G' "$t")', expected owner-only root (400|600 root root)"; exit 0 ;; esac
done
drift=$(restorecon -nRv /var/lib/google-authenticator 2>/dev/null)
if [ -n "$drift" ]; then echo "ALERT GA: token labels drifted: $(printf '%s' "$drift" | head -c 200)"; else echo "OK GA wired in; $(ls -A "$D" | wc -l) token(s), owner-only, labelled"; fi
