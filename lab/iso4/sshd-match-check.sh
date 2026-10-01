#!/bin/bash
# sshd-match-check.sh (RUNS ON AERO, as a normal user; never touches aero's sshd): does a Match block in the LAST
# drop-in (99-chp-exceptions.conf) leak past the end of its file into the main sshd_config lines that follow the
# Include? Builds a Rocky-like tree in a temp dir and asks `sshd -T` for three users. Prints one line per user.
set -euo pipefail
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir "$T/d"
ssh-keygen -q -t ecdsa -N '' -f "$T/hk"; ssh-keygen -q -t ecdsa -N '' -f "$T/ca"
cat > "$T/main" <<M
Include $T/d/*.conf
X11Forwarding no
MaxAuthTries 3
M
sed "s#/etc/ssh/chp_user_ca.pub#$T/ca.pub#" "$1/sshd-10-chp.conf" > "$T/d/10-chp.conf"
cp "$1/sshd-99-chp-exceptions.conf" "$T/d/99-chp-exceptions.conf"
/usr/sbin/sshd -V 2>&1 | head -1
for u in alice chpadmin diag; do
  printf '%s: ' "$u"
  /usr/sbin/sshd -T -f "$T/main" -h "$T/hk" -C "user=$u,host=h,addr=1.2.3.4" 2>/dev/null \
    | awk '$1=="authenticationmethods"||$1=="x11forwarding"||$1=="maxauthtries"{printf "%s=%s ", $1, $2} END{print ""}'
done
