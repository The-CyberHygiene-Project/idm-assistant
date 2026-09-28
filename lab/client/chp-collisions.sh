#!/usr/bin/env bash
# chp-collisions.sh [HOST] [LABEL]  (RUNS ON THE MAC): print a read-only snapshot of HOST's identity configuration,
# to diff between steps (kit harden, Kanidm enrolment, re-harden). Writes lab/chp-logs/state-LABEL.txt.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; host="${1:-client1}"; label="${2:-now}"
out="$here/../chp-logs/state-$label.txt"; mkdir -p "$(dirname "$out")"
ssh "$host" "sudo bash -s" > "$out" <<'REMOTE'
echo "== authselect"; authselect current -r 2>&1
for f in system-auth password-auth sshd login gdm-password sudo su; do
  p=/etc/pam.d/$f; echo "== pam.d/$f $(sha256sum $p 2>/dev/null | cut -c1-12)"
  grep -vE '^\s*(#|$)' "$p" 2>/dev/null | sed 's/  */ /g'
done
echo "== nsswitch"; grep -E '^(passwd|group|initgroups|shadow):' /etc/nsswitch.conf
echo "== sshd -T"; sshd -T 2>/dev/null | grep -iE '^(kbdinteractiveauthentication|passwordauthentication|pubkeyauthentication|authenticationmethods|usepam|trustedusercakeys|authorizedkeyscommand|permitrootlogin|denyusers|allowgroups|allowusers|ciphers|macs|kexalgorithms) '
echo "== sssd"; systemctl is-active sssd 2>&1; ls /etc/sssd/sssd.conf 2>&1
echo "== kanidm"; systemctl is-active kanidm-unixd 2>&1; ls /etc/kanidm 2>&1 | tr '\n' ' '; echo
echo "== fapolicyd/usbguard/firewalld"; for s in fapolicyd usbguard firewalld; do echo "$s $(systemctl is-active $s 2>&1)"; done
echo "== local accounts (uid>=1000)"; awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd | tr '\n' ' '; echo
echo "== AVC since boot: $(ausearch --input-logs -m AVC -ts boot 2>/dev/null | grep -c type=AVC)"
REMOTE
lab_scan="$here/../tools/secrets-scan.sh"; "$lab_scan" "$out" >/dev/null || { echo "state file tripped the secrets scan: $out" >&2; exit 1; }
echo "wrote $out ($(wc -l < "$out") lines)"
