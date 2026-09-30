#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 05-firstboot: a failed or unfinished first boot, a failed/skipped TPM binding, or a leftover one-time LUKS key must not
# go unnoticed (the key file opens the disk until its slot is killed; /root backups would carry it).
fb=${CHP_FIRSTBOOT_DIR:-/var/lib/chp/firstboot}; root=${CHP_ROOT_DIR:-/root}
up=${CHP_UPTIME:-$(cut -d. -f1 /proc/uptime)}
bad=0
for u in chp-firstboot-common chp-server-firstboot; do
  systemctl cat "$u.service" >/dev/null 2>&1 || continue
  if systemctl is-failed -q "$u.service"; then echo "ALERT $u failed: journalctl -u $u; then systemctl restart $u"; bad=1; fi
done
if [ ! -e "$fb/common.done" ] && [ "$up" -gt 1800 ]; then echo "ALERT common first boot not complete 30 min after boot"; bad=1; fi
if systemctl cat chp-server-firstboot.service >/dev/null 2>&1 && [ ! -e "$fb/server.done" ] && [ "$up" -gt 1800 ]; then
  echo "ALERT server first boot not complete 30 min after boot"; bad=1
fi
if [ -e "$fb/common.bind-failed" ]; then echo "ALERT TPM binding failed or was skipped: the disk needs the escrowed passphrase at every boot (journalctl -t chp-firstboot-common)"; bad=1; fi
if [ -e "$root/.chp-bind.key" ]; then echo "ALERT the one-time LUKS key $root/.chp-bind.key is still present (it opens the disk): systemctl restart chp-firstboot-common"; bad=1; fi
[ "$bad" -eq 0 ] && echo "OK first boot complete, TPM bound"
exit 0
