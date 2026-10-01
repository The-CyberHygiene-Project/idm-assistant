#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 49-client-enrolled: the client enrolment finished, chp_kanidm is loaded and the unixd socket dir carries its type.
# (A failed enrolment otherwise leaves the other client checks saying "not enrolled yet" forever; final review I2/I3.)
M=/var/lib/chp/firstboot; up=$(cut -d. -f1 /proc/uptime)
if ! semodule -l 2>/dev/null | grep -qx chp_kanidm; then
  echo "ALERT SELinux module chp_kanidm is not loaded (Kanidm logins and lookups will be denied): reinstall chp-identity-client"
elif [ -e "$M/client.done" ]; then
  t=$(stat -c %C /run/kanidm-unixd 2>/dev/null | cut -d: -f3)
  if [ "$t" = kanidm_unixd_var_run_t ]; then echo "OK client enrolled; chp_kanidm loaded, unixd socket dir labelled"
  else echo "ALERT /run/kanidm-unixd is labelled '${t:-missing}', expected kanidm_unixd_var_run_t"; fi
elif systemctl is-failed -q chp-client-firstboot 2>/dev/null; then
  echo "ALERT client enrolment failed (journalctl -t chp-client-enrol); it is retried every 5 min"
elif [ "$up" -gt 1800 ]; then
  echo "ALERT client enrolment not finished $((up / 60)) min after boot (journalctl -t chp-client-enrol)"
else
  echo "OK client enrolment in progress"
fi
