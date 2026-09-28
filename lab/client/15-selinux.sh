#!/usr/bin/env bash
# client2: load the lab-only kanidm_lab SELinux module (ISSO option A) and label the unixd socket directory.
set -Eeuo pipefail
cd /tmp/client
checkmodule -M -m -o kanidm_lab.mod kanidm_lab.te
semodule_package -o kanidm_lab.pp -m kanidm_lab.mod
semodule -i kanidm_lab.pp
# /run is an equivalency alias of /var/run, so the rule must be written against /var/run
semanage fcontext -l | grep -q '^/var/run/kanidm-unixd(/.\*)?' || semanage fcontext -a -t kanidm_unixd_var_run_t '/var/run/kanidm-unixd(/.*)?'
systemctl restart kanidm-unixd
sleep 2
ls -Zd /run/kanidm-unixd /run/kanidm-unixd/sock
semodule -l | grep kanidm_lab
