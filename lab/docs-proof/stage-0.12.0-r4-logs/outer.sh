#!/bin/bash
# Task 9d: unpack the temp repo copy, record the host state, run dry-run.sh in unshare -rm, record again, clean up.
set -u
cd /var/tmp && rm -rf s012d && mkdir s012d && tar -xzf ~/s012d.tgz -C s012d && rm -f ~/s012d.tgz
cp ~/dry-run.sh s012d/
st() { stat -c '%A %U %G %s %y %n' /var/lib/dnf/history.sqlite /var/lib/rpm/rpmdb.sqlite; ls -la --time-style=full-iso /etc/dnf/modules.d; rpm -q chp-site chp-base chp-documents nextcloud-chp; }
echo "== before"; st
echo "== dry-run"; unshare -rm bash /var/tmp/s012d/dry-run.sh
echo "== after"; st
rm -rf /var/tmp/s012d ~/dry-run.sh ~/outer.sh; ls -d /var/tmp/s012d 2>&1
