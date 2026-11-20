#!/bin/bash
# Task 11b: unpack the temp repo copy (streamed to /var/tmp/s013 by aero), record the host state, run dry-run.sh in
# unshare -rm, record again, clean up. $1 = role (server | workstation).
set -u
st() { stat -c '%A %U %G %s %y %n' /var/lib/dnf/history.sqlite /var/lib/rpm/rpmdb.sqlite; ls -la --time-style=full-iso /etc/dnf/modules.d;
       rpm -q chp-site chp-base chp-integrity chp-identity-client chp-documents nextcloud-chp chp-onlyoffice; }
echo "== before"; st
echo "== dry-run"; unshare -rm bash /var/tmp/s013/dry-run.sh "$1"
echo "== after"; st
rm -rf /var/tmp/s013; ls -d /var/tmp/s013 2>&1
