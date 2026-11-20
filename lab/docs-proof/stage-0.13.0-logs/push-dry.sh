#!/bin/bash
# Task 11b (RUNS ON AERO): temp copy of the 0.13.0 stage + make-repodata (exactly sign-repo's repodata path, UNSIGNED),
# then for each lab host: stream it to /var/tmp/s013 as chpadmin, run outer.sh, log. The stage itself is not touched.
set -u
W=/data/chp-release/tmp-c013; S=/data/chp-release/0.13.0/stage
rm -rf "$W/dry"; mkdir -p "$W/dry/repo"; cp -a "$S"/. "$W/dry/repo/"
bash /data/chp-release/tools/make-repodata.sh "$W/dry/repo" > "$W/dry/make-repodata.log" 2>&1 || { echo "make-repodata FAILED"; cat "$W/dry/make-repodata.log"; exit 1; }
ls "$W/dry/repo/repodata/"
K=/tmp/iso2/iso2_chpadmin; O="-i $K -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes"
for h in 50:server:srv 51:workstation:cli1 52:workstation:cli2; do
  IFS=: read -r ip role n <<<"$h"
  echo "######## iso5-$n (192.168.100.$ip, $role)"
  ssh $O chpadmin@192.168.100.$ip 'rm -rf /var/tmp/s013 && mkdir -p /var/tmp/s013'
  tar -C "$W/dry" -cf - repo | ssh $O chpadmin@192.168.100.$ip 'tar -xf - -C /var/tmp/s013'
  scp -q $O /tmp/s013-dry-run.sh chpadmin@192.168.100.$ip:/var/tmp/s013/dry-run.sh
  scp -q $O /tmp/s013-outer.sh chpadmin@192.168.100.$ip:/var/tmp/s013-outer.sh
  ssh $O chpadmin@192.168.100.$ip "bash /var/tmp/s013-outer.sh $role; rm -f /var/tmp/s013-outer.sh" > "$W/dry/dry-$n.log" 2>&1
  echo "rc=$? log $W/dry/dry-$n.log"
done
