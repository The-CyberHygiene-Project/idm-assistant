#!/bin/bash
# Task 9c dry-run of the RE-STAGED repo 0.12.0 (chp-site 0.14.0-3; unsigned stage + make-repodata
# on aero, temp copy) on iso5-srv, which has the owner-signed 0.12.0 (round 2: chp-site 0.14.0-2, chp-base 0.1.0-11) APPLIED (the 33
# packages installed, php:8.3 + postgresql:16 enabled). WITHOUT root: dnf runs as uid 0 of a private user+mount
# namespace (unshare -rm). The host's module state is COPIED into a namespace-only tmpfs (so the enabled streams are
# seen as on the host); history, cache and log are tmpfs too. --assumeno on every transaction: nothing changes.
R=/var/tmp/s012c/repo
D="dnf --setopt=reposdir=/nonexistent --repofrompath=s012c,file://$R --repo=s012c --nogpgcheck --setopt=logdir=/run/dnflog"
echo "== whoami inside: $(id -u) ; host module state:"; ls -A /etc/dnf/modules.d; cat /etc/dnf/modules.d/*.module 2>/dev/null
m=$(mktemp -d /var/tmp/s012c/mods.XXXX); cp -a /etc/dnf/modules.d/. "$m"/ 2>/dev/null
mount -t tmpfs none /etc/dnf/modules.d && cp -a "$m"/. /etc/dnf/modules.d/ && mount -t tmpfs none /var/lib/dnf \
  && mount -t tmpfs none /var/cache/dnf && { mkdir -p /run/dnflog 2>/dev/null || { mount -t tmpfs none /run && mkdir -p /run/dnflog; }; }
echo "== installed (ours):"; rpm -q chp-site chp-base chp-identity-server chp-documents nextcloud-chp
echo "== 1. module list (repo s012c only)"; $D --refresh module list 2>&1
echo "== 2. upgrade --assumeno (vs the applied 0.12.0)"; $D upgrade --assumeno 2>&1; echo "rc=$?"
echo "== 3. check-update"; $D check-update 2>&1; echo "rc=$? (100 = updates available)"
echo "== 4. install --assumeno nextcloud-chp chp-documents (already installed: nothing new)"; $D install --assumeno nextcloud-chp chp-documents 2>&1 | tail -5; echo "rc=$?"
