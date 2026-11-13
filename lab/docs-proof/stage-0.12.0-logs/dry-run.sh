#!/bin/bash
# Dry-run of repo 0.12.0 (unsigned stage + make-repodata) on iso5-srv, WITHOUT root: dnf runs as uid 0 of a private
# user+mount namespace (unshare -rm). The real root's files are read-only to it (they map to "nobody"); dnf's
# writable state (module state, history, cache, log) is on tmpfs mounts that exist only inside the namespace.
# Nothing on the host changes; --assumeno on every package transaction.
R=/var/tmp/s012/repo
D="dnf --setopt=reposdir=/nonexistent --repofrompath=s012,file://$R --repo=s012 --nogpgcheck --setopt=logdir=/run/dnflog"
echo "== whoami inside: $(id -u) ; host module state before:"; ls -A /etc/dnf/modules.d
mount -t tmpfs none /etc/dnf/modules.d && mount -t tmpfs none /var/lib/dnf && mount -t tmpfs none /var/cache/dnf \
  && mkdir -p /run/dnflog 2>/dev/null || mount -t tmpfs none /run && mkdir -p /run/dnflog
echo "== 1. module list (repo s012 only)"; $D --refresh module list 2>&1
echo "== 2. module enable php:8.3 postgresql:16 --assumeno"; $D module enable php:8.3 postgresql:16 --assumeno 2>&1; echo "rc=$?"
echo "== 3. module enable -y (namespace-private /etc/dnf/modules.d only)"; $D -y module enable php:8.3 postgresql:16 2>&1; echo "rc=$?"; ls /etc/dnf/modules.d; cat /etc/dnf/modules.d/*.module
echo "== 4. install --assumeno nextcloud-chp chp-documents (streams enabled)"; $D install --assumeno nextcloud-chp chp-documents 2>&1; echo "rc=$?"
echo "== 5. upgrade --assumeno"; $D upgrade --assumeno 2>&1; echo "rc=$?"
echo "== 6. upgrade + install together --assumeno (what a 0.6.0 server does: apply repo, then documents enable)"; $D install --assumeno nextcloud-chp chp-documents chp-site chp-base chp-identity-server 2>&1 | sed -n '/^Dependencies/,$p'; echo "rc=$?"
echo "== 7. control: streams NOT enabled -> php hidden (modular filtering)"; umount /etc/dnf/modules.d; mount -t tmpfs none /etc/dnf/modules.d; $D install --assumeno php-fpm 2>&1 | tail -4; echo "rc=$?"
