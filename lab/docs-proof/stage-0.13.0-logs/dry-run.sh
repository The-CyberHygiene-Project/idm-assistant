#!/bin/bash
# Task 11b dry-run of the UNSIGNED stage of repo 0.13.0 (temp copy + make-repodata on aero) on an iso5 host that has
# the owner-signed 0.12.0 r4 APPLIED. WITHOUT root: dnf runs as uid 0 of a private user+mount namespace (unshare -rm).
# The host's module state is COPIED into a namespace-only tmpfs; dnf history, cache and log are tmpfs too.
# --assumeno on every dnf transaction; rpm -U --test runs against a COPY of the rpm database. Nothing on the host changes.
# $1 = role: server | workstation
R=/var/tmp/s013/repo; ROLE=$1
D="dnf --setopt=reposdir=/nonexistent --repofrompath=s013,file://$R --repo=s013 --nogpgcheck --setopt=logdir=/run/dnflog"
echo "== whoami inside: $(id -u) ; role $ROLE ; host module state:"; ls -A /etc/dnf/modules.d; cat /etc/dnf/modules.d/*.module 2>/dev/null
m=$(mktemp -d /var/tmp/s013/mods.XXXX); cp -a /etc/dnf/modules.d/. "$m"/ 2>/dev/null
mount -t tmpfs none /etc/dnf/modules.d && cp -a "$m"/. /etc/dnf/modules.d/ && mount -t tmpfs none /var/lib/dnf \
  && mount -t tmpfs none /var/cache/dnf && { mkdir -p /run/dnflog 2>/dev/null || { mount -t tmpfs none /run && mkdir -p /run/dnflog; }; }
echo "== installed (ours + editor):"; rpm -q chp-site chp-base chp-integrity chp-identity-server chp-identity-client chp-documents nextcloud-chp chp-onlyoffice onlyoffice-desktopeditors chp-templates poppler-utils
echo "== 1. module list (repo s013 only)"; $D --refresh module list 2>&1
echo "== 2. upgrade --assumeno (vs the applied 0.12.0)"; $D upgrade --assumeno 2>&1; echo "rc=$?"
echo "== 3. check-update"; cu=$($D check-update 2>&1); r=$?; tail -n +2 <<<"$cu"; echo "rc=$r (100 = updates available)"
if [ "$ROLE" = server ]; then
  echo "== 4. install --assumeno nextcloud-chp chp-documents (installed: upgrade only)"; $D install --assumeno nextcloud-chp chp-documents 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo "rc=$?"
  echo "== 5. install --assumeno chp-templates"; $D install --assumeno chp-templates 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo "rc=$?"
  ups="chp-site chp-base chp-integrity chp-identity-client chp-documents nextcloud-chp"; new=""
else
  echo "== 4. install --assumeno chp-onlyoffice (the workstation editor; streams not needed)"; $D install --assumeno chp-onlyoffice 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo "rc=$?"
  echo "== 5. upgrade + install together --assumeno (apply repo, then the editor)"; $D install --assumeno chp-onlyoffice chp-site chp-base chp-integrity chp-identity-client 2>&1 | sed -n '/^Transaction Summary/,$p'; echo "rc=$?"
  echo "== 6. control: chp-documents on a workstation is not pulled by the editor"; $D repoquery --requires --resolve chp-onlyoffice 2>&1 | sort
  ups="chp-site chp-base chp-integrity chp-identity-client"
  new="chp-onlyoffice onlyoffice-desktopeditors boost-filesystem boost-system libXScrnSaver liberation-narrow-fonts xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm"
fi
echo "== 7. rpm -U --test of the upgrades${new:+ + the editor set} against a COPY of this host's rpm database"
db=$(mktemp -d /var/tmp/s013/rpmdb.XXXX); cp -a /var/lib/rpm/. "$db"/
files=$(for n in $ups $new; do ls "$R"/$n-[0-9]*.rpm; done)
rpm --dbpath "$db" -U --test --nosignature $files 2>&1; echo "rc=$? ($(wc -w <<<"$files") packages)"
