#!/bin/bash
# Task 13b dry-run of the UNSIGNED stage of repo 0.14.0 (temp copy + make-repodata on aero) on an iso5 host, as in 11b.
# WITHOUT root: dnf runs as uid 0 of a private user+mount namespace (unshare -rm). The host's module state is COPIED into
# a namespace-only tmpfs; dnf history, cache and log are tmpfs too. --assumeno on every dnf transaction; rpm -U --test
# runs against a COPY of the rpm database. Nothing on the host changes. $1 = role: server | workstation
R=/var/tmp/s014/repo; ROLE=$1
D="dnf --setopt=reposdir=/nonexistent --repofrompath=s014,file://$R --repo=s014 --nogpgcheck --setopt=logdir=/run/dnflog"
echo "== whoami inside: $(id -u) ; role $ROLE ; host module state:"; ls -A /etc/dnf/modules.d; cat /etc/dnf/modules.d/*.module 2>/dev/null
m=$(mktemp -d /var/tmp/s014/mods.XXXX); cp -a /etc/dnf/modules.d/. "$m"/ 2>/dev/null
mount -t tmpfs none /etc/dnf/modules.d && cp -a "$m"/. /etc/dnf/modules.d/ && mount -t tmpfs none /var/lib/dnf \
  && mount -t tmpfs none /var/cache/dnf && { mkdir -p /run/dnflog 2>/dev/null || { mount -t tmpfs none /run && mkdir -p /run/dnflog; }; }
echo "== installed (ours + editor):"; rpm -q chp-site chp-base chp-integrity chp-identity-server chp-identity-client chp-documents nextcloud-chp chp-onlyoffice onlyoffice-desktopeditors chp-templates poppler-utils
echo "== 1. module list (repo s014 only)"; $D --refresh module list 2>&1
echo "== 2. upgrade --assumeno (vs what is applied)"; $D upgrade --assumeno 2>&1; echo "rc=$?"
echo "== 3. check-update"; cu=$($D check-update 2>&1); r=$?; tail -n +2 <<<"$cu"; echo "rc=$r (100 = updates available)"
ups=$(awk 'NF==3 && $3=="s014" {sub(/\.[^.]*$/,"",$1); print $1}' <<<"$cu" | sort -u | tr '\n' ' ')
new=""
if [ "$ROLE" = server ]; then
  echo "== 4. install --assumeno nextcloud-chp chp-documents"; $D install --assumeno nextcloud-chp chp-documents 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo "rc=$?"
  echo "== 5. install --assumeno chp-templates"; $D install --assumeno chp-templates 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo "rc=$?"
else
  echo "== 4. install --assumeno chp-onlyoffice (the workstation editor)"; $D install --assumeno chp-onlyoffice 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo "rc=$?"
  echo "== 5. upgrade + editor together --assumeno"; $D install --assumeno chp-onlyoffice $ups 2>&1 | sed -n '/^Transaction Summary/,$p'; echo "rc=$?"
  echo "== 6. control: what chp-onlyoffice requires (resolved)"; $D repoquery --requires --resolve chp-onlyoffice 2>&1 | sort
  for n in chp-onlyoffice onlyoffice-desktopeditors chp-templates boost-filesystem boost-system libXScrnSaver liberation-narrow-fonts xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm; do
    rpm -q "$n" >/dev/null 2>&1 || new="$new $n"; done
fi
echo "== 7. rpm -U --test of the upgrades [$ups]${new:+ + not-installed editor set [$new]} against a COPY of this host's rpm database"
db=$(mktemp -d /var/tmp/s014/rpmdb.XXXX); cp -a /var/lib/rpm/. "$db"/
files=$(for n in $ups $new; do ls "$R"/$n-[0-9]*.rpm; done)
rpm --dbpath "$db" -U --test --nosignature $files 2>&1; echo "rc=$? ($(wc -w <<<"$files") packages)"
