#!/bin/bash
# 11b: dependency closure of the 0.13.0 candidate against COPIES of srv's and cli1's rpm databases (scratch installroots,
# no host touched). Runs on aero as itadmin; dnf runs as uid 0 of a private user+mount namespace (unshare -rm).
set -u
W=/data/chp-release/tmp-c013
rm -rf "$W"; mkdir -p "$W/cand"
cp -a /data/chp-release/0.12.0/stage/*.rpm "$W/cand/"
for f in chp-site-0.14.0-7 chp-documents-0.1.0-8 chp-base-0.1.0-13 chp-integrity-0.1.7-2 chp-identity-client-0.2.4-2 \
         chp-onlyoffice-0.1.0-3 nextcloud-chp-35.0.3-6; do cp -a /data/chp-release/built/$f.chp.el9.noarch.rpm "$W/cand/"; done
cp -a /data/lab-inputs/rpms/onlyoffice-desktopeditors-10.0.0-169.el7.x86_64.rpm "$W/cand/"
cp -a /data/chp-release/0.12.0/stage/modules.yaml "$W/cand/"
bash /data/chp-release/tools/make-repodata.sh "$W/cand" >/dev/null || { echo "make-repodata failed"; exit 1; }
for n in srv cli1; do mkdir -p "$W/root-$n" && tar -xzf /tmp/rpmdb-$n.tgz -C "$W/root-$n"; done
cat > "$W/ns.sh" <<'EOF'
W=/data/chp-release/tmp-c013
D() { mkdir -p "$W/log-$1" "$W/root-$1$W/log-$1"; dnf --installroot="$W/root-$1" --releasever=9 --setopt=reposdir=/nonexistent --setopt=install_weak_deps=False \
      --setopt=cachedir="$W/cache-$1" --setopt=logdir="$W/log-$1" --nogpgcheck --noplugins \
      --repofrompath=cand,file://$W/cand --repofrompath=baseos,file:///data/lab-inputs/dvd/BaseOS \
      --repofrompath=appstream,file:///data/lab-inputs/dvd/AppStream "${@:2}"; }
echo "=== cli1: install chp-onlyoffice (closure vs cand + DVD, no weak deps)"; D cli1 install --assumeno chp-onlyoffice 2>&1; echo rc=$?
echo "=== cli1: same, cand ONLY"; D cli1 --repo=cand install --assumeno chp-onlyoffice 2>&1 | tail -25; echo rc=$?
echo "=== srv: upgrade + install nextcloud-chp chp-documents, cand + DVD"; D srv install --assumeno nextcloud-chp chp-documents chp-site chp-base chp-integrity chp-identity-client 2>&1; echo rc=$?
EOF
unshare -rm bash "$W/ns.sh"
