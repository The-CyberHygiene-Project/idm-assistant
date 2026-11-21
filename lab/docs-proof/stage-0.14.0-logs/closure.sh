#!/bin/bash
# 13b (as 11b): dependency closure of the 0.14.0 stage against COPIES of srv's, cli1's and cli2's rpm databases (scratch
# installroots, no host touched; the copies are /tmp/rpmdb-<n>.tgz, streamed read-only from each host by chpadmin).
# Runs on aero as itadmin; dnf runs as uid 0 of a private user+mount namespace (unshare -rm). Without weak deps.
set -u
W=/data/chp-release/tmp-c014c
rm -rf "$W"; mkdir -p "$W/cand"
cp -a /data/chp-release/0.14.0/stage/. "$W/cand/"
bash /data/chp-release/tools/make-repodata.sh "$W/cand" >/dev/null || { echo "make-repodata failed"; exit 1; }
for n in srv cli1 cli2; do mkdir -p "$W/root-$n" && tar -xzf /tmp/rpmdb-$n.tgz -C "$W/root-$n"; done
cat > "$W/ns.sh" <<'EON'
W=/data/chp-release/tmp-c014c
D() { mkdir -p "$W/log-$1" "$W/root-$1$W/log-$1"; dnf --installroot="$W/root-$1" --releasever=9 --setopt=reposdir=/nonexistent --setopt=install_weak_deps=False \
      --setopt=cachedir="$W/cache-$1" --setopt=logdir="$W/log-$1" --nogpgcheck --noplugins \
      --repofrompath=cand,file://$W/cand --repofrompath=baseos,file:///data/lab-inputs/dvd/BaseOS \
      --repofrompath=appstream,file:///data/lab-inputs/dvd/AppStream "${@:2}"; }
for n in cli1 cli2; do
  echo "=== $n: upgrade + install chp-onlyoffice chp-templates, cand + DVD (anything from baseos/appstream = a missing extra)"; D $n install --assumeno chp-onlyoffice chp-templates 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo rc=$?
  echo "=== $n: upgrade, cand ONLY"; D $n --repo=cand upgrade --assumeno 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo rc=$?
done
echo "=== srv: upgrade + install nextcloud-chp chp-documents chp-templates, cand + DVD"; D srv install --assumeno nextcloud-chp chp-documents chp-templates 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo rc=$?
echo "=== srv: upgrade, cand ONLY"; D srv --repo=cand upgrade --assumeno 2>&1 | sed -n '/^Dependencies resolved/,$p'; echo rc=$?
EON
unshare -rm bash "$W/ns.sh"
rm -rf "$W" /tmp/rpmdb-srv.tgz /tmp/rpmdb-cli1.tgz /tmp/rpmdb-cli2.tgz
