#!/bin/bash
# Task 13e (RUNS ON AERO as itadmin): unsigned dry-run of the 0.14.1 stage WITHOUT the live lab VMs (a lab worker runs the
# regression gate on them; no saved srv/cli rpm databases exist on aero). Instead, each host's 0.14.0 package state is
# rebuilt as a scratch rpm database: dnf --installroot, tsflags=justdb (database only, no files, no scriptlets), the role's
# packages from the SIGNED 0.14.0 repo + the Rocky 9.8 DVD, without weak deps. Host sets are taken from the 13c logs
# (logs/191 and 215): srv = server role + documents + chp-templates (kept in 13c) + chp-security; cli1 = cli2 = workstation
# role + editor + chp-templates + chp-security. dnf runs as uid 0 of a private user+mount namespace (unshare -rm).
# Then, against each rebuilt database: upgrade from the candidate ALONE, the role set from candidate + DVD (anything from
# baseos/appstream = a missing extra), rpm -U --test of the upgrade set on a COPY of the database; and a fresh install of
# the role set from candidate + DVD into an empty root (the ISO path). Everything is --assumeno except the justdb builds of
# the 0.14.0 state, which only write into the scratch roots. Nothing outside $W changes.
set -u
R=/data/chp-release; W=$R/tmp-d0141
rm -rf "$W"; mkdir -p "$W/cand"
cp -a $R/0.14.1/stage/. "$W/cand/"
bash $R/tools/make-repodata.sh "$W/cand" > "$W/make-repodata.log" 2>&1 || { echo "make-repodata failed"; cat "$W/make-repodata.log"; exit 1; }
cat > "$W/ns.sh" <<'EON'
R=/data/chp-release; W=$R/tmp-d0141
SRV="chp-site chp-base chp-integrity chp-identity-server chp-identity-client chp-documents nextcloud-chp chp-templates chp-security"
WS="chp-site chp-base chp-integrity chp-identity-client chp-onlyoffice chp-templates chp-security"
# D <root> <repos, comma-separated> <dnf args>: ONLY the named repos are defined (dnf's --repo does not filter
# --repofrompath repos, so each call defines exactly the repos it may use)
declare -A U=([r0140]=file://$R/0.14.0/repo [cand]=file://$W/cand [baseos]=file:///data/lab-inputs/dvd/BaseOS [appstream]=file:///data/lab-inputs/dvd/AppStream)
D() { mkdir -p "$W/root-$1" "$W/log-$1"; local a=() r; for r in ${2//,/ }; do a+=(--repofrompath=$r,${U[$r]}); done
      dnf --installroot="$W/root-$1" --releasever=9 --setopt=reposdir=/nonexistent \
      --setopt=install_weak_deps=False --setopt=cachedir="$W/cache-$1" --setopt=logdir="$W/log-$1" --nogpgcheck --noplugins \
      --setopt=tsflags=justdb "${a[@]}" "${@:3}"; }
OURS="chp-site chp-base chp-integrity chp-identity-server chp-identity-client chp-documents nextcloud-chp chp-onlyoffice onlyoffice-desktopeditors chp-templates chp-security poppler-utils"
for spec in srv:SRV:server cli1:WS:workstation cli2:WS:workstation; do
  IFS=: read -r n set role <<<"$spec"; P=${!set}
  echo "######## $n ($role): rebuild the 0.14.0 state (justdb) from the signed 0.14.0 repo + DVD: $P"
  [ $role = server ] && { D $n r0140,baseos,appstream -y module enable php:8.3 postgresql:16 2>&1 | tail -2; }
  mkdir -p "$W/log-$n"; D $n r0140,baseos,appstream -y install $P > "$W/log-$n/build.out" 2>&1; echo "justdb build rc=$? ($(rpm --root "$W/root-$n" -qa | wc -l) packages in the scratch db)"
  echo "== installed (ours + editor) in the rebuilt db:"; rpm --root "$W/root-$n" -q $OURS
  echo "== module state:"; cat "$W/root-$n"/etc/dnf/modules.d/*.module 2>/dev/null | grep -E '^\[|^stream|^state'
  echo "== 1. upgrade --assumeno, candidate ONLY"; out=$(D $n cand upgrade --assumeno 2>&1); sed -n '/^Dependencies resolved/,$p' <<<"$out"
  ups=$(awk '/^Upgrading:/{u=1;next} /^[A-Z][a-z]+.*:$/{u=0} /^Transaction Summary/{u=0} u && NF>=4 {print $1}' <<<"$out" | sort -u | tr '\n' ' ')
  echo "upgrade set: [$ups]"
  echo "== 2. install --assumeno the role set, candidate + DVD (anything from baseos/appstream = a missing extra)"
  D $n cand,baseos,appstream install --assumeno $P 2>&1 | sed -n '/^Dependencies resolved/,$p'
  echo "== 3. rpm -U --test of [$ups] against a COPY of the rebuilt database"
  db=$(mktemp -d "$W/rpmdb-$n.XXXX"); cp -a "$W/root-$n/var/lib/rpm/." "$db"/
  files=$(for p in $ups; do ls "$W"/cand/$p-[0-9]*.rpm; done)
  rpm --dbpath "$db" -U --test --nosignature $files 2>&1; echo "rc=$? ($(wc -w <<<"$files") packages)"
done
for spec in fresh-srv:SRV:server fresh-ws:WS:workstation; do
  IFS=: read -r n set role <<<"$spec"; P=${!set}
  echo "######## $n: fresh install of the $role set into an EMPTY root, candidate + DVD, --assumeno"
  [ $role = server ] && { D $n cand,baseos,appstream -y module enable php:8.3 postgresql:16 2>&1 | tail -1; }
  out=$(D $n cand,baseos,appstream install --assumeno $P 2>&1); r=$?
  grep -E '^ (chp-|nextcloud|onlyoffice|poppler|kanidm|step-|idm-collect|google-auth|wazuh|suricata|yara|aide)' <<<"$out" | awk '{print "  "$1, $3, $4}'
  sed -n '/^Transaction Summary/,$p' <<<"$out"; grep -iE 'nothing provides|conflict|problem' <<<"$out"
  echo "rc=$r; lines from repo cand: $(grep -cE '[[:space:]]cand[[:space:]]' <<<"$out"), from baseos/appstream: $(grep -cE '[[:space:]](baseos|appstream)[[:space:]]' <<<"$out")"
done
EON
unshare -rm bash "$W/ns.sh"
rm -rf "$W"; ls -d "$W" 2>&1
