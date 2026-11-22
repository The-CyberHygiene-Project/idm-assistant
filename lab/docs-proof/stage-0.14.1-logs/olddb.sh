#!/bin/bash
# Task 13e (RUNS ON AERO as itadmin), SUPPLEMENTARY to dryroot.sh: the only saved copies of REAL lab rpm databases are
# srv's and cli1's of 2026-11-19 21:52 (before repo 0.13.0 was applied: the 0.12.0 state, no editor, no chp-templates;
# /tmp/rpmdb-<n>.tgz, copied from the Mac scratchpad, not taken from the live VMs). They are two repos behind the lab, but
# they hold each host's full real OS package set. Against each, in unshare -rm: install --assumeno of the host's role
# additions + upgrade from the candidate ALONE, and rpm -U --test of that whole set on a copy of the database.
set -u
R=/data/chp-release; W=$R/tmp-o0141
rm -rf "$W"; mkdir -p "$W/cand"; cp -a $R/0.14.1/stage/. "$W/cand/"
bash $R/tools/make-repodata.sh "$W/cand" >/dev/null 2>&1 || { echo "make-repodata failed"; exit 1; }
for n in srv cli1; do mkdir -p "$W/root-$n" && tar -xzf /tmp/rpmdb-$n.tgz -C "$W/root-$n"; done
cat > "$W/ns.sh" <<'EON'
R=/data/chp-release; W=$R/tmp-o0141
D() { mkdir -p "$W/log-$1"; dnf --installroot="$W/root-$1" --releasever=9 --setopt=reposdir=/nonexistent --setopt=install_weak_deps=False \
      --setopt=cachedir="$W/cache-$1" --setopt=logdir="$W/log-$1" --nogpgcheck --noplugins --repofrompath=cand,file://$W/cand "${@:2}"; }
for spec in "srv:chp-documents nextcloud-chp chp-templates" "cli1:chp-onlyoffice chp-templates"; do
  n=${spec%%:*}; add=${spec#*:}
  echo "######## $n (real rpm db of 2026-11-19, $(rpm --dbpath "$W/root-$n/var/lib/rpm" -qa | wc -l) packages): installed ours:"
  rpm --dbpath "$W/root-$n/var/lib/rpm" -qa 'chp-*' 'nextcloud-chp' 'onlyoffice*' | sort | tr '\n' ' '; echo
  echo "== upgrade + install $add, candidate ONLY, --assumeno"
  out=$(D $n install --assumeno $add 2>&1; D $n upgrade --assumeno 2>&1)
  sed -n '/^Dependencies resolved/,/^Operation aborted/p' <<<"$out" | grep -vE '^=+$'
  set1=$(awk '/^(Installing|Upgrading|Installing dependencies):/{u=1;next} /^Transaction Summary/{u=0} u && NF>=5 {print $1}' <<<"$out" | sort -u | tr '\n' ' ')
  db=$(mktemp -d "$W/rpmdb-$n.XXXX"); cp -a "$W/root-$n/var/lib/rpm/." "$db"/
  files=$(for p in $set1; do ls "$W"/cand/$p-[0-9]*.rpm; done)
  echo "== rpm -U --test of [$set1] against a COPY of the database"; rpm --dbpath "$db" -U --test --nosignature $files 2>&1; echo "rc=$? ($(wc -w <<<"$files") packages)"
done
EON
unshare -rm bash "$W/ns.sh"
rm -rf "$W" /tmp/rpmdb-srv.tgz /tmp/rpmdb-cli1.tgz; ls -d "$W" 2>&1
