#!/bin/bash
# Task 13e (RUNS ON AERO as itadmin): stage repo 0.14.1 = the 0.14.0 stage with exactly 7 RPMs replaced by the new builds
# in built/. The 65 other RPMs and modules.yaml are copied unchanged and must hash the same as in the signed 0.14.0 stage.
# 0.13.0 and 0.14.0 (repo + stage) are hashed before and after: they must not change.
set -Eeuo pipefail
R=/data/chp-release; S0=$R/0.14.0/stage; S=$R/0.14.1/stage; B=$R/built
OLD="chp-site-0.14.0-10 chp-documents-0.1.0-10 chp-identity-client-0.2.4-4 chp-identity-server-0.1.2-6 chp-onlyoffice-0.1.0-5 chp-templates-1.4.0-2 nextcloud-chp-35.0.3-7"
NEW="chp-site-0.14.0-12 chp-documents-0.1.0-13 chp-identity-client-0.2.4-6 chp-identity-server-0.1.2-8 chp-onlyoffice-0.1.0-7 chp-templates-1.4.0-3 nextcloud-chp-35.0.3-8"
[[ -e $R/0.14.1 ]] && { echo "refusing: $R/0.14.1 exists"; exit 1; }
snap() { for d in 0.13.0/repo 0.13.0/stage 0.14.0/repo 0.14.0/stage; do (cd "$R/$d" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | sed "s|-|$d|"); done
         stat -c '%y %n' "$R/0.13.0/repo" "$R/0.14.0/repo"; }
echo "== before (0.13.0 / 0.14.0 trees)"; snap | tee /tmp/s0141-before.txt
mkdir -p "$S"; cp -a "$S0"/. "$S"/
for n in $OLD; do rm -v "$S/$n.chp.el9.noarch.rpm"; done
for n in $NEW; do install -m 0644 "$B/$n.chp.el9.noarch.rpm" "$S/"; echo "added $n"; done
(cd "$S" && sha256sum *) > /tmp/s0141-stage-sha256.txt
(cd "$S0" && sha256sum *) > /tmp/s0140-stage-sha256.txt
echo "== counts: rpms $(ls "$S"/*.rpm | wc -l), files $(ls "$S" | wc -l), size $(du -sh "$S" | cut -f1)"
echo "== diff 0.14.0 stage -> 0.14.1 stage (sha256 lists)"; diff /tmp/s0140-stage-sha256.txt /tmp/s0141-stage-sha256.txt || true
same=0; bad=0
while read -r h f; do o=$(awk -v f="$f" '$2==f{print $1}' /tmp/s0140-stage-sha256.txt)
  if [[ -n $o ]]; then [[ $o == "$h" ]] && same=$((same+1)) || { bad=$((bad+1)); echo "DIFFERENT: $f"; }; fi
done < /tmp/s0141-stage-sha256.txt
echo "== reused files identical to the signed 0.14.0 stage: $same (expect 66 = 65 RPMs + modules.yaml), different: $bad"
echo "== stage-sha256.txt digest: $(sha256sum /tmp/s0141-stage-sha256.txt | cut -c1-64)"
echo "== after (0.13.0 / 0.14.0 trees)"; snap | tee /tmp/s0141-after.txt
cmp /tmp/s0141-before.txt /tmp/s0141-after.txt && echo "0.13.0 and 0.14.0 unchanged"
