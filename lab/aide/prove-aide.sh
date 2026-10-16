#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# prove-aide.sh STAGE (RUNS ON THE MAC): core 0.2.0 Plan A proofs on the iso5 golden hosts (srv1 = iso5-srv,
# client2 = iso5-cli2; chpadmin with the LAB ADAPTER's sudo). Spec §9: AIDE must CATCH planted changes.
#   upgrade   revert to golden; unpack repo $REPO (default 0.7.2); NOHOOK=1 skips the test ALERT_HOOK; dnf upgrade chp-site + install chp-integrity; baseline package-install with the stick plugged in (its hash pinned BEFORE the baseline)
#   pin       62 alerts before; aide-pin with the iso5 stick attached; 62 quiet; stick has aide/<host>.txt
#   catch     plant 3 changes on srv1; run the check; 60 alerts; ALERT_HOOK received it
#   accept    unlisted name refused; delegate accepts (BASELINE_DELEGATES added to /etc/chp/site.conf); audit; quiet
#   verify    aide-verify-pin MATCH; replace the database by hand -> DB_MATCH=no alert and MISMATCH
#   grouping  dnf reinstall chp-site, check, accept summary lists it under "explained"
#   stale     stop the timer -> alert; an old last-result -> alert
#   selinux   0 AVC since the upgrade; fapolicyd denials 0
#   revert    both hosts back to golden
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; F="$top/lab/iso5/ssh_config"
STICK=/data/libvirt/images/iso5-stick.img; REPO=${REPO:-0.7.2}; fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: ${2:-}"; fails=1; }
check() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1" "got '$2', want '$3'"; fi; }
A() { ssh -n -o BatchMode=yes aero "$@" 2>/dev/null; }
H() { local h=$1; shift; ssh -F "$F" -n -o ConnectTimeout=10 "$h" "$@" 2>/dev/null; }
vm() { [[ $1 == srv1 ]] && echo iso5-srv || echo iso5-cli2; }
mon() { H "$1" "sudo bash -c 'for c in /usr/lib/chp/monitor.d/6*-aide-*.sh; do \$c; done'"; }
runcheck() { H "$1" 'sudo systemctl start chp-aide-check.service; sudo cat /var/lib/chp/aide/last-result'; }
attach() { A "sudo virsh attach-disk $(vm "$1") $STICK sdz --targetbus usb --type disk --live >/dev/null"; sleep 5; }
detach() { A "sudo virsh detach-disk $(vm "$1") sdz --live >/dev/null"; sleep 3; }

case ${1:-} in
  upgrade)
    "$top/lab/iso5/reset.sh" >/dev/null || { fail "reset to golden"; exit 1; }
    for h in srv1 client2; do
      H $h 'sudo rm -rf /var/lib/chp/repo/*'
      A "tar -C /data/lab-inputs/chp/$REPO -cf - ." | ssh -F "$F" "$h" 'sudo tar -x -C /var/lib/chp/repo -f -'     # the signed repo, as a site would unpack the tarball
      attach $h     # the stick is in during the install, as on a site: aide-baseline pins its hash first (quiet check 2026-10-16)
      out=$(H $h "sudo dnf -y -q --enablerepo=chp upgrade chp-site && sudo dnf -y -q --enablerepo=chp install chp-integrity && echo INSTALLED")
      [[ $out == *INSTALLED* ]] && pass "$h: chp-site + chp-integrity from the signed repo $REPO" || fail "$h install" "$out"
      check "$h: aide.conf is ours" "$(H $h 'sudo cmp -s /etc/aide.conf /usr/share/chp-integrity/aide.conf && echo same')" "same"
      s=""; for _ in $(seq 180); do s=$(H $h 'sudo sed -n s/^BUILT_BY=//p /var/lib/chp/aide/baseline 2>/dev/null'); [[ -n $s ]] && break; sleep 15; done
      detach $h
      check "$h: baseline built at package install" "$s" "package-install"
      check "$h: stick hash pinned before the baseline" "$(H $h 'sudo bash -c "[ -s /etc/chp/site-stick.hash ] && [ /etc/chp/site-stick.hash -ot /var/lib/aide/aide.db.gz ] && echo yes"')" "yes"
      check "$h: baseline built with our aide.conf (conf older than init log)" "$(H $h 'sudo bash -c "[ /etc/aide.conf -ot \$(ls -t /var/log/aide/init-*.log | head -1) ] && echo yes"')" "yes"
      check "$h: daily timer active" "$(H $h 'systemctl is-active chp-aide-check.timer')" "active"
      check "$h: database 0600" "$(H $h 'sudo stat -c %a /var/lib/aide/aide.db.gz')" "600"
      [[ -n ${NOHOOK:-} ]] && continue     # quiet run (Task 13): no harness change after the baseline
      H $h "sudo sed -i 's#^ALERT_HOOK=.*#ALERT_HOOK=/usr/local/sbin/chp-test-hook#' /etc/chp/site.conf"     # replace: a 2nd ALERT_HOOK line is a parse error
      scp -q -F "$F" "$here/hook.sh" $h:/tmp/hook.sh && H $h 'sudo install -m 0755 /tmp/hook.sh /usr/local/sbin/chp-test-hook'
    done ;;
  pin)
    for h in srv1 client2; do
      [[ $(mon $h) == *"ALERT AIDE baseline not pinned"* ]] && pass "$h: 62 alerts before the pin" || fail "$h 62 before"
      attach $h; out=$(H $h 'sudo chp-site aide-pin'); detach $h
      [[ $out == pinned:* ]] && pass "$h: aide-pin ($out)" || fail "$h aide-pin" "$out"
      [[ $(mon $h) != *"not pinned"* ]] && pass "$h: 62 quiet after the pin" || fail "$h 62 after"
      check "$h: record on the stick" "$(A "sudo bash /tmp/iso2/stick.sh has $STICK aide/$(vm $h).txt && echo yes")" "yes"
    done ;;
  catch)
    H srv1 'sudo cp /usr/bin/true /usr/bin/chp-planted && echo "# planted" | sudo tee -a /etc/kanidm/config >/dev/null && echo "# planted" | sudo tee /etc/ssh/sshd_config.d/50-planted.conf >/dev/null'
    r=$(runcheck srv1)
    grep -qx 'EXIT=[1-7]' <<<"$r" && pass "srv1: check reports changes ($(grep -o 'ADDED=[0-9]*\|CHANGED=[0-9]*' <<<"$r" | tr '\n' ' '))" || fail "srv1 check" "$r"
    rep=$(H srv1 'sudo bash -c "cat \$(sed -n s/^REPORT=//p /var/lib/chp/aide/last-result)"')
    for p in /usr/bin/chp-planted /etc/kanidm/config /etc/ssh/sshd_config.d/50-planted.conf; do
      [[ $rep == *"$p"* ]] && pass "srv1: report names $p" || fail "srv1 report $p"; done
    [[ $(mon srv1) == *"ALERT AIDE found changes"* ]] && pass "srv1: 60 alerts" || fail "srv1 60"
    H srv1 'sudo systemctl start chp-monitor.service'; sleep 3
    [[ $(H srv1 'sudo cat /var/log/chp-test-hook.log') == *"AIDE found changes"* ]] && pass "srv1: ALERT_HOOK received the AIDE alert" || fail "srv1 hook" ;;
  accept)
    out=$(H srv1 'sudo chp-site aide-accept --approver "Somebody Else" --reason "this should be refused" --yes 2>&1'); sha0=$(H srv1 'sudo sha512sum /var/lib/aide/aide.db.gz')
    [[ $out == *"is not the ISSO"* ]] && pass "unlisted approver refused" || fail "unlisted" "$out"
    H srv1 'echo "BASELINE_DELEGATES=Deputy ISSO" | sudo tee -a /etc/chp/site.conf >/dev/null'
    attach srv1
    out=$(H srv1 'sudo chp-site aide-accept --approver "Deputy ISSO" --reason "lab proof: planted test changes" --yes 2>&1'); detach srv1
    [[ $out == *"NOT explained"* && $out == *"/usr/bin/chp-planted"* && $out == *"accepted by Deputy ISSO"* && $out == *"pinned: aide/"* ]] \
      && pass "delegate accepted; summary listed the planted files; pinned" || fail "accept" "$out"
    [[ $(H srv1 'sudo sha512sum /var/lib/aide/aide.db.gz') != "$sha0" ]] && pass "new database installed" || fail "db unchanged"
    au=$(H srv1 'sudo ausearch -m USER -ts today --input-logs </dev/null 2>/dev/null | grep -o "chp-site aide-accept[.a-z]* " | sort | uniq -c | tr -s " " | tr "\n" ";"')
    [[ $au == *"aide-accept ;"* && $au == *"aide-accept.done ;"* ]] && pass "audit: before + after records ($au)" || fail "audit" "$au"     # -ts today: check + rebuild take ~40 min
    [[ $(mon srv1) == *"OK AIDE: no changes"* && $(mon srv1) != *ALERT* ]] && pass "monitor quiet after accept" || fail "after accept" "$(mon srv1)" ;;
  verify)
    attach srv1; out=$(H srv1 'sudo chp-site aide-verify-pin; echo rc=$?'); detach srv1
    [[ $out == MATCH* && $out == *rc=0* ]] && pass "verify-pin MATCH" || fail "verify MATCH" "$out"
    H srv1 'sudo cp /var/lib/aide/aide.db.gz /root/db.keep && echo x | sudo tee -a /var/lib/aide/aide.db.gz >/dev/null'
    r=$(runcheck srv1); [[ $r == *DB_MATCH=no* ]] && pass "replaced database: DB_MATCH=no" || fail "db match" "$r"
    [[ $(mon srv1) == *"does not match the recorded baseline"* ]] && pass "60 alerts on the replaced database" || fail "60 mismatch"
    attach srv1; out=$(H srv1 'sudo chp-site aide-verify-pin; echo rc=$?'); detach srv1
    [[ $out == MISMATCH* && $out == *rc=1* ]] && pass "verify-pin MISMATCH" || fail "verify MISMATCH" "$out"
    out=$(H srv1 'sudo chp-site aide-accept --approver "D. Shannon" --reason "must be refused: replaced db" --yes 2>&1')
    [[ $out == *"investigate"* ]] && pass "accept refused on a replaced database" || fail "accept mismatch" "$out"
    H srv1 'sudo cp /root/db.keep /var/lib/aide/aide.db.gz && sudo rm /root/db.keep'; runcheck srv1 >/dev/null ;;
  grouping)
    H srv1 'sudo dnf -y -q --enablerepo=chp reinstall chp-site'
    out=$(ssh -F "$F" srv1 'sudo chp-site aide-accept --approver "D. Shannon" --reason "lab proof: grouping after reinstall" 2>&1' <<<"NO")     # no -n: the prompt reads NO
    [[ $out == *"Explained by signed package updates"* && $out == *"chp-site:"* ]] && pass "reinstalled chp-site listed as explained" || fail "grouping" "$out"
    [[ $out == *"not accepted"* ]] && pass "declined: nothing changed" || fail "decline" "$out" ;;
  stale)
    H client2 'sudo systemctl stop chp-aide-check.timer'
    [[ $(mon client2) == *"timer is not active"* ]] && pass "timer stopped -> alert" || fail "timer alert"
    H client2 'sudo systemctl start chp-aide-check.timer && sudo systemctl start chp-aide-check.service && sudo sed -i "s/^EPOCH=.*/EPOCH=1000/" /var/lib/chp/aide/last-result'
    [[ $(mon client2) == *"no completed check for"* ]] && pass "old result -> stale alert" || fail "stale alert" ;;
  selinux)
    for h in srv1 client2; do
      av=$(H $h 'sudo ausearch -m AVC,USER_AVC -ts today --input-logs </dev/null 2>/dev/null | grep "type=AVC"')
      check "$h: 0 AVC denials from AIDE, its wrapper or chp-site" "$(grep -cE 'comm="(aide|aide-check|aide-baseline|chp-site|python3|bash)"' <<<"$av")" "0"
      other=$(grep -vE 'comm="(aide|aide-check|aide-baseline|chp-site|python3|bash)"' <<<"$av" | grep -c . || true)
      [[ $other == 0 ]] || echo "FINDING $h: $other other AVC(s), not from AIDE: $(grep -o 'comm="[^"]*".*tcontext=[^ ]*' <<<"$av" | sed -E 's/ (name|dev|ino|scontext)=[^ ]*//g' | sort -u | tr '\n' ';') (requirements row 49)"
      check "$h: 0 fapolicyd denials" "$(H $h 'sudo journalctl -u fapolicyd --since today --no-pager | grep -c "dec=deny"')" "0"
      H $h 'sudo bash -c "grep -ho \"run time: [0-9ms ]*\" /var/log/aide/check-*.log | tail -1"' | sed "s/^/INFO $h check duration: /"     # log dir is 0700: glob as root
    done ;;
  revert)
    A "sudo virsh snapshot-revert iso5-srv golden --running && sudo virsh snapshot-revert iso5-cli2 golden --running" && pass "reverted to golden" || fail "revert" ;;
  *) echo "usage: prove-aide.sh upgrade|pin|catch|accept|verify|grouping|stale|selinux|revert"; exit 2 ;;
esac
exit $fails
