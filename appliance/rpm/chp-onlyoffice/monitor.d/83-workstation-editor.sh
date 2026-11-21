#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 83-workstation-editor (ISO 0.7.0 Plan 3 Task 9; chp-onlyoffice, workstations): the editor's gates still hold.
#   G3: chp-workstation-egress.service is active (not failed), the live table inet chp_workstation_egress exists with
#       policy drop and equals the table built from the shipped files in a throwaway network namespace (as check 79
#       does for NextCloud), and the lock-down table inet chp_workstation_lockdown is ABSENT (present = the egress
#       table failed and the host is loopback-only: Wazuh 100628 says why). Stopping nftables.service on Rocky runs
#       "flush ruleset": the table is gone, and this check says so.
#   G2: chp-onlyoffice-sweep.timer is active (the hourly sweep of the CUI recovery copies).
# Like the other workstation checks (chp-base, chp-identity-client) every failing run prints its ALERT. It runs
# wherever chp-onlyoffice is installed (this file ships in it; rpm -q is the trigger, Task 9 review M3): a missing
# address file or an egress unit that is not enabled is an alert, never a silent OK.
A=${CHP_WS_ADDR:-/etc/chp/workstation-egress-addr.nft}
F=${CHP_WS_NFT:-/etc/nftables/chp-workstation-egress.nft}
U=chp-workstation-egress.service
T=chp-onlyoffice-sweep.timer
if ! rpm -q chp-onlyoffice >/dev/null 2>&1; then
  echo "OK chp-onlyoffice not installed on this host"; exit 0
fi
norm() { sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'; }
bad=0
alert() { echo "ALERT $1"; bad=$((bad + 1)); }
[ -s "$A" ] || alert "workstation egress: the address file $A is missing or empty (chp-site onlyoffice enable never ran, or it was removed): the next start of $U fails and locks the workstation down"
en=$(systemctl is-enabled "$U" 2>/dev/null); en=${en:-unknown}
[ "$en" = enabled ] || alert "workstation egress: $U is $en, not enabled: the table is not loaded at the next boot (chp-site onlyoffice enable)"
st=$(systemctl is-active "$U" 2>/dev/null); st=${st:-unknown}
[ "$st" = active ] || alert "workstation egress: $U is $st (journalctl -u $U; fix the cause, then systemctl restart $U)"
if ! live=$(nft list table inet chp_workstation_egress 2>/dev/null); then
  alert "workstation egress table chp_workstation_egress is MISSING: this workstation can reach anything (was nftables.service stopped or restarted? systemctl restart $U)"
else
  printf '%s\n' "$live" | grep -Eq 'hook output .*policy drop;' \
    || alert "workstation egress table chp_workstation_egress has no output chain with policy drop"
  errf=$(mktemp) || errf=/dev/null
  if ! exp=$(unshare -n sh -c "nft -f '$F' >/dev/null && nft list table inet chp_workstation_egress" 2>"$errf"); then
    err=$(tr '\n' ' ' < "$errf" 2>/dev/null | cut -c1-200); err=${err% }
    alert "workstation egress: the expected table could not be built from $F (unshare -n / nft failed: ${err:-no error output}), so the live table was not compared"
  elif [ "$(printf '%s\n' "$live" | norm)" != "$(printf '%s\n' "$exp" | norm)" ]; then
    alert "workstation egress table chp_workstation_egress differs from the shipped rules (edited, or the files changed and $U was not restarted)"
  fi
  [ "$errf" = /dev/null ] || rm -f "$errf"
fi
if nft list table inet chp_workstation_lockdown >/dev/null 2>&1; then
  alert "workstation is in EGRESS LOCKDOWN (table chp_workstation_lockdown loaded: the egress table failed to load; journalctl -u $U -u chp-workstation-egress-lockdown)"
fi
ts=$(systemctl is-active "$T" 2>/dev/null); ts=${ts:-unknown}
[ "$ts" = active ] || alert "workstation sweep: $T is $ts: ONLYOFFICE recovery copies (CUI) are not being removed (systemctl enable --now $T)"
# P3-D7: a lock-down or render failure that has ended is reported (one journal line, Wazuh 100635/100636) once the
# agent is connected; the egress unit tries at its start, this check every 15 minutes until it is sent. Its ALERT
# lines (a report held past 60 min, or one that could not be logged) are this check's alerts
cs=${CHP_SITE_BIN:-/usr/bin/chp-site}
if [ -x "$cs" ]; then
  rout=$("$cs" onlyoffice egress-recovered 2>&1); rrc=$?
  while IFS= read -r line; do
    case $line in ALERT\ *) alert "${line#ALERT }" ;; esac
  done <<< "$rout"
  [ "$rrc" -eq 0 ] || alert "workstation egress: chp-site onlyoffice egress-recovered failed (exit $rrc): an ended lock-down or render failure may not be reported (run it by hand to see why)"
fi
[ "$bad" -eq 0 ] && echo "OK workstation editor: egress table loaded as shipped (policy drop), no lockdown, sweep timer active"
exit 0
