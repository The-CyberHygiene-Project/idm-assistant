#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 76-disk-space (spec §4): every XFS file system below 85% full. monitor.sh re-sends every ALERT line on every run,
# so this check keeps its own state: one line per alerted mount ("<mount> <epoch>"); it alerts when a mount newly
# crosses the limit, or is still over it 24 h after its last alert. A mount back under the limit is forgotten.
# The Wazuh data directory's file system belongs to check 72 (only when the security add-on is enabled).
LIMIT=85
REPEAT=86400
sd=${CHP_STATE_DIR:-/var/lib/chp/monitor}
sf=$sd/76-disk.state
now=${CHP_NOW:-$(date +%s)}
mkdir -p "$sd" 2>/dev/null && chmod 0700 "$sd" 2>/dev/null
new=""
emitted=0
# due KEY: succeed when KEY should alert now; either way carry its alert time into the new state.
# State lines are "<mount> <epoch>"; the mount may contain spaces, so the epoch is the LAST field.
# A missing, non-numeric or future (clock stepped back) time counts as due.
due() {
  local t
  t=$(awk -v k="$1" '{ e = $NF; sub(/ [^ ]*$/, ""); if ($0 == k) { print e; exit } }' "$sf" 2>/dev/null)
  case $t in ''|*[!0-9]*) new="$new$1 $now"$'\n'; return 0 ;; esac
  if [ "$now" -lt "$t" ] || [ $((now - t)) -ge $REPEAT ]; then new="$new$1 $now"$'\n'; return 0; fi
  new="$new$1 $t"$'\n'; return 1
}
emit() { echo "ALERT $1"; emitted=$((emitted + 1)); }

skip=""
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}
if [ -f "$C" ]; then
  d=$(sed -n 's/^DATA_DIR=//p' "$C" | head -1); d=${d:-/var/ossec}
  skip=$(df --output=target "$d" 2>/dev/null | tail -1)
fi

free=""
if v=$(LC_ALL=C vgs --noheadings --units g --nosuffix -o vg_free chp 2>/dev/null) && [ -n "$(echo $v)" ]; then
  g=$(echo $v | cut -d. -f1 | tr -dc '0-9')
  [ -n "$g" ] && free="; grow with lvextend -r; $g GB free in chp"
fi

# target is the LAST column so a mount point with spaces survives; a non-zero df exit with some output is partial.
out=$(df --output=source,fstype,pcent,target -x tmpfs -x devtmpfs 2>/dev/null); rc=$?
n=0
while read -r src fstype pct target; do
  n=$((n + 1)); [ "$n" -eq 1 ] && continue
  [ "$fstype" = xfs ] || continue
  [ "$target" = "$skip" ] && continue
  pct=$(echo "$pct" | tr -dc '0-9')
  [ -n "$pct" ] && [ "$pct" -ge $LIMIT ] || continue
  hint=""
  case $src in /dev/mapper/*) hint=$free ;; esac
  if due "$target"; then emit "$target is $pct% full (limit $LIMIT%)$hint"; fi
done <<< "$out"
if [ "$rc" -ne 0 ]; then
  if [ "$n" -le 1 ]; then
    # nothing readable: keep the other mounts' state
    new=$(awk '{ l = $0; sub(/ [^ ]*$/, "", l); if (l != "_df") print }' "$sf" 2>/dev/null)
    [ -n "$new" ] && new="$new"$'\n'
  fi
  if due _df; then emit "cannot read disk use (df reported an error)"; fi
fi

mkdir -p "$sd" 2>/dev/null
printf '%s' "$new" > "$sf.tmp" 2>/dev/null && mv "$sf.tmp" "$sf"
[ "$emitted" -eq 0 ] && echo "OK no XFS file system at or above $LIMIT% (or already alerted)"
exit 0
