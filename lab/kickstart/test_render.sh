#!/usr/bin/env bash
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0; TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
for n in srv1 client2; do
  SSH_PUBKEY="ecdsa-sha2-nistp384 AAAA test" OUT=$TMPD/test-$n.ks bash "$here/render.sh" $n >/dev/null
  t "$n renders" "[[ -s $TMPD/test-$n.ks ]]"
  t "$n has no unreplaced placeholders" "! grep -q '@[A-Z_]*@' $TMPD/test-$n.ks"
  t "$n validates (RHEL9)" "uvx --from pykickstart ksvalidator -v RHEL9 $TMPD/test-$n.ks >/dev/null"
  t "$n keeps FIPS + CUI" "grep -q 'fips=1' $TMPD/test-$n.ks && grep -q content_profile_cui $TMPD/test-$n.ks"
  t "$n has no compilers" "! grep -qxE '(gcc|clang|golang|cmake|rpm-build)' $TMPD/test-$n.ks"
done
t "srv1 IP .10 + bind" "grep -q 'ip=192.168.100.10 ' $TMPD/test-srv1.ks && grep -qx bind $TMPD/test-srv1.ks"
t "client2 IP .13 + resolver srv1" "grep -q 'ip=192.168.100.13 ' $TMPD/test-client2.ks && grep -q 'nameserver=192.168.100.10' $TMPD/test-client2.ks"
t "unknown host is rejected" "! OUT=$TMPD/x.ks bash '$here/render.sh' nosuch 2>/dev/null"
C1="$TMPD/test-client1.ks"
SSH_PUBKEY="ecdsa-sha2-nistp384 AAAA test" LUKSPASS="test-only-passphrase-not-real" OUT="$C1" bash "$here/render.sh" client1 >/dev/null
t "client1 renders" "[[ -s $C1 ]]"
t "client1 has no unreplaced placeholders" "! grep -q '@[A-Z_]*@' $C1"
t "client1 validates (RHEL9)" "uvx --from pykickstart ksvalidator -v RHEL9 $C1 >/dev/null"
t "client1 FIPS" "grep -q 'fips=1' $C1"
t "client1 has NO oscap addon (the kit applies the baseline)" "! grep -q com_redhat_oscap $C1"
t "client1 is Server with GUI" "grep -qx '@^graphical-server-environment' $C1"
for m in /boot/efi /boot / /home /tmp /var /var/tmp /var/log /var/log/audit; do
  t "client1 has mount $m" "grep -qE '^(part|logvol) +$m +' $C1"
done
t "client1 PV is LUKS2-encrypted" "grep -qE '^part pv\.01 .*--encrypted .*--luks-version=luks2' $C1"
t "client1 swap is a logical volume (inside LUKS)" "grep -qE '^logvol swap ' $C1 && ! grep -qE '^part swap' $C1"
t "client1 IP .12" "grep -q 'ip=192.168.100.12 ' $C1"
t "client1 does NOT bind in %post (installer PCR 7 differs; bind on first real boot)" "! grep -q 'clevis luks bind' $C1"
t "client1 installs clevis-dracut for boot-time TPM unlock" "grep -qx clevis-dracut $C1"
rm -f "$C1"
exit $fails
