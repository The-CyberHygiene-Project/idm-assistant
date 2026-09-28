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
exit $fails
