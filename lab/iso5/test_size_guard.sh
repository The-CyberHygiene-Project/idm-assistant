#!/usr/bin/env bash
# test_size_guard.sh: runs size-guard.sh against stub du/virsh/qemu-img and a temp image dir. Safe on a Mac
# (bash 3.2): no VM, no root, nothing real is touched. Cases: trip, cannot-measure x3, destroy failure, no image.
set -u
here=$(cd "$(dirname "$0")" && pwd); guard=$here/size-guard.sh
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/img" "$T/beat"
cat > "$T/bin/du" <<'S'
#!/bin/sh
cat "$STUB_DIR/du.out"; [ -f "$STUB_DIR/du.fail" ] && exit 1; exit 0
S
cat > "$T/bin/virsh" <<'S'
#!/bin/sh
case $1 in
  destroy) echo destroy >> "$STUB_DIR/virsh.log" ;;
  domstate) cat "$STUB_DIR/state" ;;
esac
exit 0
S
cat > "$T/bin/qemu-img" <<'S'
#!/bin/sh
echo "stub snapshot list"
S
printf '#!/bin/sh\nexit 0\n' > "$T/bin/sleep"
chmod +x "$T/bin/"*
export STUB_DIR=$T IMG_DIR=$T/img BEAT_DIR=$T/beat POLL_S=0 SIZE_GUARD_TEST=1
pass=0 failn=0
ok() { echo "PASS $1"; pass=$((pass + 1)); }
no() { echo "FAIL $1 ($2)"; failn=$((failn + 1)); }
reset() { rm -f "$T"/virsh.log "$T"/du.fail "$T"/beat/* "$T"/img/*; echo "shut off" > "$T/state"; touch "$T/virsh.log"; }
run() {   # run the guard; echoes output to $T/out, status to $T/rc
  PATH=$T/bin:$PATH bash "$guard" iso5-test "$1" > "$T/out" 2>&1; echo $? > "$T/rc"
}
ndestroy() { grep -c destroy "$T/virsh.log"; }

# 1. over the limit: exit 1, one STOP line, ONE destroy
reset; touch "$T/img/iso5-test-a.qcow2"; echo "60	total" > "$T/du.out"
run 50
[[ $(cat "$T/rc") == 1 ]] && ok "trip exit 1" || no "trip exit" "$(cat "$T/rc")"
grep -q "SIZE-GUARD STOP iso5-test 60 GB" "$T/out" && ok "trip message" || no "trip message" "$(cat "$T/out")"
[[ $(ndestroy) == 1 ]] && ok "trip destroys once" || no "trip destroy count" "$(ndestroy)"
[[ $(cat "$T/beat/size-guard-iso5-test.beat") == 60 ]] && ok "heartbeat written" || no "heartbeat" ""

# 2. cannot measure x3: exit 3
reset; touch "$T/img/iso5-test-a.qcow2"; echo "du: boom" > "$T/du.out"; touch "$T/du.fail"
run 50
[[ $(cat "$T/rc") == 3 ]] && ok "cannot-measure exit 3" || no "cannot-measure exit" "$(cat "$T/rc")"
grep -q "cannot measure; VM destroyed" "$T/out" && ok "cannot-measure message" || no "cannot-measure message" "$(cat "$T/out")"
[[ $(grep -c "WARNING cannot measure" "$T/out") == 3 ]] && ok "3 warnings" || no "warnings" ""

# 3. destroy failure: exit 2
reset; touch "$T/img/iso5-test-a.qcow2"; echo "60	total" > "$T/du.out"; echo running > "$T/state"
run 50
[[ $(cat "$T/rc") == 2 ]] && ok "destroy-failed exit 2" || no "destroy-failed exit" "$(cat "$T/rc")"
grep -q "SIZE-GUARD DESTROY FAILED iso5-test" "$T/out" && ok "destroy-failed message" || no "destroy-failed message" "$(cat "$T/out")"

# 4. no image: (POLL_S=60 and the stubbed sleep make the 120 s threshold hit on the 2nd poll, instantly)
# 4. no image: one warning after 120 s, keeps waiting (guard killed by the test)
reset; POLL_S=60 PATH=$T/bin:$PATH bash "$guard" iso5-test 50 > "$T/out" 2>&1 &
gp=$!; sleep 1; kill $gp 2>/dev/null; wait $gp 2>/dev/null
n=$(grep -c "WARNING no image" "$T/out")
[[ $n == 1 ]] && ok "no-image warns once" || no "no-image warning" "count=$n"

echo "$pass passed, $failn failed"; [[ $failn == 0 ]]
