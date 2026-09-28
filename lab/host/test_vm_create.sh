#!/usr/bin/env bash
# shellcheck disable=SC2034  # out/rc are read inside the eval'd test strings
# create_vm (vm-lib.sh) and b7's failure paths, run on aero with stub virsh/virt-install (no real VM is touched):
#   sudo bash /tmp/lab-host/test_vm_create.sh   (push.sh copies it there)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
stub=$(mktemp -d); trap 'rm -rf "$stub"' EXIT
# Scenario knobs read by the stubs: EXISTS (dominfo succeeds), GOLDEN (snapshot-info succeeds), STATE (domstate),
# VI_RC (virt-install exit code). Stubs append what they were asked to do to $STUBLOG.
cat > "$stub/virsh" <<'S'
#!/bin/bash
case "$1" in
  dominfo) [[ ${EXISTS:-0} == 1 ]] ;;
  snapshot-info) [[ ${GOLDEN:-0} == 1 ]] ;;
  domstate) echo "${STATE:-running}" ;;
  destroy) echo destroyed >> "$STUBLOG" ;;
  start) echo "started $2" >> "$STUBLOG" ;;
  snapshot-revert) echo "reverted $2" >> "$STUBLOG" ;;
esac
S
cat > "$stub/virt-install" <<'S'
#!/bin/bash
echo "virt-install $*" >> "$STUBLOG"
[[ ${VI_RC:-1} == 0 ]] || { echo "ERROR    Installation has exceeded specified time limit"; exit 1; }
S
chmod +x "$stub/virsh" "$stub/virt-install"
: > "$stub/t1.ks"
cat > "$stub/drive.sh" <<S
source "$here/lib.sh"; source "$here/vm-lib.sh"; need_root
create_vm t1 2 2048 20 "$stub/t1.ks" "\$@"
S
run_cv() { STUBLOG="$stub/log" PATH="$stub:/usr/bin:/usr/sbin" bash "$stub/drive.sh" "$@" 2>&1; }
run_b7() { STUBLOG="$stub/log" PATH="$stub:/usr/bin:/usr/sbin" bash "$here/b7-vm-build1.sh" 2>&1; }

: > "$stub/log"; out=$(EXISTS=0 STATE=running run_cv); rc=$?
t "timeout: exits non-zero" "(( rc != 0 ))"
t "timeout: prints the clear message pointing at the log" "grep -q 'install did not finish' <<<\"\$out\""
t "timeout: stops the stuck installer VM" "grep -q destroyed '$stub/log'"
t "timeout: does not start the VM" "! grep -q started '$stub/log'"
: > "$stub/log"; out=$(EXISTS=1 GOLDEN=0 run_cv); rc=$?
t "half-built VM (no golden snapshot): refuses with non-zero exit" "(( rc != 0 )) && grep -q 'no golden snapshot' <<<\"\$out\""
: > "$stub/log"; out=$(EXISTS=1 GOLDEN=1 run_cv); rc=$?
t "complete VM (golden snapshot): 'already exists', exit 0" "(( rc == 0 )) && grep -q 'already exists' <<<\"\$out\""
: > "$stub/log"; out=$(EXISTS=0 VI_RC=0 STATE='shut off' run_cv --tpm emulator,model=tpm-crb,version=2.0); rc=$?
t "success: extra virt-install args are passed through, VM started" "(( rc == 0 )) && grep -q -- '--tpm emulator,model=tpm-crb,version=2.0' '$stub/log' && grep -q 'started t1' '$stub/log'"
: > "$stub/log"; out=$(EXISTS=1 GOLDEN=1 run_b7); rc=$?
t "b7 wrapper still recognises a complete build1" "(( rc == 0 )) && grep -q 'already exists' <<<\"\$out\""
exit $fails
