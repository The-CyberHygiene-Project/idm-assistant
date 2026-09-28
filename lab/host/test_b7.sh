#!/usr/bin/env bash
# shellcheck disable=SC2034  # out/rc are read inside the eval'd test strings
# I1: b7's failure paths, run on aero with stub virsh/virt-install (no real VM is touched):
#   sudo bash /tmp/lab-host/test_b7.sh   (push.sh copies it there)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
stub=$(mktemp -d); trap 'rm -rf "$stub"' EXIT
# Scenario knobs read by the stubs: EXISTS (dominfo succeeds), GOLDEN (snapshot-info succeeds), STATE (domstate).
cat > "$stub/virsh" <<'S'
#!/bin/bash
case "$1" in
  dominfo) [[ ${EXISTS:-0} == 1 ]] ;;
  snapshot-info) [[ ${GOLDEN:-0} == 1 ]] ;;
  domstate) echo "${STATE:-running}" ;;
  destroy) echo destroyed >> "$STUBLOG" ;;
  start) echo started >> "$STUBLOG" ;;
esac
S
printf '#!/bin/bash\necho "ERROR    Installation has exceeded specified time limit"; exit 1\n' > "$stub/virt-install"
chmod +x "$stub/virsh" "$stub/virt-install"
run_b7() { STUBLOG="$stub/log" PATH="$stub:/usr/bin:/usr/sbin" bash "$here/b7-vm-build1.sh" 2>&1; }
: > "$stub/log"; out=$(EXISTS=0 STATE=running run_b7); rc=$?
t "timeout: exits non-zero" "(( rc != 0 ))"
t "timeout: prints the clear message pointing at the log" "grep -q 'install did not finish' <<<\"\$out\""
t "timeout: stops the stuck installer VM" "grep -q destroyed '$stub/log'"
t "timeout: does not start the VM" "! grep -q started '$stub/log'"
: > "$stub/log"; out=$(EXISTS=1 GOLDEN=0 run_b7); rc=$?
t "half-built VM (no golden snapshot): refuses with non-zero exit" "(( rc != 0 )) && grep -q 'no golden snapshot' <<<\"\$out\""
: > "$stub/log"
out=$(EXISTS=1 GOLDEN=1 run_b7); rc=$?
t "complete VM (golden snapshot): 'already exists', exit 0" "(( rc == 0 )) && grep -q 'already exists' <<<\"\$out\""
exit $fails
