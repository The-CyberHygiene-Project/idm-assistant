#!/usr/bin/env bash
# size-guard.sh NAME LIMIT_GB (RUNS ON AERO, as root): a runaway-allocation brake for a sparse-disk lab VM.
# It FAILS CLOSED. Every 10 s it measures the ACTUAL allocation (du -B1G, rounded up; not the virtual size) of
# $IMG_DIR/NAME-*.qcow2 and writes it to the heartbeat file /run/size-guard-NAME.beat (install-iso.sh waits for it).
#   over the limit            -> virsh destroy NAME, print "SIZE-GUARD STOP NAME <GB> GB" + snapshots, exit 1
#   destroy did not work      -> print "SIZE-GUARD DESTROY FAILED NAME", exit 2
#   3 failed measurements in a row (du error / unparseable) -> destroy NAME, print "SIZE-GUARD STOP NAME
#                               (cannot measure)", exit 3
#   no image after 120 s      -> one warning on stderr (wrong name or path); keeps waiting
# Start it so it outlives the ssh session:  systemd-run --unit=size-guard-NAME size-guard.sh NAME 50
# Stop it with:  systemctl stop size-guard-NAME      (messages go to: journalctl -u size-guard-NAME)
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
name=${1:?NAME} limit=${2:?LIMIT_GB}
[[ $name == iso5-* ]] || { echo "refusing: only iso5-* lab VMs"; exit 1; }
[[ $limit =~ ^[0-9]+$ ]] || { echo "LIMIT_GB must be a whole number"; exit 1; }
dir=${IMG_DIR:-/data/libvirt/images}; beat=${BEAT_DIR:-/run}/size-guard-$name.beat
rm -f "$beat"
kill_vm() {   # 0 = VM is off afterwards, 1 = it is not
  virsh destroy "$name" >/dev/null 2>&1 || true
  [[ $(virsh domstate "$name" 2>&1) == "shut off" || $(virsh domstate "$name" 2>&1) == *"failed to get domain"* ]]
}
fails=0 waited=0 warned=0
while sleep "${POLL_S:-10}"; do
  shopt -s nullglob; imgs=("$dir"/"$name"-*.qcow2); shopt -u nullglob
  if (( ${#imgs[@]} == 0 )); then
    waited=$((waited + ${POLL_S:-10}))
    (( waited >= 120 && !warned )) && { echo "SIZE-GUARD WARNING no image $dir/$name-*.qcow2 after ${waited}s (wrong name or path?)" >&2; warned=1; }
    continue
  fi
  gb=$(du -B1G -c "${imgs[@]}" 2>&1 | tail -1 | cut -f1)
  if [[ ! $gb =~ ^[0-9]+$ ]]; then
    fails=$((fails + 1)); echo "SIZE-GUARD WARNING cannot measure $name ($fails/3): '${gb}'" >&2
    if (( fails >= 3 )); then
      if kill_vm; then echo "SIZE-GUARD STOP $name (cannot measure; VM destroyed)"; exit 3
      else echo "SIZE-GUARD DESTROY FAILED $name (cannot measure)"; exit 2; fi
    fi
    continue
  fi
  fails=0; echo "$gb" > "$beat"
  if (( gb > limit )); then
    if kill_vm; then echo "SIZE-GUARD STOP $name $gb GB (limit $limit GB)"
    else echo "SIZE-GUARD DESTROY FAILED $name ($gb GB, limit $limit GB)"; fi
    for i in "${imgs[@]}"; do echo "== $i"; qemu-img snapshot -l "$i" 2>&1 || true; done
    kill_vm && exit 1 || exit 2
  fi
done
