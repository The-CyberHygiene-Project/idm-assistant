#!/usr/bin/env bash
# b1: DVD + lab RPMs become the ONLY dnf repos on aero (it is offline).
# Inputs must already be in /data/lab-inputs (copied by the Mac).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
IN=/data/lab-inputs; MNT=$IN/dvd; ISO=$IN/Rocky-9.8-x86_64-dvd.iso
[[ -f $ISO ]] || die "missing $ISO"
# Never use an input that fails verification on THIS host (review: copy errors, stale files).
MANIFEST=${LAB_MANIFEST:-$IN/MANIFEST.txt}
[[ -f $IN/verify.sh ]] || die "missing $IN/verify.sh (copy it from the Mac)"
IDM_INPUTS=$IN IDM_MANIFEST=$MANIFEST bash "$IN/verify.sh" >/dev/null \
  || die "inputs in $IN failed verification against $MANIFEST"
log "inputs verified against $MANIFEST"
run "create mount point" mkdir -p "$MNT" "$IN/rpms"
if ! grep -q " $MNT " /etc/fstab; then
  run "add DVD loop mount to fstab" sh -c "echo '$ISO $MNT iso9660 loop,ro,nofail 0 0' >> /etc/fstab"
fi
mountpoint -q "$MNT" || run "mount DVD" mount "$MNT"
# aero is offline: EVERY non-lab repo is disabled BY ID (dnf decides what "enabled" means,
# including sections with no enabled= line). Each ID is recorded for an exact restore:
#   dnf config-manager --set-enabled $(cat /etc/yum.repos.d/.lab-disabled-repos)
REC=/etc/yum.repos.d/.lab-disabled-repos
mapfile -t ENABLED < <(dnf repolist --enabled -q 2>/dev/null | awk 'NR>1{print $1}' | grep -v '^lab-' || true)
for id in "${ENABLED[@]}"; do
  run "disable repo $id (recorded for restore)" \
    sh -c "dnf config-manager --set-disabled '$id' >/dev/null && { grep -qx '$id' $REC 2>/dev/null || echo '$id' >> $REC; }"
done
run "write lab repo definitions" sh -c "cat > /etc/yum.repos.d/lab.repo <<REPO
[lab-baseos]
name=Lab DVD BaseOS (Rocky 9.8)
baseurl=file://$MNT/BaseOS
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
enabled=1
[lab-appstream]
name=Lab DVD AppStream (Rocky 9.8)
baseurl=file://$MNT/AppStream
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
enabled=1
[lab-local]
name=Lab local RPMs (sha256-verified on the Mac; unsigned)
baseurl=file://$IN/rpms
gpgcheck=0
enabled=1
REPO"
run "install createrepo_c from the DVD" dnf -y --disablerepo='*' --enablerepo='lab-baseos,lab-appstream' install createrepo_c
run "stage step RPMs in the local repo" sh -c "cp -f $IN/step-ca-*.rpm $IN/step-cli-*.rpm $IN/rpms/"
run "index the local repo" createrepo_c -q "$IN/rpms"
run "refresh metadata" dnf -q makecache
if (( ! CHECK )); then
  others=$(dnf repolist --enabled -q 2>/dev/null | awk 'NR>1{print $1}' | grep -v '^lab-' || true)
  [[ -z "$others" ]] || die "non-lab repos still enabled: $others"
  log "asserted: only lab-* repos are enabled"
fi
log "b1 done"
