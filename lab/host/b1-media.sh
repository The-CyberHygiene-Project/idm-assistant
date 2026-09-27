#!/usr/bin/env bash
# b1: DVD + lab RPMs become the ONLY dnf repos on aero (it is offline).
# Inputs must already be in /data/lab-inputs (copied by the Mac).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
IN=/data/lab-inputs; MNT=$IN/dvd; ISO=$IN/Rocky-9.8-x86_64-dvd.iso
[[ -f $ISO ]] || die "missing $ISO"
run "create mount point" mkdir -p "$MNT" "$IN/rpms"
if ! grep -q " $MNT " /etc/fstab; then
  run "add DVD loop mount to fstab" sh -c "echo '$ISO $MNT iso9660 loop,ro,nofail 0 0' >> /etc/fstab"
fi
mountpoint -q "$MNT" || run "mount DVD" mount "$MNT"
# aero is offline: EVERY non-lab repo (Rocky, EPEL, vendor repos...) is disabled, and the list
# of what was enabled is kept so it can be restored exactly.
if [[ ! -f /etc/yum.repos.d/.lab-disabled-repos ]]; then
  run "record the repos that were enabled" sh -c "dnf repolist --enabled -q 2>/dev/null | awk 'NR>1{print \$1}' | grep -v '^lab-' > /etc/yum.repos.d/.lab-disabled-repos"
fi
# shellcheck disable=SC2016  # $f must expand inside the inner sh, not here
run "disable every non-lab repo (aero has no internet)" \
  sh -c 'for f in /etc/yum.repos.d/*.repo; do [ "$f" = /etc/yum.repos.d/lab.repo ] || sed -i "s/^enabled *= *1/enabled=0/" "$f"; done'
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
log "b1 done"
