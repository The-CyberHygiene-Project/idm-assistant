#!/usr/bin/env bash
# b3: VM images on /data (LUKS), SELinux-labelled, as libvirt's default pool.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
P=/data/libvirt/images
run "create image dir" mkdir -p "$P"
# Read the full local-customisation list first: grep -q on a pipe can SIGPIPE semanage (pipefail).
grep -qF "/data/libvirt/images" < <(semanage fcontext -l -C) || \
  run "label rule virt_image_t" semanage fcontext -a -t virt_image_t "/data/libvirt/images(/.*)?"
run "apply label" restorecon -R /data/libvirt
if ! virsh pool-info default >/dev/null 2>&1; then
  run "define default pool" virsh pool-define-as default dir --target "$P"
  run "autostart pool" virsh pool-autostart default
  run "start pool" virsh pool-start default
fi
log "b3 done"
