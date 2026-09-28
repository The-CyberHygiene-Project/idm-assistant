#!/usr/bin/env bash
# b7: unattended install of build1 from the local DVD, then start it (snapshot "golden" is taken from the Mac after checks).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=vm-lib.sh
source "$(dirname "$0")/vm-lib.sh"; need_root
create_vm build1 12 16384 80 /tmp/lab-host/build1.ks
log "b7 done"
