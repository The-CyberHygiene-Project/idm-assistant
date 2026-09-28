#!/usr/bin/env bash
# serial-pty.sh VM: switch a lab VM's serial port from log-file-only to an interactive pty that still logs to the same
# file (libvirt <log>), so `virsh console` works (e.g. to answer a LUKS prompt). Takes effect at the next start.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
vm="${1:?usage: serial-pty.sh VM}"; f=/var/log/libvirt/qemu/$vm-install.log
x=$(mktemp); virsh dumpxml --inactive "$vm" > "$x"
if grep -q "<serial type='pty'>" "$x"; then log "$vm already has a pty serial"; rm -f "$x"; exit 0; fi
python3 - "$x" "$f" <<'PY'
import re, sys
p, f = sys.argv[1:]; s = open(p).read()
s = re.sub(r"<serial type='file'>\s*<source path='[^']*'/>", f"<serial type='pty'>\n      <log file='{f}' append='on'/>", s, count=1)
s = re.sub(r"<console type='file'>\s*<source path='[^']*'/>", f"<console type='pty'>\n      <log file='{f}' append='on'/>", s, count=1)
open(p, 'w').write(s)
PY
run "redefine $vm with a pty serial console (logging kept)" virsh define "$x"
rm -f "$x"
