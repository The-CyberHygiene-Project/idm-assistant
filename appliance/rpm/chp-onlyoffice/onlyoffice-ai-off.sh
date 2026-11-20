#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# onlyoffice-ai-off (chp-onlyoffice; spike gate G4): remove ONLYOFFICE's "AI Tools" plugin, whose agent tools include
# run_script and file_opener. Removing its folder removes the AI Tools tab from every editor (spike §Editor). It is a
# folder of the vendor package, so `rpm -V onlyoffice-desktopeditors` reports it missing: expected. Run by
# chp-onlyoffice's %post and %posttrans and by its trigger on every install or upgrade of onlyoffice-desktopeditors.
# Idempotent; a symbolic link in its place is removed as a link, never followed. CHP_OO_ROOT: a test root.
set -u
ROOT=${CHP_OO_ROOT:-}
P="$ROOT/opt/onlyoffice/desktopeditors/editors/sdkjs-plugins/{9DC93CDB-B576-4F0C-B55E-FCC9C48DD007}"
log() { [ -n "${CHP_OO_NOLOG:-}" ] || logger -t chp-onlyoffice -- "$*" 2>/dev/null || true; }
if [ -L "$P" ]; then
  rm -f -- "$P" || { log "could not remove the AI Tools plugin link $P"; exit 1; }
  log "removed a symbolic link in place of the AI Tools plugin ($P)"
elif [ -e "$P" ]; then
  rm -rf -- "$P" || { log "could not remove the AI Tools plugin $P"; exit 1; }
  log "removed ONLYOFFICE's AI Tools plugin ($P)"
fi
[ ! -e "$P" ] && [ ! -L "$P" ]
