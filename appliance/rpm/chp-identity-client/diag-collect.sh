#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# diag-collect: the diag key's FORCED command (ISSO #22). Accepts only [sudo -n] [/usr/sbin/]idm-collect [--user NAME]
# (or nothing) from SSH_ORIGINAL_COMMAND and runs the FIXED sudo command itself. Anything else is refused; sudo never runs.
set -eu
SUDO=${CHP_SUDO:-/usr/bin/sudo}     # CHP_SUDO: tests only (sshd passes no client environment: PermitUserEnvironment no)
deny() { echo "diag-collect: refused: only 'idm-collect [--user NAME]' is allowed" >&2; exit 1; }
cmd=${SSH_ORIGINAL_COMMAND:-}
case $cmd in *[!a-z0-9_/\ -]*) deny ;; esac        # no quotes, ;, $, (, `, |, &, glob characters, upper case
set -f; set -- $cmd; set +f                          # split on spaces only; globbing off
if [ "${1:-}" = sudo ]; then [ "${2:-}" = -n ] || deny; shift 2; fi
case ${1:-idm-collect} in /usr/sbin/idm-collect|idm-collect) ;; *) deny ;; esac
[ $# -gt 0 ] && shift
if [ $# -eq 0 ]; then exec "$SUDO" -n /usr/sbin/idm-collect; fi
if [ $# -eq 2 ] && [ "$1" = --user ] && printf '%s' "$2" | grep -Eqx '[a-z][a-z0-9_]{0,31}'; then
  exec "$SUDO" -n /usr/sbin/idm-collect --user "$2"
fi
deny
