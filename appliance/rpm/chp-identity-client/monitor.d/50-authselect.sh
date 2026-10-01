#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 50-authselect: the Kanidm authselect profile and its CUI feature set are still in place (row 27: hand edits survive until someone looks).
M=/var/lib/chp/firstboot; O=/var/lib/chp/authselect-original
if [ ! -e "$M/client.done" ]; then echo "OK authselect (not enrolled yet)"; exit 0; fi
want="custom/kanidm $(tail -n +2 "$O" 2>/dev/null | sort | tr '\n' ' ')"
got="$(authselect current -r 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | head -1) $(authselect current -r 2>/dev/null | tr ' ' '\n' | sed '/^$/d' | tail -n +2 | sort | tr '\n' ' ')"
if ! authselect check >/dev/null 2>&1; then echo "ALERT authselect check fails (files edited by hand?)"
elif [ "$got" != "$want" ]; then echo "ALERT authselect is '${got% }', expected '${want% }'"
else echo "OK authselect ${want% }"; fi
