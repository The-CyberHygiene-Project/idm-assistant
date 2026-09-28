#!/usr/bin/env bash
# Fetch EPEL-9 RPMs the CHP kit needs that the Rocky DVD lacks, and the EPEL 9 key (fingerprint pinned).
# The RPM signatures are then checked on a Rocky host by verify-epel.sh (rpm is not available on macOS).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
# shellcheck source=gpgcheck.sh
source "$here/gpgcheck.sh"
fpr_ok() { gpg --batch --with-colons --fingerprint "$1" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}' | grep -qx "$1"; }
EPEL_FPR=FF8AD1344597106ECE813B918A3872BF3228467C
BASE=https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages
PKGS=(g/google-authenticator-1.09-5.el9.x86_64.rpm)
gpg_sandbox
curl -fsSL https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9 -o "$IN/RPM-GPG-KEY-EPEL-9"
gpg --batch --import "$IN/RPM-GPG-KEY-EPEL-9" 2>/dev/null
fpr_ok "$EPEL_FPR" || { echo "EPEL 9 key fingerprint mismatch"; exit 1; }
for p in "${PKGS[@]}"; do out="$IN/$(basename "$p")"; [[ -s $out ]] || curl -fsSL "$BASE/$p" -o "$out"; echo "fetched $(basename "$out")"; done
