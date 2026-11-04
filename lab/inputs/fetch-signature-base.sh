#!/usr/bin/env bash
# Fetch Neo23x0 signature-base at the pinned commit (YARA spec §2) and check its sha256. Mac only (needs internet).
set -Eeuo pipefail
IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
SIG_COMMIT=36ab70428fc5b52701b7ee6107c853ff019ed759
SIG_SHA256=f63f2184ba3608876d695b4003b6e198ba129438dbd5aa9cb4b51ff0a86ebbe4
SIG_DATE=2026.10.29                 # the commit date: chp-yara-rules version (YYYY.MM.DD)
mkdir -p "$IN"
out="$IN/signature-base-$SIG_COMMIT.tar.gz"
[[ -s $out ]] || curl -fsSL "https://github.com/Neo23x0/signature-base/archive/$SIG_COMMIT.tar.gz" -o "$out"
got=$(shasum -a 256 "$out" | cut -d' ' -f1)
[[ $got == "$SIG_SHA256" ]] || { echo "signature-base sha256 $got is not the pinned $SIG_SHA256"; exit 1; }
echo "OK signature-base $SIG_COMMIT"
