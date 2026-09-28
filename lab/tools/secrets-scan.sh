#!/usr/bin/env bash
# Fail if anything that looks like a lab secret is in the given paths (default: the whole repo, tracked files).
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
files=("$@")
if [[ ${#files[@]} -eq 0 ]]; then while IFS= read -r f; do files+=("$f"); done < <(git ls-files); fi   # bash 3.2 (macOS): no mapfile
pat='BEGIN [A-Z ]*PRIVATE KEY|secret=[A-Z2-7]{16,}|new_password: *"[A-Za-z0-9]{8,}"|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
# JBSWY3DPEHPK3PXP is the widely published TOTP example secret, used in docs as a test input.
if grep -nE "$pat" "${files[@]}" 2>/dev/null | grep -v 'JBSWY3DPEHPK3PXP'; then echo "SECRETS-SCAN: FAIL"; exit 1; fi
echo "SECRETS-SCAN: clean (${#files[@]} files)"
