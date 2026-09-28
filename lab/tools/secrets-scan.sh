#!/usr/bin/env bash
# Fail if anything that looks like a lab secret is in the given paths (default: the whole repo, tracked files).
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
files=("$@")
# Default: all tracked files except the scanner's own test, whose fake samples exist to trip it. bash 3.2: no mapfile.
if [[ ${#files[@]} -eq 0 ]]; then
  while IFS= read -r f; do [[ $f == tests/test_secrets_scan.py ]] || files+=("$f"); done < <(git ls-files)
fi
# Case-insensitive; one alternative per secret format the lab scripts produce (tests/test_secrets_scan.py).
pat='BEGIN [A-Z ]*PRIVATE KEY'                                   # SSH/TLS/CA private keys
pat+='|secret=[A-Z2-7]{16,}'                                     # otpauth URIs, TOTP_SECRET= lines
pat+='|"(totp_secret|password|posix_password)" *: *"[^".]{8,}"'  # labNN.json / admin json
pat+='|new_password: *"[A-Za-z0-9]{8,}"'                         # kanidmd recover-account output
pat+='|use-reset-token +[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}'  # Kanidm reset tokens
pat+='|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'              # API tokens (JWS)
# JBSWY3DPEHPK3PXP is the widely published TOTP example secret, used in docs as a test input.
if grep -inE "$pat" "${files[@]}" 2>/dev/null | grep -v 'JBSWY3DPEHPK3PXP'; then echo "SECRETS-SCAN: FAIL"; exit 1; fi
echo "SECRETS-SCAN: clean (${#files[@]} files)"
