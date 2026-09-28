#!/usr/bin/env bash
set -Eeuo pipefail
IN="${IDM_INPUTS:-$HOME/inputs}"; db=$(mktemp -d); trap 'rm -rf "$db"' EXIT
rpm --dbpath "$db" --import "$IN/RPM-GPG-KEY-EPEL-9"
rpm --dbpath "$db" -q gpg-pubkey --qf '%{version}\n' | grep -qx 3228467c || { echo "unexpected key in db"; exit 1; }
for f in "$IN"/*.el9.x86_64.rpm; do
  [[ $f == *google-authenticator* ]] || continue
  rpm --dbpath "$db" -K "$f" | grep -q 'digests signatures OK' || { echo "SIGNATURE FAIL: $f"; exit 1; }
  echo "OK signed by EPEL 9: $(basename "$f")"; rpm -qpR "$f" | grep -vE '^(rpmlib|/)' | sort -u
done
