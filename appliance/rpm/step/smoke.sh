#!/usr/bin/env bash
# Runs ON build1: init a throwaway CA on loopback, start it with GODEBUG=fips140=on, health-check, issue one cert.
set -Eeuo pipefail
B=$HOME/step-build/out; T=$(mktemp -d); trap 'kill ${pid:-0} 2>/dev/null; rm -rf "$T"' EXIT
export STEPPATH=$T; head -c 32 /dev/urandom | base64 > "$T/pw"
"$B/step-cli" ca init --name "smoke CA" --dns localhost --dns 127.0.0.1 --address 127.0.0.1:9443 --provisioner smoke \
   --password-file "$T/pw" --provisioner-password-file "$T/pw" --deployment-type standalone >/dev/null
GODEBUG=fips140=on "$B/step-ca" "$T/config/ca.json" --password-file "$T/pw" >"$T/ca.log" 2>&1 & pid=$!
for _ in $(seq 20); do "$B/step-cli" ca health --ca-url https://127.0.0.1:9443 --root "$T/certs/root_ca.crt" >/dev/null 2>&1 && break; sleep 1; done
"$B/step-cli" ca health --ca-url https://127.0.0.1:9443 --root "$T/certs/root_ca.crt"
"$B/step-cli" ca certificate smoke.test "$T/s.crt" "$T/s.key" --provisioner smoke --provisioner-password-file "$T/pw" \
   --ca-url https://127.0.0.1:9443 --root "$T/certs/root_ca.crt" >/dev/null
"$B/step-cli" certificate inspect "$T/s.crt" --short
echo "SMOKE OK"

