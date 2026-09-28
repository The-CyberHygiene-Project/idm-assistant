#!/usr/bin/env bash
# bind-root-tpm.sh [HOST]  (RUNS ON THE MAC): bind HOST's root LUKS volume to its TPM (clevis tpm2, PCR 7 = Secure
# Boot state) on a REAL boot. The passphrase goes over stdin only. Nothing else may read stdin on the remote side
# (an earlier `unbind` in the same command swallowed it, 2026-09-28).
set -Eeuo pipefail
host="${1:-client1}"
dev=$(ssh -n "$host" 'sudo blkid -t TYPE=crypto_LUKS -o device | head -1')
[[ -n $dev ]] || { echo "no LUKS device on $host" >&2; exit 1; }
if ssh -n "$host" "sudo clevis luks list -d $dev" | grep -q tpm2; then echo "$host: $dev already bound"; exit 0; fi
# shellcheck disable=SC2029  # dev expands on the Mac by design
ssh "$host" "sudo clevis luks bind -y -k - -d $dev tpm2 '{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}'" < ~/idm-lab-secrets/"$host"-luks.pass
ssh -n "$host" "sudo clevis luks list -d $dev"
