#!/usr/bin/env bash
# Fetch ET Open for Suricata 7 (Suricata spec §2) into a dated file and check its pinned sha256. Mac only (internet).
set -Eeuo pipefail
IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
ET_URL=https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz
ET_DATE=2026.11.04      # the chp-suricata-rules version
ET_SHA256=1fa39a90478f007ad72b485bbab454f47a66dc2542427729f2f0f12f37e0eabb
mkdir -p "$IN"; out="$IN/et-open-$ET_DATE.tar.gz"
[[ -s $out ]] || curl -fsSL "$ET_URL" -o "$out"
got=$(shasum -a 256 "$out" | cut -d' ' -f1)
[[ $got == "$ET_SHA256" ]] || { echo "ET Open sha256 $got is not the pinned $ET_SHA256"; exit 1; }
echo "OK ET Open $ET_DATE"
