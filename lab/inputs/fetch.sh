#!/usr/bin/env bash
# Fetch + verify every offline input for the dc2-stack lab. Resumable (curl -C -).
# Runs on the Mac ONLY. Nothing unverified leaves this directory.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; MAN="$HERE/MANIFEST.txt"   # resolve BEFORE changing directory
# shellcheck source=gpgcheck.sh
source "$HERE/gpgcheck.sh"
gpg_sandbox
D="${IDM_INPUTS:-$HOME/idm-lab-inputs}"; mkdir -p "$D"; cd "$D"
ROCKY=https://download.rockylinux.org/pub/rocky/9.8/isos/x86_64
ROCKY_FPR=21CB256AE16FC54C6E652949702D426D350D275D
RUST=https://static.rust-lang.org/dist
RUST_FPR=108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE
KANIDM=v1.11.2
KANIDM_SHA=a8ed31203e5f8c036b9cb261c85ddac19291bc6ca16981495495cd9621c56529  # pinned 2026-09-27
STEPCA=https://github.com/smallstep/certificates/releases/download/v0.30.2
STEPCLI=https://github.com/smallstep/cli/releases/download/v0.31.0
get() {  # url file: skip when already complete, otherwise download/resume
  local len; len=$(curl -sIL "$1" | tr -d '\r' | awk 'tolower($1)=="content-length:"{v=$2} END{print v+0}')
  if [[ -f "$2" && "$len" != 0 && "$(bytes "$2")" == "$len" ]]; then echo "have $2"; return 0; fi
  # no length advertised (e.g. GitHub tag archives): keep an existing file; its sha256 is recorded below
  if [[ -s "$2" && "$len" == 0 ]]; then echo "have $2 (server gives no length)"; return 0; fi
  curl -fL --retry 3 -C - -o "$2" "$1"
}
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
bytes() { stat -f %z "$1"; }
fpr_ok() { gpg --batch --with-colons --fingerprint "$1" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}' | grep -qx "$1"; }
: > "$MAN.tmp"   # becomes MANIFEST.txt only when every input has passed
rec() { echo "$1|$2|$(bytes "$1")|$(sha "$1")|$3|$4" >> "$MAN.tmp"; }

echo "== Rocky 9.8 DVD"
get "$ROCKY/Rocky-9.8-x86_64-dvd.iso.CHECKSUM" Rocky-9.8-x86_64-dvd.iso.CHECKSUM
get "$ROCKY/Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc" Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc
curl -fsSL https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9 | gpg --batch --import 2>/dev/null
fpr_ok "$ROCKY_FPR" || { echo "Rocky key fingerprint mismatch"; exit 1; }
# Rocky's .asc is a DETACHED signature over CHECKSUM; the signer must be the pinned key.
verify_detached Rocky-9.8-x86_64-dvd.iso.CHECKSUM.asc Rocky-9.8-x86_64-dvd.iso.CHECKSUM "$ROCKY_FPR" \
  || { echo "Rocky CHECKSUM signature not valid for $ROCKY_FPR"; exit 1; }
get "$ROCKY/Rocky-9.8-x86_64-dvd.iso" Rocky-9.8-x86_64-dvd.iso
want=$(grep -E 'SHA256 \(Rocky-9.8-x86_64-dvd.iso\)' Rocky-9.8-x86_64-dvd.iso.CHECKSUM | awk '{print $NF}')
[[ "$(sha Rocky-9.8-x86_64-dvd.iso)" == "$want" ]] || { echo "DVD sha256 mismatch"; exit 1; }
rec Rocky-9.8-x86_64-dvd.iso 9.8 "$ROCKY" "sha256 vs CHECKSUM, CHECKSUM gpg-signed $ROCKY_FPR"

echo "== Rust 1.96.0"
R=rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz
get "$RUST/$R" "$R"; get "$RUST/$R.asc" "$R.asc"; get "$RUST/$R.sha256" "$R.sha256"
curl -fsSL https://static.rust-lang.org/rust-key.gpg.ascii | gpg --batch --import 2>/dev/null
fpr_ok "$RUST_FPR" || { echo "Rust key fingerprint mismatch"; exit 1; }
verify_detached "$R.asc" "$R" "$RUST_FPR" || { echo "Rust signature not valid for $RUST_FPR"; exit 1; }
[[ "$(sha "$R")" == "$(awk '{print $1}' "$R.sha256")" ]] || { echo "rust sha256 mismatch"; exit 1; }
rec "$R" 1.96.0 "$RUST" "gpg $RUST_FPR + sha256"

echo "== step-ca / step-cli RPMs"
get "$STEPCA/step-ca-0.30.2-1.x86_64.rpm" step-ca-0.30.2-1.x86_64.rpm
get "$STEPCA/checksums.txt" step-ca.checksums.txt
get "$STEPCLI/step-cli-0.31.0-1.x86_64.rpm" step-cli-0.31.0-1.x86_64.rpm
get "$STEPCLI/checksums.txt" step-cli.checksums.txt
check_sum() {  # file checksums-file
  [[ "$(sha "$1")" == "$(grep -E " \*?$1\$" "$2" | awk '{print $1}')" ]] || { echo "$1 sha256 mismatch"; exit 1; }
}
check_sum step-ca-0.30.2-1.x86_64.rpm step-ca.checksums.txt
check_sum step-cli-0.31.0-1.x86_64.rpm step-cli.checksums.txt
rec step-ca-0.30.2-1.x86_64.rpm 0.30.2 "$STEPCA" "sha256 vs release checksums.txt"
rec step-cli-0.31.0-1.x86_64.rpm 0.31.0 "$STEPCLI" "sha256 vs release checksums.txt"

echo "== Kanidm $KANIDM source + vendored crates"
# The tag archive is unsigned: download to .part, accept only the pinned sha256.
if [[ "$( [[ -f kanidm-1.11.2.tar.gz ]] && sha kanidm-1.11.2.tar.gz)" != "$KANIDM_SHA" ]]; then
  rm -f kanidm-1.11.2.tar.gz.part
  curl -fL --retry 3 -o kanidm-1.11.2.tar.gz.part "https://github.com/kanidm/kanidm/archive/refs/tags/$KANIDM.tar.gz"
  [[ "$(sha kanidm-1.11.2.tar.gz.part)" == "$KANIDM_SHA" ]] || { echo "Kanidm tarball sha256 != pinned"; exit 1; }
  mv kanidm-1.11.2.tar.gz.part kanidm-1.11.2.tar.gz
fi
# Re-vendoring makes a byte-different tarball (timestamps), so an existing one is reused;
# every crate inside is checked against Cargo.lock's hashes when cargo builds offline.
if [[ ! -s kanidm-1.11.2-vendor.tar.gz ]]; then
  rm -rf kanidm-src && mkdir kanidm-src && tar -xzf kanidm-1.11.2.tar.gz -C kanidm-src --strip-components=1
  ( cd kanidm-src && cargo vendor --locked --versioned-dirs vendor > vendor-config.toml )
  tar -czf kanidm-1.11.2-vendor.tar.gz.part -C kanidm-src vendor vendor-config.toml
  mv kanidm-1.11.2-vendor.tar.gz.part kanidm-1.11.2-vendor.tar.gz
  rm -rf kanidm-src
fi
rec kanidm-1.11.2.tar.gz 1.11.2 "github kanidm/kanidm tag $KANIDM" "sha256 == pinned KANIDM_SHA (tag archive is unsigned)"
rec kanidm-1.11.2-vendor.tar.gz 1.11.2 "cargo vendor --locked" "crate hashes enforced by Cargo.lock at build time"

mv "$MAN.tmp" "$MAN"
echo "ALL INPUTS VERIFIED. Manifest: $MAN"
