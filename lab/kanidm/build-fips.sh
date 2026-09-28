#!/usr/bin/env bash
# Runs ON build1. FIPS-variant experiment: Kanidm 1.11.2 with rustls' "fips" feature (AWS-LC FIPS module,
# aws-lc-fips-sys), built offline. Only kanidmd and kanidm: they carry the TLS stack. Needs Go, cmake, perl (DVD).
set -Eeuo pipefail
V=1.11.2; IN=$HOME/inputs; W=$HOME/kanidm-build-fips; SRC=$W/src
export PATH=/opt/rust-1.96/bin:$PATH KANIDM_BUILD_PROFILE=release_linux CARGO_TARGET_DIR=$W/target
mkdir -p "$W"
if [[ ! -d $SRC ]]; then
  mkdir -p "$SRC"
  tar -xzf "$IN/kanidm-$V.tar.gz" -C "$SRC" --strip-components=1
  # The variant tarball carries the patched Cargo.toml, its Cargo.lock and the matching vendor set.
  tar -xzf "$IN/kanidm-$V-fips-vendor.tar.gz" -C "$SRC"
  mkdir -p "$SRC/.cargo"
  cp "$SRC/vendor-config.toml" "$SRC/.cargo/config.toml"
  printf '\n[net]\noffline = true\n' >> "$SRC/.cargo/config.toml"
fi
cd "$SRC"
grep -q '"fips",' Cargo.toml || { echo "FAILED: variant Cargo.toml lacks the fips feature"; exit 1; }
: > "$W/build.log"; : > "$W/timings.txt"
b() { local t=$1; shift; local s; s=$(date +%s); "$@" >>"$W/build.log" 2>&1 || { echo "FAILED: $t (see $W/build.log)"; tail -30 "$W/build.log"; exit 1; }; echo "$t $(( $(date +%s) - s )) s" | tee -a "$W/timings.txt"; }
b kanidmd  cargo build --locked -p daemon --bin kanidmd --release
b kanidm   cargo build --locked -p kanidm_tools --bin kanidm --release
cargo tree --locked -e normal --prefix none -f '{p}' -p daemon | sed 's/ (.*//; s/ (\*)//' | sort -u > "$W/linked-crates.txt"
echo "BUILD OK"; cat "$W/timings.txt"
