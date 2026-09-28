#!/usr/bin/env bash
# Runs ON build1. Offline build of Kanidm 1.11.2 with the release_linux profile (Makefile release/* targets,
# plus --locked, plus the selinux feature for unixd). Re-runnable: cargo resumes from its cache.
set -Eeuo pipefail
V=1.11.2; IN=$HOME/inputs; W=$HOME/kanidm-build; SRC=$W/src
export PATH=/opt/rust-1.96/bin:$PATH KANIDM_BUILD_PROFILE=release_linux CARGO_TARGET_DIR=$W/target
mkdir -p "$W"
if [[ ! -d $SRC ]]; then
  mkdir -p "$SRC"
  tar -xzf "$IN/kanidm-$V.tar.gz" -C "$SRC" --strip-components=1
  tar -xzf "$IN/kanidm-$V-vendor.tar.gz" -C "$SRC"
  mkdir -p "$SRC/.cargo"
  cp "$SRC/vendor-config.toml" "$SRC/.cargo/config.toml"
  printf '\n[net]\noffline = true\n' >> "$SRC/.cargo/config.toml"
fi
cd "$SRC"
: > "$W/build.log"; : > "$W/timings.txt"
b() { local t=$1; shift; local s; s=$(date +%s); "$@" >>"$W/build.log" 2>&1 || { echo "FAILED: $t (see $W/build.log)"; tail -30 "$W/build.log"; exit 1; }; echo "$t $(( $(date +%s) - s )) s" | tee -a "$W/timings.txt"; }
b kanidmd        cargo build --locked -p daemon --bin kanidmd --release
b kanidm         cargo build --locked -p kanidm_tools --bin kanidm --release
b pam_kanidm     cargo build --locked -p pam_kanidm --release
b nss_kanidm     cargo build --locked -p nss_kanidm --release
b unixd          cargo build --locked --features unix,selinux -p kanidm_unix_int --release --bin kanidm_unixd --bin kanidm_unixd_tasks --bin kanidm-unix
b ssh            cargo build --locked --release --bin kanidm_ssh_authorizedkeys --bin kanidm_ssh_authorizedkeys_direct
# Q2: which crates are actually linked into what we ship (Cargo.lock lists every optional crate too).
for spec in "daemon" "kanidm_tools" "pam_kanidm" "nss_kanidm" "kanidm_unix_int --features unix,selinux"; do
  # shellcheck disable=SC2086  # $spec holds a package name plus optional flags
  cargo tree --locked -e normal --prefix none -f '{p}' -p $spec
done | sed 's/ (.*//; s/ (\*)//' | sort -u > "$W/linked-crates.txt"
cd "$CARGO_TARGET_DIR/release"
sha256sum kanidmd kanidm kanidm_unixd kanidm_unixd_tasks kanidm-unix kanidm_ssh_authorizedkeys \
  kanidm_ssh_authorizedkeys_direct libpam_kanidm.so libnss_kanidm.so > "$W/SHA256SUMS"
echo "BUILD OK"; cat "$W/timings.txt"
