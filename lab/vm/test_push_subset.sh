#!/usr/bin/env bash
# I2: the manifest subset sent to build1 must contain exactly the files being pushed, so a manifest line for an
# input that build1 never receives (e.g. the FIPS vendor tarball) cannot make verification fail.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
# shellcheck source=subset.sh
source "$here/vm/subset.sh"
base=(rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz kanidm-1.11.2.tar.gz kanidm-1.11.2-vendor.tar.gz)
# shellcheck disable=SC2034  # out/out2 are read inside the eval'd test strings
out=$(manifest_subset "$here/inputs/MANIFEST.txt" "${base[@]}")
t "subset has exactly the three pushed inputs" "[[ \$(printf '%s\n' \"\$out\" | wc -l | tr -d ' ') == 3 ]]"
t "subset omits the FIPS vendor tarball when it isn't pushed" "! grep -q '^kanidm-1.11.2-fips-vendor' <<<\"\$out\""
# shellcheck disable=SC2034
out2=$(manifest_subset "$here/inputs/MANIFEST.txt" "${base[@]}" kanidm-1.11.2-fips-vendor.tar.gz)
t "subset includes the FIPS tarball when it is pushed" "grep -q '^kanidm-1.11.2-fips-vendor' <<<\"\$out2\""
t "an unknown input name makes manifest_subset fail" "! manifest_subset '$here/inputs/MANIFEST.txt' no-such-file.tar.gz >/dev/null"
exit $fails
