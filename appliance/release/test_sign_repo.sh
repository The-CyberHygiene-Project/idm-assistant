#!/usr/bin/env bash
# test_sign_repo.sh (RUNS ON AERO): sign-repo.sh / verify-repo.sh with THROWAWAY software keys in a temp GNUPGHOME.
# Fixtures: an unsigned lab RPM and EPEL's signed google-authenticator from /data/lab-inputs/rpms.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
out() { "$@" 2>&1 || true; }   # output of a command expected to fail, for grep (pipefail is on)
FIX=${FIXTURES:-/data/lab-inputs/rpms}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export GNUPGHOME=$T/gnupg; mkdir -m 700 "$GNUPGHOME"
gen() { gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$1 <$1@test.invalid>" rsa3072 sign 1d 2>/dev/null
        gpg --with-colons --list-keys "$1@test.invalid" | awk -F: '/^fpr/{print $10; exit}'; }
A=$(gen chp-test); B=$(gen stranger)
mkdir "$T/keys"; gpg --armor --export "$A" > "$T/keys/A.asc"; cp "$here/RPM-GPG-KEY-EPEL-9" "$T/keys/"
printf '%s\n' "$A cyberhygiene A.asc" "FF8AD1344597106ECE813B918A3872BF3228467C epel9 RPM-GPG-KEY-EPEL-9" > "$T/keys/trusted-keys.txt"
mkdir "$T/stage"; cp "$FIX"/kanidm-clients-1.11.2-1.lab.el9.x86_64.rpm "$FIX"/google-authenticator-*.rpm "$T/stage/"
# 1 happy path
t "signs a stage of unsigned + EPEL-signed RPMs"   "bash '$here/sign-repo.sh' '$T/stage' '$T/out' '$A' '$T/keys' >/dev/null"
t "verify-repo passes on the result"               "bash '$here/verify-repo.sh' '$T/out' '$T/keys' | grep -q 'REPO OK: 2 packages'"
t "our RPM now carries OUR key id"                  "rpm -qp --qf '%{RSAHEADER:pgpsig}\n' '$T'/out/kanidm-clients-*.rpm 2>/dev/null | grep -qi '${A: -16}'"
t "EPEL's RPM keeps EPEL's signature"               "rpm -qp --qf '%{RSAHEADER:pgpsig}\n' '$T'/out/google-authenticator-*.rpm 2>/dev/null | grep -qi 3228467c"
t "the stage itself is untouched (still unsigned)"  "! rpm -qp --qf '%{RSAHEADER:pgpsig}\n' '$T'/stage/kanidm-clients-*.rpm | grep -qi 'key id'"
t "refuses an existing out-dir"                     "! bash '$here/sign-repo.sh' '$T/stage' '$T/out' '$A' '$T/keys' >/dev/null 2>&1"
# 2 unpinned signer in the stage (Review Focus 3)
mkdir "$T/stage2"; cp "$T"/stage/*.rpm "$T/stage2/"
rpmsign --addsign --define "_gpg_name $B" --define "_gpg_digest_algo sha256" "$T"/stage2/kanidm-clients-*.rpm >/dev/null 2>&1
t "refuses an RPM signed by an unpinned key"        "out bash '$here/sign-repo.sh' '$T/stage2' '$T/out2' '$A' '$T/keys' | grep -q REFUSED"
t "…and creates no out-dir"                         "[[ ! -e $T/out2 ]]"
# 3 signer unavailable mid-run (Review Focus 2): a fingerprint with no secret key
t "fails when the signer key is unavailable"        "! bash '$here/sign-repo.sh' '$T/stage' '$T/out3' 0000000000000000000000000000000000000000 '$T/keys' >/dev/null 2>&1"
t "…and creates no out-dir"                         "[[ ! -e $T/out3 ]]"
t "…and leaves no temp dir behind"                  "! ls -d '$T'/.sign.* >/dev/null 2>&1"
# 4 verify-repo negatives
cp -a "$T/out" "$T/v1"; cp "$FIX"/kanidm-server-1.11.2-1.lab.el9.x86_64.rpm "$T/v1/"
t "verify: an unsigned RPM added later fails"       "out bash '$here/verify-repo.sh' '$T/v1' '$T/keys' | grep -q 'BAD SIGNATURE: kanidm-server'"
cp -a "$T/out" "$T/v2"; echo '<!-- x -->' >> "$T/v2/repodata/repomd.xml"
t "verify: edited repomd.xml fails"                  "out bash '$here/verify-repo.sh' '$T/v2' '$T/keys' | grep -q 'BAD repomd signature'"
cp -a "$T/out" "$T/v3"; rm "$T/v3/repodata/repomd.xml.asc"
t "verify: missing repomd.xml.asc fails"             "out bash '$here/verify-repo.sh' '$T/v3' '$T/keys' | grep -q 'MISSING repomd.xml.asc'"
cp -a "$T/out" "$T/v4"; gpg --batch --yes -u "$B" --armor --detach-sign -o "$T/v4/repodata/repomd.xml.asc" "$T/v4/repodata/repomd.xml"
t "verify: repomd signed by another key fails"      "out bash '$here/verify-repo.sh' '$T/v4' '$T/keys' | grep -q 'BAD repomd signature'"
cp -a "$T/keys" "$T/k5"; sed -i "s/^$A /${B} /" "$T/k5/trusted-keys.txt"
t "verify: a key file that doesn't match its pin fails" "out bash '$here/verify-repo.sh' '$T/out' '$T/k5' | grep -q 'KEY MISMATCH'"
mkdir -p "$T/v6/repodata"
t "verify: an empty repo fails"                     "out bash '$here/verify-repo.sh' '$T/v6' '$T/keys' | grep -q 'no RPMs'"
exit $fails

