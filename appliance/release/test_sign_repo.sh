#!/usr/bin/env bash
# test_sign_repo.sh (RUNS ON AERO): sign-repo.sh / verify-repo.sh with THROWAWAY software keys in a temp GNUPGHOME.
# Fixtures: an unsigned lab RPM and EPEL's signed google-authenticator from /data/lab-inputs/rpms.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
out() { "$@" 2>&1 || true; }   # output of a command expected to fail, for grep (pipefail is on)
FIX=${FIXTURES:-/data/lab-inputs/rpms}
OURS=${OURS:-/data/chp-release/built}   # our unsigned builds: Vendor "The CyberHygiene Project", release .chp
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export GNUPGHOME=$T/gnupg; mkdir -m 700 "$GNUPGHOME"
: > "$T/none.txt"; export CHP_MODULES_TXT=$T/none.txt   # verify-repo: these repos carry no module streams (section 9 sets its own)
gen() { gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$1 <$1@test.invalid>" rsa3072 sign 1d 2>/dev/null
        gpg --with-colons --list-keys "$1@test.invalid" | awk -F: '/^fpr/{print $10; exit}'; }
A=$(gen chp-test); B=$(gen stranger)
mkdir "$T/keys"; gpg --armor --export "$A" > "$T/keys/A.asc"; cp "$here/RPM-GPG-KEY-EPEL-9" "$T/keys/"
printf '%s\n' "$A cyberhygiene A.asc" "FF8AD1344597106ECE813B918A3872BF3228467C epel9 RPM-GPG-KEY-EPEL-9" > "$T/keys/trusted-keys.txt"
mkdir "$T/stage"; cp "$OURS"/kanidm-clients-1.11.2-2.chp.el9.x86_64.rpm "$FIX"/google-authenticator-*.rpm "$T/stage/"
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
# 5 I-2: never sign an unsigned RPM that is not ours
mkdir "$T/stage5"; cp "$FIX"/kanidm-clients-1.11.2-1.lab.el9.x86_64.rpm "$T/stage5/"
t "refuses to sign an unsigned RPM that is not ours (vendor/release)" "out bash '$here/sign-repo.sh' '$T/stage5' '$T/out5' '$A' '$T/keys' | grep -q 'REFUSED: kanidm-clients-1.11.2-1.lab'"
t "…and creates no out-dir"                         "[[ ! -e $T/out5 ]]"
# 6 I-2: assemble-repo takes our packages only from the built dir, third-party names only from the other dir
mkdir -p "$T/a/built" "$T/a/third"; cp "$OURS"/idm-collect-*.rpm "$T/a/built/"
cp "$FIX"/kanidm-server-1.11.2-1.lab.el9.x86_64.rpm "$FIX"/google-authenticator-*.rpm "$T/a/third/"
printf '%s\n' "idm-collect ours" "kanidm-server ours" "google-authenticator epel" > "$T/a/PACKAGES.txt"
cp "$here/assemble-repo.sh" "$here/stage-modules.sh" "$T/a/"; : > "$T/a/MODULES.txt"   # no streams
t "assemble: our package missing from built/ is MISSING, not taken from third-party" "out bash '$T/a/assemble-repo.sh' '$T/a/stage' '$T/a/built' '$T/a/third' | grep -q 'MISSING package: kanidm-server'"
printf '%s\n' "idm-collect ours" "google-authenticator epel" > "$T/a/PACKAGES.txt"
t "assemble: ours from built/, EPEL from third-party" "bash '$T/a/assemble-repo.sh' '$T/a/stage2' '$T/a/built' '$T/a/third' >/dev/null && ls '$T/a/stage2' | grep -q idm-collect && ls '$T/a/stage2' | grep -q google-authenticator"
# 7 I-3: only a PINNED PRIMARY key may have signed an RPM
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$A" rsa3072 sign 1d 2>/dev/null
SUB=$(gpg --with-colons --list-keys "$A" | awk -F: '/^sub/{s=1} s && /^fpr/{print $10; exit}')
mkdir "$T/v7"; cp "$OURS"/idm-collect-*.rpm "$T/v7/"
rpmsign --addsign --define "_gpg_name ${SUB}!" --define "_gpg_digest_algo sha256" "$T"/v7/*.rpm >/dev/null 2>&1
createrepo_c --quiet "$T/v7"; gpg --batch --yes -u "$A" --armor --detach-sign -o "$T/v7/repodata/repomd.xml.asc" "$T/v7/repodata/repomd.xml"
gpg --armor --export "$A" > "$T/keys/A.asc"     # pinned key file now carries the signing subkey too
t "fixture: v7's RPM really is signed by the subkey (else the next check is vacuous)" "rpm -qp --qf '%{RSAHEADER:pgpsig}' '$T'/v7/*.rpm 2>/dev/null | grep -qi '${SUB: -16}'"
t "verify: an RPM signed by a SUBKEY of a pinned key fails" "out bash '$here/verify-repo.sh' '$T/v7' '$T/keys' | grep -q 'BAD SIGNATURE: idm-collect'"
cp -a "$T/keys" "$T/k8"; gpg --armor --export "$A" "$B" > "$T/k8/A.asc"
mkdir "$T/v8"; cp "$OURS"/idm-collect-*.rpm "$T/v8/"
rpmsign --addsign --define "_gpg_name $B" --define "_gpg_digest_algo sha256" "$T"/v8/*.rpm >/dev/null 2>&1
t "fixture: v8's RPM really is signed by the second key" "rpm -qp --qf '%{RSAHEADER:pgpsig}' '$T'/v8/*.rpm 2>/dev/null | grep -qi '${B: -16}'"
createrepo_c --quiet "$T/v8"; gpg --batch --yes -u "$A" --armor --detach-sign -o "$T/v8/repodata/repomd.xml.asc" "$T/v8/repodata/repomd.xml"
t "verify: a key file carrying a second key is rejected" "out bash '$here/verify-repo.sh' '$T/v8' '$T/k8' | grep -q 'KEY FILE HOLDS 2 KEYS'"
# 9 module metadata (ISO 0.7.0): Rocky's modular php RPM + the DVD's AppStream modules.yaml (third-party dir)
VM=$FIX/appstream-modules.yaml.gz; PHP=$(ls "$FIX"/php-common-8.3.*.module+*.rpm | head -1)
PIN=$(sed 's/#.*//' "$here/MODULES.txt" | awk '$1=="vendor-sha256"{print $2}')
mkdir "$T/m1"; cp "$PHP" "$T/m1/"; printf '%s\n' "php 8.3" "vendor-sha256 $PIN" > "$T/m1.txt"
t "modules: the fixture vendor file is the pinned one (MODULES.txt vendor-sha256)" "[[ -n '$PIN' && \$(sha256sum '$VM' | cut -d' ' -f1) == '$PIN' ]]"
t "modules: keeps only the listed stream"            "bash '$here/stage-modules.sh' '$VM' '$T/m1.txt' '$T/m1' >/dev/null && grep -q 'stream: \"8.3\"' '$T/m1/modules.yaml' && ! grep -qE 'stream: \"8.[12]\"|name: postgresql' '$T/m1/modules.yaml'"
mkdir "$T/m2"; cp "$PHP" "$T/m2/"; printf '%s\n' "postgresql 16" "vendor-sha256 $PIN" > "$T/m2.txt"
t "modules: refuses a modular RPM outside the listed streams" "out bash '$here/stage-modules.sh' '$VM' '$T/m2.txt' '$T/m2' | grep -q 'not in any listed stream' && [[ ! -e $T/m2/modules.yaml ]]"
mkdir "$T/m3"; cp "$PHP" "$T/m3/"; : > "$T/m3.txt"
t "modules: refuses modular RPMs when no stream is listed" "out bash '$here/stage-modules.sh' '$VM' '$T/m3.txt' '$T/m3' | grep -q 'no streams'"
t "repodata: refuses modular RPMs without modules.yaml"  "out bash '$here/make-repodata.sh' '$T/m3' | grep -q 'no modules.yaml'"
t "repodata: adds the modules metadata, no loose copy"   "bash '$here/make-repodata.sh' '$T/m1' && grep -q '<data type=\"modules\">' '$T/m1/repodata/repomd.xml' && [[ ! -e $T/m1/modules.yaml ]]"
createrepo_c --quiet "$T/m3"
t "verify: modular RPMs without modules metadata fail"  "out bash '$here/verify-repo.sh' '$T/m3' '$T/keys' | grep -q 'MISSING modules metadata'"
mkdir "$T/m4"; cp "$PHP" "$T/m4/"; bash "$here/stage-modules.sh" "$VM" "$T/m1.txt" "$T/m4" >/dev/null
cp -a "$T/keys" "$T/k9"; cp /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9 "$T/k9/"   # aero is Rocky 9: the vendor key file
echo "21CB256AE16FC54C6E652949702D426D350D275D rocky9 RPM-GPG-KEY-Rocky-9" >> "$T/k9/trusted-keys.txt"
t "sign-repo: signed repo carries the modules metadata" "CHP_MODULES_TXT='$T/m1.txt' bash '$here/sign-repo.sh' '$T/m4' '$T/m4out' '$A' '$T/k9' >/dev/null 2>&1 && [[ -f $T/m4out/repodata/repomd.xml ]] && grep -q '<data type=\"modules\">' '$T/m4out/repodata/repomd.xml'"
# 10 Task 9b signing-tool hardening
# 10a vendor modules file pinned by sha256 in MODULES.txt
mkdir "$T/p1"; cp "$PHP" "$T/p1/"; printf '%s\n' "php 8.3" "vendor-sha256 $(printf 0%.0s {1..64})" > "$T/p1.txt"
t "modules: refuses a vendor file whose sha256 is not the pin" "out bash '$here/stage-modules.sh' '$VM' '$T/p1.txt' '$T/p1' | grep -q 'pins 0000' && [[ ! -e $T/p1/modules.yaml ]]"
echo "php 8.3" > "$T/p2.txt"
t "modules: refuses streams without a vendor-sha256 pin" "out bash '$here/stage-modules.sh' '$VM' '$T/p2.txt' '$T/p1' | grep -q 'no single vendor-sha256 pin' && [[ ! -e $T/p1/modules.yaml ]]"
zcat "$VM" > "$T/vendor.yaml"; cp "$T/vendor.yaml" "$T/vendor2.yaml"; echo "# x" >> "$T/vendor2.yaml"
printf '%s\n' "php 8.3" "vendor-sha256 $(sha256sum "$T/vendor.yaml" | cut -d' ' -f1)" > "$T/p3.txt"
t "modules: refuses a changed vendor file (one byte) against its pin" "out bash '$here/stage-modules.sh' '$T/vendor2.yaml' '$T/p3.txt' '$T/p1' | grep -q 'has sha256' && [[ ! -e $T/p1/modules.yaml ]]"
# 10b awk post-check: YAML the one-pass cut does not understand is refused, not passed on
sed 's/^    8\.1: \[common\]$/    8.1:\n    - common/' "$T/vendor.yaml" > "$T/block.yaml"
printf '%s\n' "php 8.3" "vendor-sha256 $(sha256sum "$T/block.yaml" | cut -d' ' -f1)" > "$T/p4.txt"
t "fixture: block.yaml really has a block-style php profile" "grep -qx '    8.1:' '$T/block.yaml'"
t "modules post-check: refuses block-style profiles of an unlisted stream" "out bash '$here/stage-modules.sh' '$T/block.yaml' '$T/p4.txt' '$T/p1' | grep -q 'post-check' && [[ ! -e $T/p1/modules.yaml ]]"
awk '{print} /^  module: php$/{print "  intents:"; print "    desktop:"; print "      stream: 8.1"}' "$T/vendor.yaml" > "$T/intents.yaml"
printf '%s\n' "php 8.3" "vendor-sha256 $(sha256sum "$T/intents.yaml" | cut -d' ' -f1)" > "$T/p5.txt"
t "modules post-check: refuses defaults with intents" "out bash '$here/stage-modules.sh' '$T/intents.yaml' '$T/p5.txt' '$T/p1' | grep -q 'post-check.*intents' && [[ ! -e $T/p1/modules.yaml ]]"
t "modules post-check: the real vendor file passes (pinned, plain)" "bash '$here/stage-modules.sh' '$T/vendor.yaml' '$T/p3.txt' '$T/p1' >/dev/null && [[ -f $T/p1/modules.yaml ]]"
# 10c modular detection by the RPM RELEASE tag, not the file name
mkdir "$T/r1"; cp "$PHP" "$T/r1/renamed-php.rpm"
t "repodata: a modular RPM with a plain file name is still refused" "out bash '$here/make-repodata.sh' '$T/r1' | grep -q '1 modular RPM'"
mkdir "$T/r2"; cp "$PHP" "$T/r2/renamed-php.rpm"; printf '%s\n' "postgresql 16" "vendor-sha256 $PIN" > "$T/r2.txt"
t "modules: a renamed modular RPM outside the streams is still refused" "out bash '$here/stage-modules.sh' '$VM' '$T/r2.txt' '$T/r2' | grep -q 'not in any listed stream'"
createrepo_c --quiet "$T/r1"
t "verify: a renamed modular RPM without modules metadata fails" "out bash '$here/verify-repo.sh' '$T/r1' '$T/keys' | grep -q 'MISSING modules metadata (1 modular'"
# 10d verify: the RPM files equal primary.xml, and every repodata file matches its repomd checksum
cp -a "$T/out" "$T/w1"; cp "$T"/w1/google-authenticator-*.rpm "$T/w1/extra-copy.rpm"
t "verify: a signed RPM not listed in primary.xml fails" "out bash '$here/verify-repo.sh' '$T/w1' '$T/keys' | grep -q 'EXTRA RPM not in primary.xml: extra-copy.rpm'"
cp -a "$T/out" "$T/w2"; rm "$T"/w2/google-authenticator-*.rpm
t "verify: an RPM listed in primary.xml but missing fails" "out bash '$here/verify-repo.sh' '$T/w2' '$T/keys' | grep -q 'MISSING RPM listed in primary.xml: google-authenticator'"
cp -a "$T/out" "$T/w3"; f=$(ls "$T"/w3/repodata/*-other.xml.*); printf x >> "$f"
t "verify: a repodata file changed under a signed repomd fails" "out bash '$here/verify-repo.sh' '$T/w3' '$T/keys' | grep -q 'BAD repodata checksum: other'"
cp -a "$T/out" "$T/w4"; rm "$T"/w4/repodata/*-filelists.xml.*
t "verify: a repodata file listed in repomd but missing fails" "out bash '$here/verify-repo.sh' '$T/w4' '$T/keys' | grep -q 'MISSING repodata file: .*filelists'"
t "verify: the clean repo still passes (2 packages)" "bash '$here/verify-repo.sh' '$T/out' '$T/keys' | grep -q 'REPO OK: 2 packages'"
# 10e verify: the modules record (checksum, streams == MODULES.txt)
t "verify: the modular repo passes against its own stream list" "bash '$here/verify-repo.sh' '$T/m4out' '$T/k9' '$T/m1.txt' | grep -q 'REPO OK: 1 packages'"
t "verify: modules streams != the tools' MODULES.txt (php+postgresql) fails" "out bash '$here/verify-repo.sh' '$T/m4out' '$T/k9' '$here/MODULES.txt' | grep -q 'MODULES MISMATCH'"
t "verify: a repo without modules metadata fails against the tools' MODULES.txt" "out bash '$here/verify-repo.sh' '$T/out' '$T/keys' '$here/MODULES.txt' | grep -q 'MISSING modules metadata'"
cp -a "$T/m4out" "$T/w5"; f=$(ls "$T"/w5/repodata/*modules.yaml*); printf x >> "$f"
t "verify: a changed modules record fails its repomd checksum" "out bash '$here/verify-repo.sh' '$T/w5' '$T/k9' '$T/m1.txt' | grep -q 'BAD repodata checksum: modules'"
exit $fails
