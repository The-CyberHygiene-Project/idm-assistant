# ISO Plan 1: Signing Key, Signed Repo and the Third-Party/Collector RPMs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A YubiKey-held project signing key and a **signed, verified RPM repository**, version `0.1.0`, holding
Kanidm (FIPS TLS variant), step-ca/step-cli built from source, `idm-collect`, and EPEL's `google-authenticator`.
That repository is the foundation every later ISO plan installs from.

**Architecture:** The signing key is generated **on** the YubiKey (non-exportable). On aero, `rpmsign`/`gpg`
reach it only through the Mac's gpg-agent, forwarded over SSH for the length of one command. Packages are built
in the disposable **build1** VM (Kanidm, step) or on aero (noarch `idm-collect`). `sign-repo.sh` signs, builds
repodata and signs `repomd.xml` in a temporary copy, and the result appears only if `verify-repo.sh` passes
(all-or-nothing). An install test on the lab VMs shows that dnf enforces the signatures and that the FIPS-variant binaries work.

**Tech Stack:** GnuPG 2.5 (Mac) / 2.3 (aero), YubiKey 5 OpenPGP (RSA 3072), expect, rpm-sign 4.16, createrepo_c
0.20, Rust 1.96 (Kanidm, as Plan 2), an upstream Go toolchain from go.dev (step), bash test scripts in the repo's
`t()` style, pytest (collector).

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md` (§2 decisions, §3.1 units, §8 build and
release, §9 verifications, §12 plan 1). Requirements log: `lab/iso-requirements.md` (rows 1, 2, 13, 21, 23).

## Global Constraints

- The repo must work with `gpgcheck=1` **and** `repo_gpgcheck=1`. Every RPM carries a V4 RSA/SHA256 signature by a **pinned** key (row 1).
- The signing key lives **only** on the YubiKey. It is generated on-card, never exported, RSA 3072, SHA-256 digests, touch required to sign.
- Public-repo hygiene: never commit or print PINs, the YubiKey serial, or lab secrets. Run `bash lab/tools/secrets-scan.sh` before any push (its existing FAILs on `tests/test_redact.py` / `tests/test_repairs.py` dummy fixtures are known). The user pushes, or approves the push.
- **Never compile on appliance hosts** (row 2). Builds happen in build1 only. fapolicyd `permissive = 1` on build1 needs the **ISSO's (the user's) approval each time**, is ledgered in `lab/vm-deviations.md`, and is reverted with a **reboot**.
- Kanidm ships as the **AWS-LC FIPS TLS variant** for the server **and** unixd (ISSO #14).
- step-ca's unit sets `GODEBUG=fips140=on`. `fips140=only` is forbidden: step-ca 0.30.2 panics on MD5 at start (row 13).
- Nothing site-specific goes into shipped files: no `kanidm.lab.test` and no lab IPs in any RPM.
- Our own RPMs: `Vendor: The CyberHygiene Project`, Release suffix `.chp`, `License: Apache-2.0`. Third-party packages keep their upstream licence (Kanidm MPL-2.0, step Apache-2.0) and ship its licence file via `%license`.
- Product naming (`appliance/branding/README.md`): never "Rocky Linux …" as a name. Every shipped **script** starts with the three lines of `appliance/branding/file-header.txt`, right after the shebang.
- aero and the VMs never reach the internet. Internet fetches happen only on the Mac, and each is pinned by sha256 in a `MANIFEST.txt`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The user has limited vision and typing. Anything the user must run is **one short command**, e.g. `! bash ~/k1.sh` (stage long commands in a script at a short path). PINs are entered in pinentry-mac dialogs, never on a command line.

## Review Focus

1. **A stale forwarded agent socket on aero** (aero's sshd has `StreamLocalBindUnlink no`). The second signing session in a row silently gets no forward, aero's gpg says "No secret key", and the signature never happens. Expected: every session clears the socket first, so a second run works. Pinned by Task 2's back-to-back test.
2. **The YubiKey is unplugged or the touch times out mid-signing.** Expected: nothing is published, and there's no half-signed output directory. Pinned by Task 3's "signer key unavailable → no out-dir" test.
3. **An RPM signed by an unpinned key** (a stray upstream RPM, or a test key) reaching the stage. Expected: `sign-repo.sh` refuses it, and never re-signs over it. Pinned by Task 3.
4. **A hostile or garbled `KANIDM_URL` in the collector config** (shell metacharacters, `http://`, a path). Expected: the collector does not use it and reports an error field. Pinned by Task 4.
5. **The wrong vendor set or toolchain slipping into a build** (the non-FIPS Kanidm vendor tarball, `GOTOOLCHAIN=auto` fetching a different Go). Expected: the check scripts fail the build. Pinned by Task 5's `check-fips.sh` and Task 7's `check-step.sh`.

---

## File Structure

```
appliance/
  release/                       signing + repo tooling (Mac and aero)
    keygen.exp                   Mac: generate the signing key ON the YubiKey (expect, keyword-driven)
    RPM-GPG-KEY-cyberhygiene     public key (Task 1 output)
    RPM-GPG-KEY-EPEL-9           EPEL's public key (copied from ~/idm-lab-inputs, pinned)
    trusted-keys.txt             "<fingerprint> <label> <file>" per pinned key
    SIGNING-KEY.md               fingerprint, custody, touch policy, loss/rotation procedure
    push.sh                      Mac: copy appliance/release/* to aero:/data/chp-release/tools/
    sign-session.sh              Mac: run ONE command on aero with the YubiKey's agent forwarded
    test_sign_session.sh         Mac: back-to-back + negative checks (needs the YubiKey; touch)
    sign-repo.sh                 aero: stage → signed, verified repo (all-or-nothing)
    verify-repo.sh               aero/any EL9: pinned-key signatures on every RPM + repomd.xml.asc
    test_sign_repo.sh            aero: tests for the two above with throwaway software keys
    PACKAGES.txt                 package names that make up the 0.1.0 repo
    assemble-repo.sh             aero: newest RPM of each PACKAGES.txt name → stage dir
    RELEASE-RECORD-0.1.0.md      Task 8 output: NEVRAs, sha256s, signer, verify + install-test results
    CMVP-STATUS.md               Task 8 output: CMVP status of each crypto module (spec §9)
  inputs/
    fetch-step.sh                Mac: step sources + Go toolchains + vendored modules, pinned
    MANIFEST.txt                 file|version|bytes|sha256|source|how verified
    verify.sh                    any host: re-check files against MANIFEST.txt
  rpm/
    kanidm/                      FIPS-variant Kanidm packaging (copied from lab/kanidm-rpm, which stays as the Plan 2 record)
      build.sh  build-rpms.sh  kanidm.spec  check-rpms.sh  check-fips.sh
      expected-files.txt  expected-by-package.txt  units/*.service  BUILD-RECORD.md
    step/
      build.sh  smoke.sh  build-rpms.sh  step-ca.spec  step-cli.spec  step-ca.service  step-ca.sysusers
      check-step.sh  BUILD-RECORD.md
    idm-collect/
      idm-collect.spec  build-rpm.sh
collector/idm-collect            modified: /usr/sbin path, config-driven KANIDM_URL, file header
engine/remote.py                 modified: /usr/sbin/idm-collect
tests/test_collector_script.py   modified + new tests
lab/host/diag-access.sh          modified: installs the RPM, writes collect.conf, new sudo paths
lab/tools/readonly-proof.sh      modified: new path
LICENSE                          new: Apache-2.0 text
```

Why copy `lab/kanidm-rpm` instead of moving it: `lab/kanidm-rpm` + `BUILD-RECORD.md` are the record of what
Plan 2/3 tested; the product packaging now evolves separately.

---

### Task 1: The release signing key on the YubiKey (Mac)

**Files:**
- Create: `appliance/release/keygen.exp`, `appliance/release/RPM-GPG-KEY-cyberhygiene`,
  `appliance/release/RPM-GPG-KEY-EPEL-9`, `appliance/release/trusted-keys.txt`, `appliance/release/SIGNING-KEY.md`

**Interfaces:**
- Produces: `CHP_FPR`, the 40-hex fingerprint of the primary (signing) key, which is written in `trusted-keys.txt` with label
  `cyberhygiene` and the file `RPM-GPG-KEY-cyberhygiene`. Every later task reads the fingerprint from that file:
  `CHP_FPR=$(awk '$2=="cyberhygiene"{print $1}' appliance/release/trusted-keys.txt)`.

- [ ] **Step 1: pinentry-mac and a shared card reader.** The Mac has no GUI pinentry, and the forwarded agent (Task 2)
  has no terminal, so PINs must come from a dialog.
  ```bash
  brew install pinentry-mac
  grep -q '^pinentry-program' ~/.gnupg/gpg-agent.conf 2>/dev/null || echo "pinentry-program $(brew --prefix)/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf
  grep -qx pcsc-shared ~/.gnupg/scdaemon.conf 2>/dev/null || echo pcsc-shared >> ~/.gnupg/scdaemon.conf   # don't lock PIV/other apps out of the card
  gpgconf --kill gpg-agent scdaemon
  gpg --card-status | grep -E 'Signature key|Key attributes'
  ```
  Expected: `Signature key ....: [none]`.

- [ ] **Step 2: PINs are not the factory defaults.** Ask the user: "Have this YubiKey's OpenPGP PINs been changed from
  the defaults (123456 / 12345678)?" If not, stage `gpg --change-pin` in `~/k0.sh` (`#!/bin/sh` + that line) and ask the
  user to run `! sh ~/k0.sh`. They choose `1` (PIN), then `3` (Admin PIN), then `q`, entering values in the dialogs. **Never
  record the PINs.**

- [ ] **Step 3: Write `appliance/release/keygen.exp`.** It drives gpg's `--command-fd` protocol by prompt **keyword**
  and aborts on any keyword it does not know, so a gpg version change cannot answer the wrong question.
  ```tcl
  #!/usr/bin/expect -f
  # keygen.exp (RUNS ON THE MAC, once): generate the CyberHygiene release signing key ON the YubiKey's OpenPGP applet.
  # The secret key is created by the card and can never be exported. PINs are asked by pinentry-mac, never here.
  # Every gpg prompt arrives as "[GNUPG:] GET_LINE|GET_BOOL <keyword>"; unknown keywords abort (fail closed).
  set timeout 600
  array set answer {
    cardedit.genkeys.algo        1
    cardedit.genkeys.size        3072
    cardedit.genkeys.backup_enc  n
    cardedit.genkeys.replace_keys y
    keygen.valid                 2y
    keygen.valid.okay            y
    keygen.email                 ""
    keygen.userid.cmd            O
  }
  set answer(keygen.name)    "The CyberHygiene Project Release Signing"
  set answer(keygen.comment) "Lab Installer packages"
  set menu {admin key-attr generate quit}
  spawn gpg --command-fd 0 --status-fd 1 --card-edit
  expect {
    -re {\[GNUPG:\] GET_LINE cardedit\.prompt} {
      if {[llength $menu] == 0} { puts "\nABORT: card-edit prompted after quit"; exit 1 }
      send "[lindex $menu 0]\r"; set menu [lrange $menu 1 end]; exp_continue }
    -re {\[GNUPG:\] GET_(LINE|BOOL|HIDDEN) ([a-z._]+)} {
      set kw $expect_out(2,string)
      if {![info exists answer($kw)]} { puts "\nABORT: unexpected prompt '$kw' (nothing answered)"; exit 1 }
      send "$answer($kw)\r"; exp_continue }
    -re {\[GNUPG:\] KEY_CREATED \S+ ([0-9A-F]{40})} { set fpr $expect_out(1,string); exp_continue }
    timeout { puts "\nABORT: timed out"; exit 1 }
    eof
  }
  if {![info exists fpr]} { puts "\nFAILED: no key was created"; exit 1 }
  puts "\nKEY CREATED $fpr"
  ```

- [ ] **Step 4: The user runs it.** Stage `~/k1.sh` containing `expect ~/idm-assistant/appliance/release/keygen.exp`
  and ask the user to run `! sh ~/k1.sh`. They enter the **Admin PIN** (key-attr, three times, once per key slot) and the **PIN**
  (generate) in the dialogs. Card generation of 3 × RSA 3072 takes several minutes.
  Expected: the last line is `KEY CREATED <40 hex>`. If it prints `ABORT: unexpected prompt 'X'`, add `X` with the
  correct answer to `answer` (read gpg's question in the transcript), then re-run. `replace_keys y` handles the
  partially generated case.

- [ ] **Step 5: Require a touch for every signature.** Stage `~/k2.sh` = `ykman openpgp keys set-touch sig on -f`
  (it prompts for the Admin PIN in the terminal) and ask the user to run `! sh ~/k2.sh`. Check:
  `ykman openpgp info | grep -A1 -i 'signature'` shows `Touch policy: On`.

- [ ] **Step 6: Export and pin the public keys.**
  ```bash
  cd ~/idm-assistant/appliance/release
  FPR=$(gpg --card-status --with-colons | awk -F: '/^fpr/{print $2; exit}')
  [[ $FPR =~ ^[0-9A-F]{40}$ ]] || { echo "no signature key fingerprint on the card"; exit 1; }
  gpg --armor --export "$FPR" > RPM-GPG-KEY-cyberhygiene
  cp ~/idm-lab-inputs/RPM-GPG-KEY-EPEL-9 .
  printf '%s\n' "# <fingerprint> <label> <file>: the ONLY keys a CyberHygiene repo may carry signatures from" \
    "$FPR cyberhygiene RPM-GPG-KEY-cyberhygiene" \
    "FF8AD1344597106ECE813B918A3872BF3228467C epel9 RPM-GPG-KEY-EPEL-9" > trusted-keys.txt
  for f in RPM-GPG-KEY-cyberhygiene RPM-GPG-KEY-EPEL-9; do
    gpg --with-colons --import-options show-only --import "$f" | awk -F: '/^fpr/{print $10; exit}'
  done
  ```
  Expected: the two printed fingerprints equal the two in `trusted-keys.txt` (the EPEL one matches the pin already in
  `lab/inputs/MANIFEST.txt`).

- [ ] **Step 7: A signature round-trip on the Mac.**
  `echo test > /tmp/k.txt && gpg -u "$FPR" --detach-sign --armor -o /tmp/k.txt.asc /tmp/k.txt && gpg --verify /tmp/k.txt.asc /tmp/k.txt; rm -f /tmp/k.txt*`
  The YubiKey blinks and the user touches it. Expected: `Good signature from "The CyberHygiene Project Release Signing (Lab Installer packages)"`.

- [ ] **Step 8: Write `appliance/release/SIGNING-KEY.md`.** Its contents, filled in from Steps 4–7:
  - fingerprint (`$FPR`), algorithm RSA 3072, created date, expiry (2 years from creation)
  - custody: "generated on-card on the System Owner's YubiKey 5 NFC; not exportable; no backup copy exists". Do **not** record the serial.
  - touch policy On. Expect **two touches per RPM** (rpm 4.16 adds a header and a header+payload signature) and one for `repomd.xml`.
  - **Expiry:** before the expiry date, extend it on-card with `gpg --quick-set-expire $FPR 2y`, re-export, re-commit.
  - **Loss or compromise:** generate a new key (Tasks 1.3–1.7), replace the `cyberhygiene` line in `trusted-keys.txt`,
    rebuild and re-sign the repo and ISO, and tell every site to re-pin. There is no revocation certificate
    for an on-card key without a backup: record that as accepted for the dev-team phase.

- [ ] **Step 9: Commit.**
  ```bash
  git add appliance/release/{keygen.exp,RPM-GPG-KEY-cyberhygiene,RPM-GPG-KEY-EPEL-9,trusted-keys.txt,SIGNING-KEY.md}
  git commit -m "ISO Plan 1 Task 1: release signing key generated on the YubiKey (RSA 3072, touch); public keys pinned

  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
  ```

---

### Task 2: A signing session on aero with the YubiKey forwarded

**Files:**
- Create: `appliance/release/push.sh`, `appliance/release/sign-session.sh`, `appliance/release/test_sign_session.sh`

**Interfaces:**
- Consumes: `trusted-keys.txt`, `RPM-GPG-KEY-cyberhygiene` (Task 1).
- Produces: `appliance/release/sign-session.sh '<one shell command string>'`, which runs the command on aero (as `itadmin`)
  with gpg able to sign with `CHP_FPR`, and exits with the command's status. `appliance/release/push.sh` copies the
  release tools to `aero:/data/chp-release/tools/`.

- [ ] **Step 1: Create the release area on aero (once).**
  `ssh aero 'sudo install -d -o itadmin -g itadmin -m 0755 /data/chp-release /data/chp-release/tools'`

- [ ] **Step 2: Write `appliance/release/push.sh`.**
  ```bash
  #!/usr/bin/env bash
  # push.sh (RUNS ON THE MAC): copy the release tools and pinned keys to aero:/data/chp-release/tools/.
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"
  shopt -s nullglob
  scp -q "$here"/*.sh "$here"/RPM-GPG-KEY-* "$here"/trusted-keys.txt "$here"/PACKAGES*.txt aero:/data/chp-release/tools/
  echo "pushed to aero:/data/chp-release/tools/"
  ```

- [ ] **Step 3: Write the failing test `appliance/release/test_sign_session.sh`.**
  ```bash
  #!/usr/bin/env bash
  # test_sign_session.sh (RUNS ON THE MAC; YubiKey plugged in; touch it when it blinks, twice).
  set -uo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; fails=0
  t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
  FPR=$(awk '$2=="cyberhygiene"{print $1}' "$here/trusted-keys.txt")
  cmd="echo sign-session-test > /tmp/ss.txt && gpg --batch --yes -u $FPR --detach-sign --armor -o /tmp/ss.txt.asc /tmp/ss.txt && gpg --verify /tmp/ss.txt.asc /tmp/ss.txt 2>&1 | grep -q 'Good signature'"
  t "aero signs through the forwarded agent"            "bash '$here/sign-session.sh' \"$cmd\""
  t "a second session right after also works (stale socket cleared)" "bash '$here/sign-session.sh' \"$cmd\""
  t "without a session aero cannot sign (the key is not on aero)" \
    "! ssh aero 'gpg --batch --yes -u $FPR --detach-sign -o /tmp/ss2.sig /tmp/ss.txt' >/dev/null 2>&1"
  t "no forwarded socket is left behind" "! ssh aero 'test -S \$(gpgconf --list-dir agent-socket)'"
  ssh aero 'rm -f /tmp/ss.txt /tmp/ss.txt.asc /tmp/ss2.sig'
  exit $fails
  ```
  Run: `bash appliance/release/test_sign_session.sh`. Expected: FAIL (`sign-session.sh` does not exist).

- [ ] **Step 4: Write `appliance/release/sign-session.sh`.**
  ```bash
  #!/usr/bin/env bash
  # sign-session.sh '<command>' (RUNS ON THE MAC): run ONE command on aero with this Mac's gpg-agent (and so the
  # YubiKey) forwarded as aero's agent socket. The secret key never leaves the card; aero has the socket only while
  # the command runs. aero's sshd has StreamLocalBindUnlink=no, so a leftover socket would silently break the
  # forward: it is removed before and after. aero's gpg is told never to start a local agent (it has no key).
  set -Eeuo pipefail
  H=${SIGN_HOST:-aero}
  here="$(cd "$(dirname "$0")" && pwd)"
  [[ $# -eq 1 ]] || { echo "usage: sign-session.sh '<command>'"; exit 2; }
  gpg --card-status >/dev/null 2>&1 || { echo "YubiKey not found: plug it in"; exit 1; }
  local_sock=$(gpgconf --list-dir agent-extra-socket)
  gpg-connect-agent /bye >/dev/null 2>&1
  remote_sock=$(ssh "$H" 'gpgconf --create-socketdir 2>/dev/null; gpgconf --list-dir agent-socket')
  ssh "$H" "mkdir -p -m 700 ~/.gnupg; grep -qx no-autostart ~/.gnupg/gpg.conf 2>/dev/null || echo no-autostart >> ~/.gnupg/gpg.conf; gpgconf --kill gpg-agent 2>/dev/null || true; rm -f '$remote_sock'"
  ssh "$H" 'gpg --batch --quiet --import 2>/dev/null' < "$here/RPM-GPG-KEY-cyberhygiene"
  set +e
  ssh -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -R "$remote_sock:$local_sock" "$H" "$1"
  rc=$?
  set -e
  ssh "$H" "rm -f '$remote_sock'"
  exit $rc
  ```

- [ ] **Step 5: Run the test.** `bash appliance/release/test_sign_session.sh`. The user touches the key twice (a PIN dialog
  appears on the first signature). Expected: 4 × PASS.
  If "aero signs" fails with `No secret key`, check on aero that `gpg-connect-agent 'keyinfo --list' /bye` lists
  the card key while a session is open (`sign-session.sh 'gpg-connect-agent "keyinfo --list" /bye'`).

- [ ] **Step 6: Commit.**
  `git add appliance/release/{push.sh,sign-session.sh,test_sign_session.sh} && git commit -m "ISO Plan 1 Task 2: signing session on aero via forwarded YubiKey agent (stale-socket safe)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`

---

### Task 3: `sign-repo.sh` and `verify-repo.sh` (TDD with throwaway keys)

**Files:**
- Create: `appliance/release/verify-repo.sh`, `appliance/release/sign-repo.sh`, `appliance/release/test_sign_repo.sh`

**Interfaces:**
- Consumes: `trusted-keys.txt` format (Task 1); `sign-session.sh` (Task 2) for the real run.
- Produces:
  - `verify-repo.sh <repo-dir> <keys-dir>` exits 0 and prints `REPO OK: <n> packages …` only if every `*.rpm` carries a
    `Header V4 RSA/SHA256 Signature` that verifies against a key in `<keys-dir>/trusted-keys.txt`, each key file's
    fingerprint equals its pin, and `repodata/repomd.xml.asc` is a valid signature by the `cyberhygiene` key.
    Otherwise it prints one line per problem and exits 1.
  - `sign-repo.sh <stage-dir> <out-dir> <signer-fpr> <keys-dir>` signs unsigned RPMs, keeps pinned third-party
    signatures, refuses unpinned ones, builds and signs repodata, verifies, and only then creates `<out-dir>`.

- [ ] **Step 1: Write the failing test `appliance/release/test_sign_repo.sh`** (it runs on aero, and needs no YubiKey).
  ```bash
  #!/usr/bin/env bash
  # test_sign_repo.sh (RUNS ON AERO): sign-repo.sh / verify-repo.sh with THROWAWAY software keys in a temp GNUPGHOME.
  # Fixtures: an unsigned lab RPM and EPEL's signed google-authenticator from /data/lab-inputs/rpms.
  set -uo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; fails=0
  t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
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
  t "refuses an RPM signed by an unpinned key"        "bash '$here/sign-repo.sh' '$T/stage2' '$T/out2' '$A' '$T/keys' 2>&1 | grep -q REFUSED"
  t "…and creates no out-dir"                         "[[ ! -e $T/out2 ]]"
  # 3 signer unavailable mid-run (Review Focus 2): a fingerprint with no secret key
  t "fails when the signer key is unavailable"        "! bash '$here/sign-repo.sh' '$T/stage' '$T/out3' 0000000000000000000000000000000000000000 '$T/keys' >/dev/null 2>&1"
  t "…and creates no out-dir"                         "[[ ! -e $T/out3 ]]"
  t "…and leaves no temp dir behind"                  "! ls -d '$T'/.sign.* >/dev/null 2>&1"
  # 4 verify-repo negatives
  cp -a "$T/out" "$T/v1"; cp "$FIX"/kanidm-server-1.11.2-1.lab.el9.x86_64.rpm "$T/v1/"
  t "verify: an unsigned RPM added later fails"       "bash '$here/verify-repo.sh' '$T/v1' '$T/keys' | grep -q 'BAD SIGNATURE: kanidm-server'"
  cp -a "$T/out" "$T/v2"; echo '<!-- x -->' >> "$T/v2/repodata/repomd.xml"
  t "verify: edited repomd.xml fails"                  "bash '$here/verify-repo.sh' '$T/v2' '$T/keys' | grep -q 'BAD repomd signature'"
  cp -a "$T/out" "$T/v3"; rm "$T/v3/repodata/repomd.xml.asc"
  t "verify: missing repomd.xml.asc fails"             "bash '$here/verify-repo.sh' '$T/v3' '$T/keys' | grep -q 'MISSING repomd.xml.asc'"
  cp -a "$T/out" "$T/v4"; gpg --batch --yes -u "$B" --armor --detach-sign -o "$T/v4/repodata/repomd.xml.asc" "$T/v4/repodata/repomd.xml"
  t "verify: repomd signed by another key fails"      "bash '$here/verify-repo.sh' '$T/v4' '$T/keys' | grep -q 'BAD repomd signature'"
  cp -a "$T/keys" "$T/k5"; sed -i "s/^$A /${B} /" "$T/k5/trusted-keys.txt"
  t "verify: a key file that doesn't match its pin fails" "bash '$here/verify-repo.sh' '$T/out' '$T/k5' | grep -q 'KEY MISMATCH'"
  mkdir -p "$T/v6/repodata"
  t "verify: an empty repo fails"                     "bash '$here/verify-repo.sh' '$T/v6' '$T/keys' | grep -q 'no RPMs'"
  exit $fails
  ```
  Run: `bash appliance/release/push.sh && ssh aero 'bash /data/chp-release/tools/test_sign_repo.sh'`.
  Expected: FAILs (the scripts don't exist yet).

- [ ] **Step 2: Write `appliance/release/verify-repo.sh`.**
  ```bash
  #!/usr/bin/env bash
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  # verify-repo.sh <repo-dir> <keys-dir>: every RPM carries a V4 RSA/SHA256 header signature by a PINNED key
  # (<keys-dir>/trusted-keys.txt: "<fpr> <label> <file>"), and repodata/repomd.xml.asc is valid and made by the
  # 'cyberhygiene' key. Prints one line per problem; exit 1 on any.
  set -Eeuo pipefail
  R=$1; K=$2
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  export GNUPGHOME=$tmp/gnupg; mkdir -m 700 "$GNUPGHOME"
  rpm --dbpath "$tmp/rpmdb" --initdb
  bad=0; say() { echo "$*"; bad=1; }
  chp=""
  while read -r fpr label file; do
    [[ -z ${fpr:-} || $fpr == \#* ]] && continue
    got=$(gpg --batch --with-colons --import-options show-only --import "$K/$file" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
    [[ $got == "$fpr" ]] || { echo "KEY MISMATCH: $file is ${got:-unreadable}, pinned $fpr"; exit 1; }
    gpg --batch --quiet --import "$K/$file" 2>/dev/null
    rpm --dbpath "$tmp/rpmdb" --import "$K/$file"
    [[ $label == cyberhygiene ]] && chp=$fpr
  done < "$K/trusted-keys.txt"
  [[ -n $chp ]] || { echo "NO cyberhygiene key pinned in $K/trusted-keys.txt"; exit 1; }
  shopt -s nullglob; n=0
  for f in "$R"/*.rpm; do
    n=$((n + 1))
    out=$(rpm --dbpath "$tmp/rpmdb" -Kv "$f" 2>&1 || true)
    if ! grep -q 'Header V4 RSA/SHA256 Signature, key ID [0-9a-f]*: OK' <<<"$out" || grep -qE 'NOKEY|NOT OK|BAD' <<<"$out"; then
      say "BAD SIGNATURE: $(basename "$f")"
    fi
  done
  (( n > 0 )) || say "no RPMs in $R"
  if [[ ! -f $R/repodata/repomd.xml.asc ]]; then say "MISSING repomd.xml.asc"
  elif ! gpg --batch --status-fd 1 --verify "$R/repodata/repomd.xml.asc" "$R/repodata/repomd.xml" 2>/dev/null \
         | grep -qE "^\[GNUPG:\] VALIDSIG .* $chp\$"; then
    say "BAD repomd signature (must be by $chp)"
  fi
  (( bad == 0 )) || exit 1
  echo "REPO OK: $n packages, all signed by pinned keys; repomd.xml signed by $chp"
  ```

- [ ] **Step 3: Write `appliance/release/sign-repo.sh`.**
  ```bash
  #!/usr/bin/env bash
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  # sign-repo.sh <stage-dir> <out-dir> <signer-fpr> <keys-dir>: sign every UNSIGNED RPM of stage-dir with signer-fpr,
  # keep signatures by pinned third-party keys (e.g. EPEL) as they are, REFUSE anything signed by an unpinned key,
  # build repodata, sign repomd.xml, verify. Works in a temp copy next to out-dir; out-dir appears only when all of it
  # passed (all-or-nothing: an unplugged YubiKey or a missed touch leaves nothing half-signed). stage-dir is unchanged.
  set -Eeuo pipefail
  S=$1; O=$2; FPR=$3; K=$4
  here="$(cd "$(dirname "$0")" && pwd)"
  [[ -e $O ]] && { echo "refusing: $O already exists"; exit 1; }
  mkdir -p "$(dirname "$O")"
  work=$(mktemp -d "$(dirname "$O")/.sign.XXXXXX"); db=$(mktemp -d)
  trap 'rm -rf "$work" "$db"' EXIT
  rpm --dbpath "$db" --initdb
  while read -r fpr _label file; do
    [[ -z ${fpr:-} || $fpr == \#* ]] && continue
    rpm --dbpath "$db" --import "$K/$file"
  done < "$K/trusted-keys.txt"
  shopt -s nullglob
  rpms=("$S"/*.rpm); (( ${#rpms[@]} )) || { echo "no RPMs in $S"; exit 1; }
  cp -a "${rpms[@]}" "$work/"
  to_sign=()
  for f in "$work"/*.rpm; do
    out=$(rpm --dbpath "$db" -Kv "$f" 2>&1 || true)
    if grep -q 'Signature, key ID' <<<"$out"; then
      grep -qE 'NOKEY|NOT OK|BAD' <<<"$out" && { echo "REFUSED: $(basename "$f") is signed by an unpinned key or is damaged"; exit 1; }
    else
      to_sign+=("$f")
    fi
  done
  if (( ${#to_sign[@]} )); then
    rpmsign --addsign --define "_gpg_name $FPR" --define "_gpg_digest_algo sha256" "${to_sign[@]}"
  fi
  createrepo_c --quiet "$work"
  gpg --batch --yes --local-user "$FPR" --armor --detach-sign -o "$work/repodata/repomd.xml.asc" "$work/repodata/repomd.xml"
  bash "$here/verify-repo.sh" "$work" "$K"
  chmod 0755 "$work"
  mv "$work" "$O"
  trap 'rm -rf "$db"' EXIT
  echo "SIGNED REPO: $O"
  ```

- [ ] **Step 4: Run the tests.** `bash appliance/release/push.sh && ssh aero 'bash /data/chp-release/tools/test_sign_repo.sh'`.
  Expected: all PASS. (All signature queries use the header signature, `RSAHEADER`, which is what rpm 4.16 and
  `verify-repo.sh` check.)

- [ ] **Step 5: A real run through the YubiKey.** It proves that `rpmsign` works through the forwarded agent.
  ```bash
  bash appliance/release/push.sh
  FPR=$(awk '$2=="cyberhygiene"{print $1}' appliance/release/trusted-keys.txt)
  ssh aero 'rm -rf /data/chp-release/yk-test && mkdir -p /data/chp-release/yk-test/stage && cp /data/lab-inputs/rpms/kanidm-clients-1.11.2-1.lab.el9.x86_64.rpm /data/chp-release/yk-test/stage/'
  bash appliance/release/sign-session.sh "bash /data/chp-release/tools/sign-repo.sh /data/chp-release/yk-test/stage /data/chp-release/yk-test/out $FPR /data/chp-release/tools"
  ssh aero 'rm -rf /data/chp-release/yk-test'
  ```
  The user touches the key about 3 times. Expected: `REPO OK: 1 packages …` then `SIGNED REPO: …`.

- [ ] **Step 6: Commit.** `git add appliance/release/{verify-repo.sh,sign-repo.sh,test_sign_repo.sh}` and commit
  `ISO Plan 1 Task 3: sign-repo (all-or-nothing, pinned third-party keys kept, unpinned refused) + verify-repo; tests` with the Co-Authored-By line.

---

### Task 4: `idm-collect` as an RPM (config-driven URL, /usr/sbin), and the repo licence

**Files:**
- Create: `LICENSE` (the Apache-2.0 text), `appliance/rpm/idm-collect/idm-collect.spec`, `appliance/rpm/idm-collect/build-rpm.sh`
- Modify: `collector/idm-collect` (header, redact path, `# >>> kanidm-url` block), `engine/remote.py:14`,
  `tests/test_collector_script.py`, `lab/host/diag-access.sh`, `lab/tools/readonly-proof.sh:16`

**Interfaces:**
- Produces:
  - `/usr/sbin/idm-collect [--user NAME]`, which reads `KANIDM_URL=` from `/etc/idm-collect/collect.conf` (root: always
    that file; non-root tests may set `IDM_COLLECT_CONF`), with rules at `/usr/share/idm-collect/redact.sed`
  - `engine.remote.collect()` calls `sudo -n /usr/sbin/idm-collect`
  - an RPM `idm-collect-0.1.0-1.chp.el9.noarch.rpm`
- The `diag` sudo rule keeps `--user *` for the lab. Plan 4 settles the appliance's rule against ISSO #22 (see the note at the end).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_collector_script.py`, and change the existing path assertion).
  ```python
  def test_root_always_uses_the_installed_rules():
      assert _redact_path(0) == "/usr/share/idm-collect/redact.sed"


  def _kanidm_url(conf_text, uid=1000):
      import tempfile, os
      lines = SCRIPT.read_text().splitlines()
      i, j = lines.index("# >>> kanidm-url"), lines.index("# <<< kanidm-url")
      with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
          f.write(conf_text)
      try:
          sh = f'id() {{ echo {uid}; }}\nIDM_COLLECT_CONF={f.name}\n' + "\n".join(lines[i + 1:j]) + '\necho "$KANIDM_URL"'
          return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()
      finally:
          os.unlink(f.name)


  def test_kanidm_url_comes_from_the_config():
      assert _kanidm_url("KANIDM_URL=https://idm.example.test\n") == "https://idm.example.test"


  def test_kanidm_url_allows_a_port():
      assert _kanidm_url("KANIDM_URL=https://idm.example.test:8443\n") == "https://idm.example.test:8443"


  def test_kanidm_url_last_assignment_wins():
      assert _kanidm_url("KANIDM_URL=https://a.test\nKANIDM_URL=https://b.test\n") == "https://b.test"


  import pytest


  @pytest.mark.parametrize("bad", [
      "KANIDM_URL=http://idm.example.test",            # not TLS
      "KANIDM_URL=https://idm.example.test/v1",        # a path
      "KANIDM_URL=https://x.test;touch /tmp/pwn",      # shell metacharacters
      "KANIDM_URL=https://$(id).test",                 # command substitution text
      "KANIDM_URL=https://IDM.EXAMPLE.TEST",           # upper case: not the form we write
      "KANIDM_URL=",                                   # empty
      "",                                              # missing
  ])
  def test_kanidm_url_rejects_anything_else(bad):
      assert _kanidm_url(bad + "\n") == ""


  def test_root_always_reads_the_installed_config():
      # as root the installed config is used whatever the environment says (same rule as redact.sed)
      lines = SCRIPT.read_text().splitlines()
      i, j = lines.index("# >>> kanidm-url"), lines.index("# <<< kanidm-url")
      sh = 'id() { echo 0; }\nIDM_COLLECT_CONF=/tmp/evil.conf\n' + "\n".join(lines[i + 1:j]) + '\necho "$CONF"'
      out = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()
      assert out == "/etc/idm-collect/collect.conf"


  def test_no_site_value_is_baked_in():
      assert "kanidm.lab.test" not in SCRIPT.read_text()


  def test_shipped_script_carries_the_file_header():
      head = SCRIPT.read_text().splitlines()[1:4]
      assert head == [
          "# CyberHygiene Project Lab Installer — based on Rocky Linux 9.",
          "# Not an official Rocky Linux product.",
          "# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.",
      ]
  ```
  Run: `uv run pytest tests/test_collector_script.py -q`. Expected: FAIL (no `kanidm-url` block; wrong path; no header).

- [ ] **Step 2: Change the collector.** In `collector/idm-collect`:
  - insert the three `file-header.txt` lines directly after `#!/bin/sh`
  - in the comment and the redact-path block, replace `/usr/local/sbin/idm-collect.redact.sed` with `/usr/share/idm-collect/redact.sed` (both places)
  - replace the line `KANIDM_URL=https://idm.kanidm.lab.test` with:
  ```sh
  # >>> kanidm-url
  # The Kanidm URL is site data (/etc/idm-collect/collect.conf, written by the client role), never baked in. Only
  # https://<lower-case host>[:port] is accepted; anything else leaves it empty and the Kanidm checks report an error.
  if [ "$(id -u)" -eq 0 ]; then CONF=/etc/idm-collect/collect.conf; else CONF="${IDM_COLLECT_CONF:-/etc/idm-collect/collect.conf}"; fi
  KANIDM_URL=$(sed -n 's/^KANIDM_URL=//p' "$CONF" 2>/dev/null | tail -n 1)
  case "$KANIDM_URL" in
    https://*) _h=${KANIDM_URL#https://}
               case "$_h" in ''|*[!a-z0-9.:-]*|:*|*:) KANIDM_URL="" ;; esac ;;
    *) KANIDM_URL="" ;;
  esac
  # <<< kanidm-url
  ```
  - right after `err()` is defined, add
    `[ -n "$KANIDM_URL" ] || err "collect.conf: KANIDM_URL missing or invalid (want https://host[:port])"`, and guard the
    Kanidm `curl` at the `$KANIDM_URL/v1/person/$user` call with `[ -n "$KANIDM_URL" ] &&`, so an empty URL never
    produces a request to `/v1/...`.

- [ ] **Step 3: Update `engine/remote.py:14`** to `argv = ["sudo", "-n", "/usr/sbin/idm-collect"] + …`, and
  `lab/tools/readonly-proof.sh:16` to `/usr/sbin/idm-collect`.

- [ ] **Step 4: Run the tests.** `uv run pytest -q`. Expected: all pass (244 + the new ones).

- [ ] **Step 5: Add `LICENSE`** (Apache-2.0, the official text):
  `curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE && head -3 LICENSE`. Expected: the first line is
  `Apache License`, then `Version 2.0, January 2004`.

- [ ] **Step 6: Write `appliance/rpm/idm-collect/idm-collect.spec`.**
  ```
  Name:           idm-collect
  Version:        0.1.0
  Release:        1.chp%{?dist}
  Summary:        Read-only identity diagnostics collector (The CyberHygiene Project)
  License:        Apache-2.0
  Vendor:         The CyberHygiene Project
  URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
  BuildArch:      noarch
  Source0:        idm-collect
  Source1:        redact.sed
  Source2:        LICENSE
  Requires:       curl, sed, gawk, openssl, chrony, openssh-server, authselect, policycoreutils, audit, glibc-common

  %description
  idm-collect prints one idm-report/1 JSON document describing the identity stack (Kanidm, unixd, step-ca trust,
  SSH CA, sshd, SELinux, time). It changes nothing on the host; secrets are redacted before output.
  Site data (the Kanidm URL) is read from /etc/idm-collect/collect.conf.

  %install
  install -Dm0755 %{SOURCE0} %{buildroot}%{_sbindir}/idm-collect
  install -Dm0644 %{SOURCE1} %{buildroot}%{_datadir}/idm-collect/redact.sed
  install -dm0700 %{buildroot}%{_sysconfdir}/idm-collect
  install -Dm0644 %{SOURCE2} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

  %files
  %license %{_datadir}/licenses/%{name}/LICENSE
  %{_sbindir}/idm-collect
  %dir %{_datadir}/idm-collect
  %{_datadir}/idm-collect/redact.sed
  %dir %attr(0700,root,root) %{_sysconfdir}/idm-collect

  %changelog
  * Tue Sep 29 2026 The CyberHygiene Project - 0.1.0-1.chp
  - First packaged release: /usr/sbin path, config-driven Kanidm URL.
  ```
  (`step` and `kanidm-unix` are used when present and are deliberately not `Requires:`: the collector runs on
  hosts without them and reports what's missing.)

- [ ] **Step 7: Write `appliance/rpm/idm-collect/build-rpm.sh`** (runs on the Mac and builds on aero; noarch, no compiler).
  ```bash
  #!/usr/bin/env bash
  # build-rpm.sh (RUNS ON THE MAC): build idm-collect's noarch RPM on aero into /data/chp-release/built/.
  set -Eeuo pipefail
  top="$(cd "$(dirname "$0")/../../.." && pwd)"
  ssh aero 'rm -rf /tmp/idmc && mkdir -p /tmp/idmc/SOURCES /tmp/idmc/SPECS /data/chp-release/built'
  scp -q "$top/collector/idm-collect" "$top/collector/redact.sed" "$top/LICENSE" aero:/tmp/idmc/SOURCES/
  scp -q "$top/appliance/rpm/idm-collect/idm-collect.spec" aero:/tmp/idmc/SPECS/
  ssh aero 'rpmbuild -bb --define "_topdir /tmp/idmc" /tmp/idmc/SPECS/idm-collect.spec >/tmp/idmc/build.log 2>&1 || { tail -20 /tmp/idmc/build.log; exit 1; }
            cp /tmp/idmc/RPMS/noarch/idm-collect-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/idm-collect-*.rpm && rm -rf /tmp/idmc'
  ```
  Run it. Expected: the file list shows `/usr/sbin/idm-collect`, `/usr/share/idm-collect/redact.sed`, `/etc/idm-collect`
  and the licence.

- [ ] **Step 8: Change `lab/host/diag-access.sh`** so it installs the RPM and writes the config instead of copying the
  script. Keep the account, key and sudoers parts as they are, with the new paths.
  - Mac side: `scp -q aero:/data/chp-release/built/idm-collect-0.1.0-1.chp.el9.noarch.rpm /tmp/` once before the loop,
    then `scp -q /tmp/idm-collect-0.1.0-1.chp.el9.noarch.rpm "$K.pub" "$h:/tmp/"` per host.
  - Remote side: replace the two `install … /usr/local/sbin/…` lines and the `restorecon -R /usr/local/sbin` with
    ```bash
    rm -f /usr/local/sbin/idm-collect /usr/local/sbin/idm-collect.redact.sed
    dnf -y -q install /tmp/idm-collect-0.1.0-1.chp.el9.noarch.rpm
    printf 'KANIDM_URL=https://idm.kanidm.lab.test\n' > /etc/idm-collect/collect.conf
    chmod 0644 /etc/idm-collect/collect.conf
    restorecon -R /home/diag /etc/idm-collect
    ```
    Delete the `install -d … /etc/idm-collect` line (the RPM owns it), and change the sudo rule to
    `diag ALL=(root) NOPASSWD: /usr/sbin/idm-collect, /usr/sbin/idm-collect --user *`.
  - Change the cleanup `rm -f` to remove `/tmp/idm-collect-0.1.0-1.chp.el9.noarch.rpm` instead of the script and sed file.
  - Change the header comment to name `/usr/sbin/idm-collect (RPM)`.

- [ ] **Step 9: Install on the lab hosts, prove read-only, check fapolicyd.**
  ```bash
  lab/host/diag-access.sh srv1 client2
  lab/tools/readonly-proof.sh srv1 --user lab02 && lab/tools/readonly-proof.sh client2 --user lab02
  for h in srv1 client2; do ssh $h 'sudo ausearch -m FANOTIFY -ts recent 2>/dev/null | grep -c idm-collect || true'; done
  ```
  Expected: both proofs report no file changes, and 0 fapolicyd denials (the RPM-installed script is trusted).
  `uv run python -m engine collect srv1 --user lab02` returns a report whose `errors` has no `collect.conf` entry.

- [ ] **Step 10: Re-take golden and confirm.** The lab hosts now carry the RPM, so the golden snapshots must be re-taken
  or every regression reset would bring back the old `/usr/local` script.
  ```bash
  bash lab/reset.sh                   # back to the current golden, then re-install on top
  lab/host/diag-access.sh srv1 client2
  for v in srv1 client2; do ssh aero "sudo virsh snapshot-delete $v golden && sudo virsh snapshot-create-as $v golden 'Plan ISO-1: idm-collect RPM'"; done
  IDM_TEST_APPROVE=1 uv run python -m engine regress --runs 1 --out lab/plan7/regression-iso1-collector-$(date +%F).md
  ```
  Expected: **11/11 GREEN** (about 25 min). If any scenario is not green, stop and debug with
  superpowers:systematic-debugging before continuing.

- [ ] **Step 11: Commit.** Add `LICENSE`, `appliance/rpm/idm-collect/`, `collector/idm-collect`, `engine/remote.py`,
  `tests/test_collector_script.py`, `lab/host/diag-access.sh`, `lab/tools/readonly-proof.sh` and the regression report.
  Message: `ISO Plan 1 Task 4: idm-collect RPM (/usr/sbin, config-driven KANIDM_URL, file header); Apache-2.0 LICENSE; golden re-taken; regression 11/11`.

**Note for the user, carried to Plan 4 (not a blocker here):** ISSO #22 approved "exactly `sudo -n /usr/bin/idm-collect`
with no arguments", but the engine passes `--user NAME` for user-specific checks, and the lab rule allows `--user *`.
Plan 4 must choose between two options: (a) an SSH forced-command gate that accepts only `idm-collect [--user <[a-z0-9_]+>]`, with sudoers
allowing that shape, or (b) no `--user` on appliance hosts.

---

### Task 5: Kanidm FIPS-variant RPMs (build1)

**Files:**
- Create: `appliance/rpm/kanidm/{build.sh,build-rpms.sh,kanidm.spec,check-rpms.sh,check-fips.sh,expected-files.txt,expected-by-package.txt,BUILD-RECORD.md}`,
  `appliance/rpm/kanidm/units/*.service` (copied from `lab/kanidm-rpm/units/`)

**Interfaces:**
- Consumes: `~/idm-lab-inputs/kanidm-1.11.2.tar.gz` and `kanidm-1.11.2-fips-vendor.tar.gz` (pinned in `lab/inputs/MANIFEST.txt`);
  build1 with Rust at `/opt/rust-1.96`.
- Produces: `kanidm-{server,clients,unixd}-1.11.2-2.chp.el9.x86_64.rpm` in `aero:/data/chp-release/built/`.

- [ ] **Step 1: Copy the packaging.**
  `mkdir -p appliance/rpm/kanidm && cp -a lab/kanidm-rpm/{kanidm.spec,build-rpms.sh,check-rpms.sh,expected-files.txt,expected-by-package.txt,units} appliance/rpm/kanidm/`

- [ ] **Step 2: Write the failing check `appliance/rpm/kanidm/check-fips.sh`** (Review Focus 5).
  ```bash
  #!/usr/bin/env bash
  # Runs ON build1: the TLS-carrying binaries in THIS spec's RPMs must contain the AWS-LC FIPS module (ISSO #14:
  # server AND unixd). Extracts from the RPMs, not from the build tree: we check what ships.
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; D="${1:-$HOME/rpmbuild/RPMS/x86_64}"
  VR=$(rpmspec -q --qf '%{version}-%{release}\n' "$here/kanidm.spec" 2>/dev/null | head -1)
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  for p in server clients unixd; do ( cd "$tmp" && rpm2cpio "$D/kanidm-$p-$VR.x86_64.rpm" | cpio -idm --quiet ); done
  bad=0
  for b in usr/sbin/kanidmd usr/bin/kanidm usr/sbin/kanidm_unixd; do
    if strings "$tmp/$b" | grep -q 'AWS-LC FIPS 4.2.0'; then echo "FIPS OK   $b"; else echo "NOT FIPS  $b"; bad=1; fi
  done
  (( bad == 0 )) || exit 1
  echo "FIPS VARIANT OK ($VR)"
  ```

- [ ] **Step 3: Edit `appliance/rpm/kanidm/kanidm.spec`.**
  - `Release:        2.chp%{?dist}`
  - add `Vendor:         The CyberHygiene Project` after `License:`
  - `Summary:        Kanidm identity management (FIPS TLS variant, Rocky 9 compatible)`
  - `Source0:        kanidm-%{version}-fips-staged.tar.gz`
  - `%description`: `Kanidm %{version} built offline from source for EL9 with rustls' "fips" feature: TLS runs in the AWS-LC FIPS 4.2.0 module. Application cryptography (Argon2 password hashing, TOTP HMAC) stays in RustCrypto (outside any FIPS module; POA&M). Built without TPM support.`
  - in `%install`: `install -Dm0644 LICENSE.md %{buildroot}%{_datadir}/licenses/kanidm/LICENSE.md`
  - in each of the three `%files` sections: `%license %{_datadir}/licenses/kanidm/LICENSE.md`
  - a new top `%changelog` entry: `* Tue Sep 29 2026 The CyberHygiene Project - 1.11.2-2.chp` / `- FIPS TLS variant (rustls "fips", AWS-LC FIPS 4.2.0) for server and unixd; licence file; vendor.`
  - add `/usr/share/licenses/kanidm/LICENSE.md` to `expected-files.txt`.

- [ ] **Step 4: Write `appliance/rpm/kanidm/build.sh`**: the whole of `lab/kanidm/build.sh`, with these changes:
  `W=$HOME/kanidm-build-fips`, it extracts `kanidm-$V-fips-vendor.tar.gz` instead of `-vendor.tar.gz`, and it adds the
  guard `grep -q '"fips",' Cargo.toml || { echo "FAILED: not the FIPS variant tree"; exit 1; }` right after `cd "$SRC"`.
  Every `b …` target line stays the same (all nine binaries).

- [ ] **Step 5: Edit `appliance/rpm/kanidm/build-rpms.sh`.** Set `W=$HOME/kanidm-build-fips`, add
  `cp "$SRC/LICENSE.md" "$S/"` before the `tar`, name the tarball `kanidm-1.11.2-fips-staged.tar.gz`, and after
  `bash "$here/check-rpms.sh"` add `bash "$here/check-fips.sh"`.

- [ ] **Step 6: Start build1 and relax fapolicyd (needs the ISSO).** Ask the user: *"Approve fapolicyd permissive on build1
  for the FIPS-variant Kanidm and step builds (Plan 1 Tasks 5 and 7), reverted with a reboot afterwards?"* Only on yes:
  ```bash
  ssh aero 'sudo virsh start build1'; sleep 60
  ssh build1 'sudo sed -i "s/^permissive = 0/permissive = 1/" /etc/fapolicyd/fapolicyd.conf && sudo systemctl restart fapolicyd'
  ```
  Add a row to `lab/vm-deviations.md` for build1: `fapolicyd permissive = 1 for ISO Plan 1 builds (ISSO-approved <date>); reverted + rebooted after Task 7`.

- [ ] **Step 7: Push the inputs and build.**
  ```bash
  ssh build1 'mkdir -p ~/inputs ~/appliance-kanidm'
  scp -q ~/idm-lab-inputs/kanidm-1.11.2.tar.gz ~/idm-lab-inputs/kanidm-1.11.2-fips-vendor.tar.gz build1:inputs/
  ssh build1 'cd ~/inputs && sha256sum kanidm-1.11.2.tar.gz kanidm-1.11.2-fips-vendor.tar.gz'
  scp -qr appliance/rpm/kanidm/* build1:appliance-kanidm/
  ssh build1 'bash ~/appliance-kanidm/build.sh && bash ~/appliance-kanidm/build-rpms.sh'
  ```
  Expected: the sha256s equal `lab/inputs/MANIFEST.txt` (`a8ed3120…`, `ae5bf81a…`); the build ends with `RPMS OK … (1.11.2-2.chp.el9)`
  and `FIPS VARIANT OK`. If `kanidm_unixd` prints `NOT FIPS`, **STOP and report to the user**: ISSO #14 assumed unixd's
  TLS would be in the module. Do not ship a mixed set.

- [ ] **Step 8: Collect and record.**
  `ssh build1 'ls ~/rpmbuild/RPMS/x86_64/kanidm-*-1.11.2-2.chp*.rpm' | while read -r f; do ssh build1 "cat $f" | ssh aero "cat > /data/chp-release/built/$(basename "$f")"; done`.
  Write `appliance/rpm/kanidm/BUILD-RECORD.md`: date, build1 facts (as in `lab/kanidm-rpm/BUILD-RECORD.md`), the fapolicyd deviation, timings
  (`~/kanidm-build-fips/timings.txt`), the binary sha256s, the RPM sha256s (`sha256sum` on aero), and the `check-rpms` and `check-fips` output.

- [ ] **Step 9: Commit** `appliance/rpm/kanidm/` and `lab/vm-deviations.md` with the message
  `ISO Plan 1 Task 5: Kanidm 1.11.2-2.chp FIPS TLS variant RPMs (server + unixd verified in-module)`.

---

### Task 6: step-ca / step-cli source inputs, pinned (Mac)

**Files:**
- Create: `appliance/inputs/fetch-step.sh`, `appliance/inputs/verify.sh`, `appliance/inputs/MANIFEST.txt`

**Interfaces:**
- Produces, in `~/idm-lab-inputs/appliance/`: `step-ca-0.30.2.tar.gz`, `step-ca-0.30.2-vendor.tar.gz`, `step-cli-0.31.0.tar.gz`,
  `step-cli-0.31.0-vendor.tar.gz`, `go<GOV>.linux-amd64.tar.gz` (and the darwin one used for vendoring). Each is a row in
  `appliance/inputs/MANIFEST.txt`: `file|version|bytes|sha256|source|how verified`.
  `appliance/inputs/verify.sh <dir>` exits 0 only if every row's file matches.

- [ ] **Step 1: Write `appliance/inputs/verify.sh`** (runs on the Mac and on Linux).
  ```bash
  #!/usr/bin/env bash
  # verify.sh <dir>: every file named in MANIFEST.txt exists in <dir> with the pinned size and sha256.
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; D=${1:?dir}
  sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
  bad=0
  while IFS='|' read -r f _v _bytes want _src _how; do
    [[ -z $f || $f == \#* ]] && continue
    [[ -f $D/$f ]] || { echo "MISSING $f"; bad=1; continue; }
    [[ $(sha "$D/$f") == "$want" ]] && echo "OK      $f" || { echo "MISMATCH $f"; bad=1; }
  done < "$here/MANIFEST.txt"
  exit $bad
  ```

- [ ] **Step 2: Write `appliance/inputs/fetch-step.sh`.**
  ```bash
  #!/usr/bin/env bash
  # fetch-step.sh (RUNS ON THE MAC ONLY): step-ca + step-cli sources, the Go toolchain their go.mod asks for, and their
  # vendored modules, all pinned in MANIFEST.txt. GitHub tag archives are unsigned: their sha256 is pinned on first
  # fetch (the kanidm precedent in lab/inputs). Go toolchains are checked against go.dev's published sha256 (TLS).
  # Vendoring checks every module against the source's go.sum ('go mod verify') before 'go mod vendor'.
  set -Eeuo pipefail
  HERE="$(cd "$(dirname "$0")" && pwd)"; MAN="$HERE/MANIFEST.txt"
  D="${IDM_INPUTS:-$HOME/idm-lab-inputs}/appliance"; mkdir -p "$D"; cd "$D"
  CA_V=0.30.2; CLI_V=0.31.0
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
  bytes() { stat -f %z "$1"; }
  : > "$MAN.tmp"
  rec() { echo "$1|$2|$(bytes "$1")|$(sha "$1")|$3|$4" >> "$MAN.tmp"; }
  [[ -s step-ca-$CA_V.tar.gz ]]  || curl -fL --retry 3 -o step-ca-$CA_V.tar.gz  https://github.com/smallstep/certificates/archive/refs/tags/v$CA_V.tar.gz
  [[ -s step-cli-$CLI_V.tar.gz ]] || curl -fL --retry 3 -o step-cli-$CLI_V.tar.gz https://github.com/smallstep/cli/archive/refs/tags/v$CLI_V.tar.gz
  # Go: the newest stable patch release of the highest minor that either go.mod asks for ('go' or 'toolchain' line)
  want=$( { tar -xzOf step-ca-$CA_V.tar.gz certificates-$CA_V/go.mod; tar -xzOf step-cli-$CLI_V.tar.gz cli-$CLI_V/go.mod; } \
          | awk '$1=="go"||$1=="toolchain"{v=$2; sub(/^go/,"",v); print v}' | sort -V | tail -1)
  minor=$(cut -d. -f1,2 <<<"$want")
  curl -fsSL 'https://go.dev/dl/?mode=json&include=all' > go-releases.json
  read -r GOV LNX LNX_SHA MAC MAC_SHA < <(python3 - "$minor" <<'PY'
  import json, sys
  minor = sys.argv[1]; rel = json.load(open("go-releases.json"))
  def key(v): return tuple(int(x) for x in v[2:].split("."))
  cands = [r for r in rel if r["stable"] and (r["version"] == "go" + minor or r["version"].startswith("go" + minor + "."))]
  r = max(cands, key=lambda r: key(r["version"]))
  f = {(x["os"], x["arch"], x["kind"]): x for x in r["files"]}
  l, m = f[("linux", "amd64", "archive")], f[("darwin", "arm64", "archive")]
  print(r["version"], l["filename"], l["sha256"], m["filename"], m["sha256"])
  PY
  )
  echo "Go: go.mod wants >= $want → $GOV"
  for pair in "$LNX $LNX_SHA" "$MAC $MAC_SHA"; do
    read -r f s <<<"$pair"
    [[ -s $f ]] || curl -fL --retry 3 -o "$f" "https://go.dev/dl/$f"
    [[ $(sha "$f") == "$s" ]] || { echo "Go sha256 mismatch: $f"; exit 1; }
  done
  rm -rf go-mac && mkdir go-mac && tar -xzf "$MAC" -C go-mac
  export GOROOT=$PWD/go-mac/go PATH=$PWD/go-mac/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-mod=mod
  vend() {  # tarball topdir out
    rm -rf src && mkdir src && tar -xzf "$1" -C src
    ( cd "src/$2" && go mod download && go mod verify && go mod vendor )
    COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$3" -C "src/$2" vendor
    rm -rf src
  }
  [[ -s step-ca-$CA_V-vendor.tar.gz ]]  || vend step-ca-$CA_V.tar.gz  certificates-$CA_V step-ca-$CA_V-vendor.tar.gz
  [[ -s step-cli-$CLI_V-vendor.tar.gz ]] || vend step-cli-$CLI_V.tar.gz cli-$CLI_V        step-cli-$CLI_V-vendor.tar.gz
  rec step-ca-$CA_V.tar.gz $CA_V "github smallstep/certificates tag v$CA_V" "sha256 pinned on first fetch (tag archive unsigned)"
  rec step-cli-$CLI_V.tar.gz $CLI_V "github smallstep/cli tag v$CLI_V" "sha256 pinned on first fetch (tag archive unsigned)"
  rec "$LNX" "${GOV#go}" "https://go.dev/dl/$LNX" "sha256 == go.dev published sha256"
  rec "$MAC" "${GOV#go}" "https://go.dev/dl/$MAC" "sha256 == go.dev published sha256 (vendoring only)"
  rec step-ca-$CA_V-vendor.tar.gz $CA_V "go mod vendor ($GOV)" "module hashes enforced by go.sum (go mod verify)"
  rec step-cli-$CLI_V-vendor.tar.gz $CLI_V "go mod vendor ($GOV)" "module hashes enforced by go.sum (go mod verify)"
  rm -rf go-mac go-releases.json
  mv "$MAN.tmp" "$MAN"; cat "$MAN"
  ```

- [ ] **Step 3: Run it and verify.** `bash appliance/inputs/fetch-step.sh && bash appliance/inputs/verify.sh ~/idm-lab-inputs/appliance`.
  Expected: 6 MANIFEST rows and 6 × `OK`. If a download stalls, LuLu is probably blocking `curl` or `go` (as with
  `cargo` in Plan 1 of the lab): ask the user to allow it, then re-run (the script resumes).
  If `tar -xzOf … certificates-0.30.2/go.mod` fails, list the archive's top directory with `tar -tzf … | head -1` and
  fix the `topdir` names in both places.

- [ ] **Step 4: Commit** `appliance/inputs/` with the message
  `ISO Plan 1 Task 6: step-ca/step-cli sources, Go toolchain and vendored modules pinned (MANIFEST)`.

---

### Task 7: step-ca / step-cli RPMs built from source (build1)

**Files:**
- Create: `appliance/rpm/step/{build.sh,smoke.sh,build-rpms.sh,step-ca.spec,step-cli.spec,step-ca.service,step-ca.sysusers,check-step.sh,BUILD-RECORD.md}`

**Interfaces:**
- Consumes: Task 6's inputs; build1 with fapolicyd permissive (Task 5 Step 6).
- Produces: `step-ca-0.30.2-2.chp.el9.x86_64.rpm` (`/usr/bin/step-ca`; the unit `step-ca.service`, **not enabled**, with
  `GODEBUG=fips140=on`; the sysusers entry for user `step`) and `step-cli-0.31.0-2.chp.el9.x86_64.rpm` (`/usr/bin/step-cli`,
  `/usr/bin/step` → `step-cli`), in `aero:/data/chp-release/built/`. The paths match the upstream RPMs the lab used, so
  `lab/srv1/*.sh` works unchanged.

- [ ] **Step 1: Write the failing check `appliance/rpm/step/check-step.sh`.**
  ```bash
  #!/usr/bin/env bash
  # Runs ON build1: what the step RPMs ship. Go version and FIPS module pinned (Review Focus 5), the unit keeps
  # GODEBUG=fips140=on and never fips140=only (row 13), versions are real, and nothing lab-specific is inside.
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; D="${1:-$HOME/rpmbuild/RPMS/x86_64}"
  GOV=$(cat "$HOME/step-build/go-version.txt")
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  ca=$(ls "$D"/step-ca-0.30.2-2.chp*.rpm); cli=$(ls "$D"/step-cli-0.31.0-2.chp*.rpm)
  for r in "$ca" "$cli"; do ( cd "$tmp" && rpm2cpio "$r" | cpio -idm --quiet ); done
  bad=0; t() { if eval "$2"; then echo "OK    $1"; else echo "FAIL  $1"; bad=1; fi; }
  t "step-ca built with $GOV"            "'$HOME/step-build/go/bin/go' version -m '$tmp/usr/bin/step-ca' | grep -q \"$GOV\""
  t "step-ca uses a frozen FIPS module"  "'$HOME/step-build/go/bin/go' version -m '$tmp/usr/bin/step-ca' | grep -qE 'GOFIPS140=v1\\.0\\.0'"
  t "step-cli built with $GOV"           "'$HOME/step-build/go/bin/go' version -m '$tmp/usr/bin/step-cli' | grep -q \"$GOV\""
  t "step-ca reports 0.30.2"             "'$tmp/usr/bin/step-ca' version 2>&1 | grep -q 0.30.2"
  t "step-cli reports 0.31.0"            "'$tmp/usr/bin/step-cli' version 2>&1 | grep -q 0.31.0"
  t "step -> step-cli"                   "[[ \$(readlink '$tmp/usr/bin/step') == step-cli ]]"
  t "unit sets GODEBUG=fips140=on"       "grep -qx 'Environment=GODEBUG=fips140=on' '$tmp/usr/lib/systemd/system/step-ca.service'"
  t "unit never says fips140=only"       "! grep -q 'fips140=only' '$tmp/usr/lib/systemd/system/step-ca.service'"
  t "sysusers creates step"              "grep -qE '^u step ' '$tmp/usr/lib/sysusers.d/step-ca.conf'"
  t "licence files shipped"              "ls '$tmp'/usr/share/licenses/step-ca/LICENSE '$tmp'/usr/share/licenses/step-cli/LICENSE >/dev/null"
  t "nothing lab-specific inside"        "! grep -rqs 'kanidm.lab.test\\|192.168.100' '$tmp/usr/lib' '$tmp/usr/share'"
  (( bad == 0 )) || exit 1; echo "STEP RPMS OK"
  ```

- [ ] **Step 2: Write `appliance/rpm/step/build.sh`.**
  ```bash
  #!/usr/bin/env bash
  # Runs ON build1: build step-ca and step (cli) OFFLINE with the pinned Go toolchain. CGO off, vendored modules only,
  # no toolchain switching. Go's FIPS 140-3 module is selected at build time: GOFIPS140=v1.0.0 (the frozen module
  # snapshot) makes fips140=on the binary's default; the unit still sets GODEBUG=fips140=on explicitly (row 13).
  set -Eeuo pipefail
  IN=$HOME/inputs/appliance; W=$HOME/step-build; CA_V=0.30.2; CLI_V=0.31.0
  GO_TGZ=$(ls "$IN"/go*.linux-amd64.tar.gz); [[ $(wc -l <<<"$GO_TGZ") -eq 1 ]] || { echo "want exactly one Go toolchain"; exit 1; }
  rm -rf "$W"; mkdir -p "$W/src" "$W/out"
  tar -xzf "$GO_TGZ" -C "$W"
  export GOROOT=$W/go PATH=$W/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off GONOSUMDB='*' \
         CGO_ENABLED=0 GOCACHE=$W/cache GOPATH=$W/gopath GOFIPS140=${GOFIPS140:-v1.0.0}
  go version | awk '{print $3}' > "$W/go-version.txt"
  { go version; echo "GOFIPS140=$GOFIPS140"; ls "$GOROOT/lib/fips140" 2>/dev/null; } | tee "$W/toolchain.txt"
  bt=$(date -u +%Y-%m-%dT%H:%MZ)
  build() {  # tarball topdir pkg out version
    tar -xzf "$IN/$1.tar.gz" -C "$W/src"; tar -xzf "$IN/$1-vendor.tar.gz" -C "$W/src/$2"
    ( cd "$W/src/$2" && go build -trimpath -ldflags "-s -w -X main.Version=$5 -X main.BuildTime=$bt" -o "$W/out/$4" "$3" )
    cp "$W/src/$2/LICENSE" "$W/out/LICENSE-$4"
  }
  build step-ca-$CA_V   certificates-$CA_V ./cmd/step-ca step-ca  $CA_V
  build step-cli-$CLI_V cli-$CLI_V         ./cmd/step    step-cli $CLI_V
  "$W/out/step-ca" version; "$W/out/step-cli" version
  echo "BUILD OK"
  ```
  If `go build` rejects `GOFIPS140=v1.0.0` ("unknown GOFIPS140 version"), look at the listing in `toolchain.txt`, re-run with
  `GOFIPS140=<the v1.0.0 snapshot name shown there>`, and record that in BUILD-RECORD. If `version` prints `N/A`, the
  `-X` symbol names differ in that source: find them with `grep -rn 'Version *=' cmd/` and fix the ldflags.

- [ ] **Step 3: Write `appliance/rpm/step/smoke.sh`**. It runs on build1, before packaging, and shows that the source-built
  step-ca works in FIPS mode the way the upstream binary did.
  ```bash
  #!/usr/bin/env bash
  # Runs ON build1: init a throwaway CA on loopback, start it with GODEBUG=fips140=on, health-check, issue one cert.
  set -Eeuo pipefail
  B=$HOME/step-build/out; T=$(mktemp -d); trap 'kill ${pid:-0} 2>/dev/null; rm -rf "$T"' EXIT
  export STEPPATH=$T; head -c 32 /dev/urandom | base64 > "$T/pw"
  "$B/step-cli" ca init --name "smoke CA" --dns localhost --address 127.0.0.1:9443 --provisioner smoke \
     --password-file "$T/pw" --provisioner-password-file "$T/pw" --deployment-type standalone >/dev/null
  GODEBUG=fips140=on "$B/step-ca" "$T/config/ca.json" --password-file "$T/pw" >"$T/ca.log" 2>&1 & pid=$!
  for _ in $(seq 20); do "$B/step-cli" ca health --ca-url https://127.0.0.1:9443 --root "$T/certs/root_ca.crt" >/dev/null 2>&1 && break; sleep 1; done
  "$B/step-cli" ca health --ca-url https://127.0.0.1:9443 --root "$T/certs/root_ca.crt"
  "$B/step-cli" ca certificate smoke.test "$T/s.crt" "$T/s.key" --provisioner smoke --provisioner-password-file "$T/pw" \
     --ca-url https://127.0.0.1:9443 --root "$T/certs/root_ca.crt" >/dev/null
  "$B/step-cli" certificate inspect "$T/s.crt" --short
  echo "SMOKE OK"
  ```

- [ ] **Step 4: Write the unit and sysusers files.**
  `appliance/rpm/step/step-ca.service`: the lab unit (`lab/srv1/units/step-ca.service`) with
  `Description=step-ca internal certificate authority`, all the other lines unchanged (including the fips140 comment).
  `appliance/rpm/step/step-ca.sysusers`: `u step - "step-ca service" /etc/step-ca /sbin/nologin`.

- [ ] **Step 5: Write `appliance/rpm/step/step-ca.spec`.**
  ```
  %global debug_package %{nil}
  Name:           step-ca
  Version:        0.30.2
  Release:        2.chp%{?dist}
  Summary:        step-ca internal certificate authority (built from source, Go FIPS 140-3 module)
  License:        Apache-2.0
  Vendor:         The CyberHygiene Project
  URL:            https://github.com/smallstep/certificates
  Source0:        step-ca-%{version}-staged.tar.gz
  Requires:       step-cli
  BuildRequires:  systemd-rpm-macros
  %{?sysusers_requires_compat}

  %description
  step-ca %{version} built offline from source with CGO disabled and Go's FIPS 140-3 module selected at build time.
  The unit runs it with GODEBUG=fips140=on. It is installed disabled; the identity-server role configures and enables it.

  %prep
  %setup -q -n staged

  %install
  install -Dm0755 step-ca %{buildroot}%{_bindir}/step-ca
  install -Dm0644 step-ca.service %{buildroot}%{_unitdir}/step-ca.service
  install -Dm0644 step-ca.sysusers %{buildroot}%{_sysusersdir}/step-ca.conf
  install -Dm0644 LICENSE-step-ca %{buildroot}%{_datadir}/licenses/step-ca/LICENSE

  %pre
  %sysusers_create_compat step-ca.sysusers

  %post
  %systemd_post step-ca.service
  %preun
  %systemd_preun step-ca.service
  %postun
  %systemd_postun_with_restart step-ca.service

  %files
  %license %{_datadir}/licenses/step-ca/LICENSE
  %{_bindir}/step-ca
  %{_unitdir}/step-ca.service
  %{_sysusersdir}/step-ca.conf

  %changelog
  * Tue Sep 29 2026 The CyberHygiene Project - 0.30.2-2.chp
  - Built from source (vendored modules, pinned Go), GOFIPS140 module; unit with GODEBUG=fips140=on; sysusers.
  ```
  (`%sysusers_create_compat` reads its argument relative to the build directory: if rpmbuild can't find
  `step-ca.sysusers` at `%pre` generation, use `%{SOURCE0}`-extracted path `%{_builddir}/staged/step-ca.sysusers`.)

- [ ] **Step 6: Write `appliance/rpm/step/step-cli.spec`.**
  ```
  %global debug_package %{nil}
  Name:           step-cli
  Version:        0.31.0
  Release:        2.chp%{?dist}
  Summary:        step command-line tool (built from source)
  License:        Apache-2.0
  Vendor:         The CyberHygiene Project
  URL:            https://github.com/smallstep/cli
  Source0:        step-cli-%{version}-staged.tar.gz

  %description
  The step CLI %{version}, built offline from source with CGO disabled and Go's FIPS 140-3 module selected at build time.

  %prep
  %setup -q -n staged

  %install
  install -Dm0755 step-cli %{buildroot}%{_bindir}/step-cli
  ln -s step-cli %{buildroot}%{_bindir}/step
  install -Dm0644 LICENSE-step-cli %{buildroot}%{_datadir}/licenses/step-cli/LICENSE

  %files
  %license %{_datadir}/licenses/step-cli/LICENSE
  %{_bindir}/step-cli
  %{_bindir}/step

  %changelog
  * Tue Sep 29 2026 The CyberHygiene Project - 0.31.0-2.chp
  - Built from source (vendored modules, pinned Go), GOFIPS140 module.
  ```

- [ ] **Step 7: Write `appliance/rpm/step/build-rpms.sh`.**
  ```bash
  #!/usr/bin/env bash
  # Runs ON build1: stage the built binaries + unit/sysusers/licences into tarballs, rpmbuild both specs, check.
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; O=$HOME/step-build/out
  rpmdev-setuptree
  stage() {  # name version files...
    local n=$1 v=$2; shift 2; local S; S=$(mktemp -d)/staged; mkdir -p "$S"; cp "$@" "$S/"
    tar -czf ~/rpmbuild/SOURCES/$n-$v-staged.tar.gz -C "$(dirname "$S")" staged
  }
  stage step-ca 0.30.2 "$O/step-ca" "$O/LICENSE-step-ca" "$here/step-ca.service" "$here/step-ca.sysusers"
  stage step-cli 0.31.0 "$O/step-cli" "$O/LICENSE-step-cli"
  cp "$here"/step-ca.spec "$here"/step-cli.spec ~/rpmbuild/SPECS/
  rpmbuild -bb ~/rpmbuild/SPECS/step-cli.spec >/dev/null
  rpmbuild -bb ~/rpmbuild/SPECS/step-ca.spec >/dev/null
  bash "$here/check-step.sh"
  ```

- [ ] **Step 8: Push, build, smoke-test, package.**
  ```bash
  ssh build1 'mkdir -p ~/inputs/appliance ~/appliance-step'
  scp -q ~/idm-lab-inputs/appliance/{step-ca-0.30.2*.tar.gz,step-cli-0.31.0*.tar.gz,go*.linux-amd64.tar.gz} build1:inputs/appliance/
  scp -q appliance/inputs/{verify.sh,MANIFEST.txt} build1:inputs/appliance/
  ssh build1 'cd ~/inputs/appliance && grep -v darwin MANIFEST.txt > M && mv M MANIFEST.txt && bash verify.sh .'
  scp -q appliance/rpm/step/* build1:appliance-step/
  ssh build1 'bash ~/appliance-step/build.sh && bash ~/appliance-step/smoke.sh && bash ~/appliance-step/build-rpms.sh'
  ```
  Expected: 5 × `OK` from verify (the darwin toolchain isn't pushed), `BUILD OK`, `SMOKE OK` (the cert inspect line shows
  ECDSA), then `STEP RPMS OK`. The smoke test is the evidence that the source build behaves like the upstream binary
  under `fips140=on`. If it fails, stop and debug.

- [ ] **Step 9: Restore build1.**
  `ssh build1 'sudo sed -i "s/^permissive = 1/permissive = 0/" /etc/fapolicyd/fapolicyd.conf && sudo systemctl restart fapolicyd && sudo systemctl reboot'`,
  wait, then `ssh build1 'grep ^permissive /etc/fapolicyd/fapolicyd.conf'` → `permissive = 0`. Update the `lab/vm-deviations.md` row with "reverted + rebooted <date>".

- [ ] **Step 10: Collect and record.** Copy both RPMs to `aero:/data/chp-release/built/` (the same `ssh … cat | ssh aero` pattern as
  Task 5 Step 8), then `ssh aero 'sudo virsh shutdown build1'`. Write `appliance/rpm/step/BUILD-RECORD.md`: Go version and
  GOFIPS140 (`toolchain.txt`), binary and RPM sha256s, smoke output, check output, and the fapolicyd deviation.

- [ ] **Step 11: Commit** `appliance/rpm/step/` and `lab/vm-deviations.md` with the message
  `ISO Plan 1 Task 7: step-ca 0.30.2 / step-cli 0.31.0 built from source (pinned Go, GOFIPS140), RPMs + smoke test`.

---

### Task 8: Assemble, sign and prove the 0.1.0 repo; CMVP record

**Files:**
- Create: `appliance/release/PACKAGES.txt`, `appliance/release/assemble-repo.sh`, `appliance/release/RELEASE-RECORD-0.1.0.md`,
  `appliance/release/CMVP-STATUS.md`

**Interfaces:**
- Consumes: `/data/chp-release/built/*.rpm` (Tasks 4, 5, 7), the EPEL GA RPM at `/data/lab-inputs/rpms/`, `sign-session.sh`,
  `sign-repo.sh`, `verify-repo.sh`.
- Produces: `aero:/data/chp-release/0.1.0/repo/`, a signed and verified repo that Plans 3–5 install from; a copy served at
  `http://192.168.100.1:8080/chp/0.1.0/` for lab VMs.

- [ ] **Step 1: Write `appliance/release/PACKAGES.txt`.**
  ```
  # package names in the 0.1.0 repo (one per line); assemble-repo.sh takes the newest RPM of each
  kanidm-server
  kanidm-clients
  kanidm-unixd
  step-ca
  step-cli
  idm-collect
  google-authenticator
  ```

- [ ] **Step 2: Write `appliance/release/assemble-repo.sh`** (aero).
  ```bash
  #!/usr/bin/env bash
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  # assemble-repo.sh <stage-dir> <source-dir>...: copy the newest RPM of each PACKAGES.txt name into stage-dir.
  # Fails if a name has no RPM, or if stage-dir already exists.
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; S=$1; shift
  [[ -e $S ]] && { echo "refusing: $S exists"; exit 1; }
  mkdir -p "$S"
  while read -r name; do
    [[ -z $name || $name == \#* ]] && continue
    best=$(for d in "$@"; do for f in "$d"/*.rpm; do [[ -f $f ]] && [[ $(rpm -qp --qf '%{NAME}' "$f" 2>/dev/null) == "$name" ]] && echo "$f"; done; done \
           | while read -r f; do printf '%s\t%s\n' "$(rpm -qp --qf '%{EPOCH}:%{VERSION}-%{RELEASE}' "$f" 2>/dev/null | sed 's/^(none)/0/')" "$f"; done \
           | sort -V | tail -1 | cut -f2)
    [[ -n $best ]] || { echo "MISSING package: $name"; exit 1; }
    cp -a "$best" "$S/"; echo "  $name ← $(basename "$best")"
  done < "$here/PACKAGES.txt"
  ```
  (It must pick `…-2.chp` over the lab's `…-1.lab`. Step 3 checks that it did.)

- [ ] **Step 3: Assemble and sign through the YubiKey.**
  ```bash
  bash appliance/release/push.sh
  FPR=$(awk '$2=="cyberhygiene"{print $1}' appliance/release/trusted-keys.txt)
  ssh aero 'bash /data/chp-release/tools/assemble-repo.sh /data/chp-release/0.1.0/stage /data/chp-release/built /data/lab-inputs/rpms'
  ssh aero 'ls /data/chp-release/0.1.0/stage | grep -c "chp\.el9"'
  bash appliance/release/sign-session.sh "bash /data/chp-release/tools/sign-repo.sh /data/chp-release/0.1.0/stage /data/chp-release/0.1.0/repo $FPR /data/chp-release/tools"
  ```
  Expected: 7 packages listed, and `6` from the grep (every package except EPEL's GA is ours). The user touches the key about 13 times.
  Expected result: `REPO OK: 7 packages …`, then `SIGNED REPO: /data/chp-release/0.1.0/repo`.

- [ ] **Step 4: Serve it to the lab VMs.** Copy the repo into the lab repo's docroot and add the keys:
  `ssh aero 'sudo mkdir -p /data/lab-inputs/chp && sudo cp -a /data/chp-release/0.1.0/repo /data/lab-inputs/chp/0.1.0 && sudo cp /data/chp-release/tools/RPM-GPG-KEY-cyberhygiene /data/chp-release/tools/RPM-GPG-KEY-EPEL-9 /data/lab-inputs/chp/ && curl -fsI http://192.168.100.1:8080/chp/0.1.0/repodata/repomd.xml.asc | head -1'`
  Expected: `HTTP/1.0 200 OK`.

- [ ] **Step 5: Install test on the lab (dnf enforces signatures; the FIPS variant interoperates).** Stage it as
  `lab/host/iso1-install-test.sh`, run from the Mac. It is committed as evidence tooling.
  ```bash
  #!/usr/bin/env bash
  # iso1-install-test.sh (RUNS ON THE MAC): install the signed 0.1.0 repo's packages on srv1 + client2 with
  # gpgcheck=1 and repo_gpgcheck=1; prove dnf refuses the repo without our key; check the services, the unixd lookup
  # and fapolicyd. Finish with lab/reset.sh (golden restores the lab builds).
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")/../.." && pwd)"
  REPO='[chp]
  name=CyberHygiene Project Lab Installer packages 0.1.0
  baseurl=http://192.168.100.1:8080/chp/0.1.0/
  enabled=1
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9'
  for h in srv1 client2; do
    scp -q "$here"/appliance/release/RPM-GPG-KEY-cyberhygiene "$here"/appliance/release/RPM-GPG-KEY-EPEL-9 "$h:/tmp/"
    ssh "$h" "sudo install -m0644 /tmp/RPM-GPG-KEY-cyberhygiene /tmp/RPM-GPG-KEY-EPEL-9 /etc/pki/rpm-gpg/ && printf '%s\n' '$REPO' | sudo tee /etc/yum.repos.d/chp.repo >/dev/null"
  done
  echo "== negative: without our key dnf must refuse the repo"
  ssh client2 "sudo sed -i 's|^gpgkey=.*|gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9|' /etc/yum.repos.d/chp.repo && sudo dnf -q clean all"
  if ssh client2 'sudo dnf -y -q --repo chp makecache' >/dev/null 2>&1; then echo "FAIL: repo accepted without our key"; exit 1; fi
  echo "PASS: refused"
  ssh client2 "sudo sed -i 's|^gpgkey=.*|gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9|' /etc/yum.repos.d/chp.repo && sudo dnf -q clean all"
  start=$(ssh srv1 'date +%H:%M:%S')
  echo "== srv1: server-side packages"
  ssh srv1 'sudo dnf -y -q upgrade kanidm-server kanidm-clients step-ca step-cli && rpm -q kanidm-server step-ca step-cli && sudo systemctl restart kanidmd step-ca && sleep 5 && systemctl is-active kanidmd step-ca'
  ssh srv1 'curl -fsS --cacert /etc/step-ca/certs/root_ca.crt https://idm.kanidm.lab.test/status; echo; step-cli ca health --ca-url https://ca.kanidm.lab.test:9000 --root /etc/step-ca/certs/root_ca.crt'
  echo "== client2: unixd (FIPS variant) against the FIPS-variant server"
  ssh client2 'sudo dnf -y -q upgrade kanidm-unixd kanidm-clients && rpm -q kanidm-unixd && sudo systemctl restart kanidm-unixd kanidm-unixd-tasks && sleep 5 && sudo kanidm-unix status && getent passwd lab02'
  for h in srv1 client2; do
    echo "== $h: signatures + fapolicyd"
    ssh "$h" 'for p in $(rpm -qa --qf "%{NAME}\n" | grep -E "^(kanidm|step|idm-collect)"); do rpm -q --qf "%{NAME}-%{VERSION}-%{RELEASE} %{RSAHEADER:pgpsig}\n" $p; done'
    ssh "$h" "sudo ausearch -m FANOTIFY -ts $start 2>/dev/null | grep -c type=FANOTIFY || true"
  done
  echo "== restore golden"
  bash "$here/lab/reset.sh"
  ```
  Expected:
  - `PASS: refused`
  - srv1 shows the `2.chp` versions, both services `active`, Kanidm `/status` → `true`, and `step-ca` health `ok`
  - client2 unixd `online`, and `getent` prints lab02
  - each listed package's signature line shows our key ID (EPEL's GA isn't installed here)
  - fapolicyd FANOTIFY count `0` on both hosts
  - reset completes

  Any other result: stop, debug, and do not sign a release.

- [ ] **Step 6: CMVP status (spec §9).** Look up, on the NIST CMVP site (validated modules search and the
  Modules-In-Process list): the **AWS-LC Cryptographic Module** (is there a certificate or an MIP entry covering *4.2.0*?),
  the **Go Cryptographic Module** (at the version selected by `GOFIPS140` in `appliance/rpm/step/BUILD-RECORD.md`), and
  the **Rocky Linux 9 OpenSSL FIPS provider** (for the OS side). Write `appliance/release/CMVP-STATUS.md` with, for each: the module name
  and version, certificate number or MIP status, validation date / sunset date, the URL, and the date checked. Add a column for whether *our build*
  matches the certificate's operational environment and build procedure (from its Security Policy); write "not verified" wherever it hasn't been checked.
  End it with the **draft SSP text for ISSO #14**: TLS for Kanidm is in AWS-LC FIPS 4.2.0 (status as found); Argon2 and TOTP HMAC
  are outside (POA&M, 3.13.11); step-ca uses the Go module (status as found). Do not claim validation that the lookup does not show.

- [ ] **Step 7: Release record.** Write `appliance/release/RELEASE-RECORD-0.1.0.md` with: the date, the signer fingerprint, each package's NEVRA +
  sha256 (`ssh aero 'cd /data/chp-release/0.1.0/repo && sha256sum *.rpm'`), the `verify-repo.sh` output, and the install-test transcript summary
  (Step 5 expected lines, marked PASS or FAIL as observed).

- [ ] **Step 8: Tests, scan, commit.**
  `uv run pytest -q` (all pass); `bash lab/kickstart/test_render.sh` (unchanged, still passes); `bash lab/tools/secrets-scan.sh`
  (only the two known fixture FAILs); `grep -rn "<yubikey-serial>" . --exclude-dir=.git` finds nothing.
  Commit `appliance/release/{PACKAGES.txt,assemble-repo.sh,RELEASE-RECORD-0.1.0.md,CMVP-STATUS.md}` and
  `lab/host/iso1-install-test.sh` with the message `ISO Plan 1 Task 8: signed 0.1.0 repo (7 packages) verified; dnf enforces signatures; FIPS-variant server+unixd interoperate; CMVP status recorded`.

---

## Self-review (done while writing)

- **Spec coverage (plan 1 of §12):** YubiKey key setup + custody note → Task 1; Kanidm FIPS-variant rebuild (#14) → Task 5;
  step-ca / step-cli RPMs → Tasks 6–7; idm-collect RPM (rows 21, 23 read-only unchanged) → Task 4; signed repo (row 1,
  `gpgcheck`/`repo_gpgcheck`) → Tasks 3 and 8; CMVP verification (§9) → Task 8 Step 6. Not in this plan: `chp-site` and the kickstarts (Plan 2), the role RPMs (Plans 3–4),
  the ISO and the For Jeff release (Plan 5).
- **Deviation from the spec, recorded:** the spec says "sign on aero with the YubiKey". This plan keeps the YubiKey on
  the **Mac** and forwards its agent to aero (Task 2), because the key is then never physically moved and aero still does the
  `rpmsign`. The effect is the same, and the key only needs to be in one place.
- **Open for Plan 4:** the `--user` argument vs ISSO #22's "no arguments" (Task 4 note).
