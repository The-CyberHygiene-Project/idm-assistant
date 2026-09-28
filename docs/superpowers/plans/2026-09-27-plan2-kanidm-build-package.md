# Plan 2: Kanidm 1.11.2 Offline Build and RPM Packaging on FIPS Rocky 9.8 (M2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Kanidm 1.11.2 (server, CLI, unixd, PAM/NSS, SSH tools) **offline on a FIPS-mode, CUI-hardened Rocky 9.8 VM**, package it as RPMs, and answer ADR 0001's two blocking questions with evidence:
- **Q1 (packaging):** can Kanidm be built and packaged for Rocky 9, offline?
- **Q2 (FIPS):** which of its crypto runs outside a FIPS-validated module? (This plan covers the static and build side; runtime behaviour is Plan 3.)

**Architecture:** A dedicated build VM, **build1** (192.168.100.20), runs on aero's `br-lab`.
- It is installed unattended from the local DVD by a kickstart **derived from dc2's own `anaconda-ks.cfg`**.
- Compilers live **only** on build1; it never runs identity services.
- The build uses the vendored crates and Rust 1.96 already verified in Plan 1, with cargo forced offline. The VM also has no route off the lab.
- RPMs are "binary repack" spec files: build once with `make release/*`, then package the outputs.
- A final, separate **FIPS-variant experiment** tries `rustls` against AWS-LC's FIPS module.

**Tech Stack:** Rocky 9.8 kickstart + virt-install (aero), Rust 1.96 / cargo (offline), rpmbuild, OpenSCAP, Python 3 + pytest (crypto-inventory tool, on the Mac).

**Spec:** `docs/superpowers/specs/2026-09-26-idm-diagnostic-lab-design.md` (rev 2, §4.1–4.4, milestone M2)

## Why run this test: what we will know afterwards that we don't know now

Kanidm is the proposed replacement for FreeIPA on dc2 (ADR 0001). The ADR leaves two questions open, and dc2 can't be finalised until they're answered. Kanidm **publishes no packages for Rocky or RHEL**, so "install it" really means "build it and package it yourself". Nobody on this project has yet done that on a machine hardened like dc2.

| Question | What we know today | What we'll know after Plan 2 | Why it matters |
|---|---|---|---|
| **1. Can Kanidm be built and packaged for Rocky 9 at all?** (ADR Q1) | Only that the source compiles on the Mac and that upstream ships Debian/openSUSE packaging. | Yes or no, **on a FIPS + CUI-hardened Rocky 9.8 machine with no internet**, plus a written, repeatable recipe and a list of every defect hit and how it was fixed. | If it can't be done reliably, Kanidm isn't viable for dc2 and the ADR must be reopened. |
| **2. Does the hardening get in the way?** | Unknown. FIPS mode and the CUI profile can break compilers, Go, cmake or rpmbuild. | Exactly which build tools (if any) fail under FIPS/CUI, and the cure for each. | dc2 is FIPS + CUI; a recipe that works only on a soft machine is worthless there. |
| **3. Is Kanidm's cryptography FIPS-validated?** (ADR Q2) | Strong static evidence that it is **not**: Kanidm doesn't use Rocky's FIPS-validated OpenSSL; it carries its own crypto (non-FIPS AWS-LC, ring, RustCrypto). | A documented inventory of every crypto library in the build, plus a tested answer on whether a **FIPS-module variant** (AWS-LC FIPS) can be built, and what stays outside it even then. For example, Argon2 password hashing isn't a FIPS-approved algorithm at all. | This decides what the System Security Plan can truthfully claim for NIST SP 800-171 **3.13.11 (FIPS-validated cryptography for CUI)**: compliant, compliant with a variant build, or an accepted risk / POA&M item. |
| **4. What exactly gets installed, and where?** | Upstream docs, which disagree with each other on some paths. | A concrete RPM file list (binaries, PAM/NSS modules, systemd units, config paths) that matches the compiled-in paths. | It becomes the **independent reference** against which Jeff's documentation-only dc2 build is checked (the acceptance test). |
| **5. What does a build cost?** | Unknown. | Build time and machine size on real hardware. | Kanidm releases often, and every upgrade means a rebuild, so this is the recurring maintenance cost for dc2. |

**What Plan 2 will *not* tell us** (that is Plan 3):
- whether the server actually runs correctly under FIPS and SELinux;
- whether logins, MFA and SSH keys work end to end on client machines;
- how the TPM and disk-encryption options behave (see below).

Plan 2 answers "can we produce trustworthy packages?". Plan 3 answers "do they work?".

## Decisions recorded for this plan (ISSO, 2026-09-27)

- **SELinux: enforcing on every VM**, and unixd is built with Kanidm's `selinux` feature.
- **Build VM size: 12 vCPU / 16 GB, approved**, then shrunk to the spec's 6 / 8 afterwards.
- **TPM: not in Plan 2** (the decision was delegated). Reasons:
  - Kanidm's `tpm` feature only protects the credentials cached **on client machines**, not the server.
  - Building it needs `tpm2-tss-devel`, which isn't on the DVD.
  - Recording it as a Plan 3 experiment costs nothing now.

  VMs will **never share aero's physical TPM**. The DVD ships **`swtpm`**, a software TPM that gives each VM its own private emulated TPM, so the experiment stays inside the lab.
- **Disk encryption: none on build1** (a disposable build machine that must boot unattended). **Plan 3 experiment:** LUKS on a client or server VM, unlocked at boot by its virtual TPM using **`clevis-luks` + `clevis-pin-tpm2`** (both on the DVD). That's how dc2 could have encryption *and* unattended reboots, and it answers the "LUKS key held by the TPM" question safely before anyone tries it on real hardware.

## Global Constraints

- **Offline:** build1 has no gateway and no DNS beyond the lab. All inputs come from the Mac (already verified: `lab/inputs/MANIFEST.txt`). cargo runs with `net.offline = true`.
- **Fidelity:** build1 is **FIPS** (`fips=1` at install) with **SELinux enforcing** and the **CUI profile at install** (as dc2). It also mirrors dc2's tailoring, which unselects only `sysctl_user_max_user_namespaces`.
- **Lab deviations from dc2's kickstart:**
  - no LUKS (unattended boot);
  - local DVD instead of the internet;
  - lab IP;
  - passwordless sudo for `itadmin`;
  - root locked.

  Each is logged in `lab/vm-deviations.md`.
- **Build profile:** `KANIDM_BUILD_PROFILE=release_linux`, so paths are `/etc/kanidm/server.toml`, `/etc/kanidm/config`, `/etc/kanidm/unixd`, the UI at `/usr/share/kanidm/ui/hpkg`, and the admin socket at `/var/run/kanidmd/sock`. Packaging paths **must** match this profile.
- **Features:** unixd is built with `unix,selinux`. SELinux labelling of the home directories it creates is needed on enforcing Rocky. `tpm` is **off** (see Decisions: virtual TPM + clevis is a Plan 3 experiment).
- **Systemd units:** start from upstream's **`platform/opensuse/*.service`**, which have `StateDirectory` and `DynamicUser`.
- **Independent cross-check:** don't read the dc2 repo's Kanidm runbooks. Findings go to `lab/adr0001-q1-packaging.md` and `lab/adr0001-q2-fips.md` in **this** (public) repo.
- VM sizing for this plan: build1 gets **12 vCPU / 16 GB / 80 GB thin** while it's the only VM. Record this against the spec's 6/8 figure, and shrink it after Plan 2.
- Run a pre-publication scan before any push.

## Review Focus

1. **The unattended install stalls** (a kickstart error, a missing package, a LUKS prompt), and nobody sees it because there's no GUI. `b7` logs the serial console to a file and times out with a clear message. *Task 2, Step 3.*
2. **cargo silently tries the network**, so an "offline build" isn't proven. `net.offline = true` plus a VM with no route: any fetch attempt fails loudly. *Task 5, Step 3.*
3. **Binaries compiled with one profile's paths but packaged at another's** (the likely ADR "build profile flag error"). Verify the compiled-in paths with `strings`/`--help` before packaging. *Task 5, Step 4.*
4. **RPM file names or locations that PAM/NSS won't find** (`pam_kanidm.so` in `/usr/lib64/security/`, `libnss_kanidm.so.2` in `/usr/lib64/`). The spec is checked with `rpm -qpl` against an explicit expected list. *Task 6, Step 4.*
5. **FIPS mode breaks a build tool** (Go, cmake or rpmbuild digests) and the failure gets misread as a Kanidm defect. Every failure is recorded with its tool and error text in the Q1 report before any workaround. *Tasks 5, 6 and 8.*

---

## File Structure

| Path | Responsibility |
|---|---|
| `lab/kickstart/dc2-reference/` | verbatim copies of dc2's `anaconda-ks.cfg` and `dc2-cui-tailoring.xml` (read-only references) |
| `lab/kickstart/build1.ks.in` | build1 kickstart template (`@SSH_PUBKEY@` substituted at use) |
| `lab/host/b7-vm-build1.sh` | creates build1 with virt-install, waits, starts it, snapshots `golden` |
| `lab/vm/push-build1.sh` | Mac → build1: copies inputs and build scripts |
| `lab/kanidm/build.sh` | runs ON build1: Rust install, offline build, timings, hashes |
| `lab/kanidm-rpm/kanidm.spec` | RPM spec (subpackages: server, clients, unixd) |
| `lab/kanidm-rpm/build-rpms.sh` | runs ON build1: stages files and runs rpmbuild |
| `lab/kanidm-rpm/units/` | systemd units (from upstream `platform/opensuse`) |
| `tools/crypto_inventory.py` + `tests/test_crypto_inventory.py` | lists crypto crates from a `Cargo.lock` (FIPS analysis) |
| `lab/vm-deviations.md` | build1 differences from dc2 |
| `lab/adr0001-q1-packaging.md`, `lab/adr0001-q2-fips.md` | the two reports |

---

### Task 1: dc2 reference files and the build1 kickstart

**Files:** Create `lab/kickstart/dc2-reference/anaconda-ks.cfg`, `lab/kickstart/dc2-reference/dc2-cui-tailoring.xml`, `lab/kickstart/build1.ks.in`, `lab/vm-deviations.md`

**Interfaces:** Produces `build1.ks.in` with the single placeholder `@SSH_PUBKEY@`.

- [ ] **Step 1: Copy dc2's references verbatim** (the root password in dc2's file is already redacted)

```bash
mkdir -p lab/kickstart/dc2-reference
for f in anaconda-ks.cfg dc2-cui-tailoring.xml; do
  gh api "repos/The-CyberHygiene-Project/cyberhygiene-dc2/contents/$f" -H "Accept: application/vnd.github.raw" > "lab/kickstart/dc2-reference/$f"
done
grep -c REDACTED lab/kickstart/dc2-reference/anaconda-ks.cfg
```
Expected: `1` (confirms no real secret is copied)

- [ ] **Step 2: Write `lab/kickstart/build1.ks.in`**

```
# build1: offline Kanidm build host (disposable). DERIVED FROM cyberhygiene-dc2/anaconda-ks.cfg.
# Differences from dc2 are listed in lab/vm-deviations.md.
text
cdrom
poweroff
lang en_US.UTF-8
keyboard --vckeymap=us --xlayouts='us'
timezone America/Denver --utc
network --bootproto=static --device=link --ip=192.168.100.20 --netmask=255.255.255.0 --nodefroute --noipv6 --activate --hostname=build1.lab.test
firewall --enabled --service=ssh
selinux --enforcing
rootpw --lock
user --name=itadmin --groups=wheel
sshkey --username=itadmin "@SSH_PUBKEY@"
bootloader --append="fips=1"
zerombr
ignoredisk --only-use=vda
clearpart --all --initlabel --drives=vda
part /boot --fstype=xfs --size=1024
part pv.01 --size=1 --grow
volgroup rl_build1 pv.01
logvol /              --vgname=rl_build1 --name=root          --fstype=xfs --size=15360
logvol /home          --vgname=rl_build1 --name=home          --fstype=xfs --size=35840
logvol /tmp           --vgname=rl_build1 --name=tmp           --fstype=xfs --size=5120
logvol /var           --vgname=rl_build1 --name=var           --fstype=xfs --size=10240
logvol /var/log       --vgname=rl_build1 --name=var_log       --fstype=xfs --size=3072
logvol /var/log/audit --vgname=rl_build1 --name=var_log_audit --fstype=xfs --size=3072
logvol /var/tmp       --vgname=rl_build1 --name=var_tmp       --fstype=xfs --size=3072
logvol swap           --vgname=rl_build1 --name=swap          --size=4096

%addon com_redhat_kdump --disable
%end

%addon com_redhat_oscap
    content-type = scap-security-guide
    profile = xccdf_org.ssgproject.content_profile_cui
%end

%packages
@^minimal-environment
audit
chrony
crypto-policies
firewalld
openscap-scanner
scap-security-guide
openssh-server
sudo
gcc
gcc-c++
make
clang
clang-devel
cmake
golang
perl-FindBin
pkgconf-pkg-config
pam-devel
systemd-devel
libselinux-devel
rpm-build
rpmdevtools
rpmlint
tar
xz
rsync
%end

%post --log=/root/ks-post.log
set -x
printf 'itadmin ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-itadmin-lab
chmod 0440 /etc/sudoers.d/90-itadmin-lab
# Lab time source is aero.
sed -i -E 's/^(pool|server) .*/server 192.168.100.1 iburst/' /etc/chrony.conf
# Mirror dc2-cui-tailoring.xml: dc2 UNSELECTS sysctl_user_max_user_namespaces.
grep -rlE 'user\.max_user_namespaces' /etc/sysctl.d /etc/sysctl.conf 2>/dev/null | xargs -r sed -i '/user\.max_user_namespaces/d'
rm -f /etc/sysctl.d/user_max_user_namespaces.conf
# The initramfs was built earlier with the CUI sysctl files inside it; rebuild it, or the value still applies at boot.
dracut -f --regenerate-all
%end
```

- [ ] **Step 3: Validate the kickstart syntax**

Run: `uvx --from pykickstart ksvalidator -v RHEL9 <(sed 's/@SSH_PUBKEY@/ecdsa-sha2-nistp384 AAAA test/' lab/kickstart/build1.ks.in)`
Expected: no output and exit 0. If a directive is rejected (e.g. an option this RHEL9 version lacks), fix it to the validator's suggestion and record a ruling.

- [ ] **Step 4: Write `lab/vm-deviations.md`**

```markdown
# Lab VMs: deviations from dc2's kickstart

| VM | Deviation | Why |
|---|---|---|
| build1 | install from local DVD (`cdrom`), not `url` to the internet | lab is offline |
| build1 | **no LUKS** on the logical volumes | unattended boot of a disposable build VM (LUKS + virtual-TPM unlock via clevis is a Plan 3 experiment) |
| build1 | static 192.168.100.20/24, no default route, no DNS | lab network |
| build1 | `rootpw --lock`; `itadmin` SSH-key login + passwordless sudo | Mac drives the build over SSH |
| build1 | chrony → 192.168.100.1 (aero) | lab time source |
| build1 | minimal environment + compilers (dc2 is graphical-server) | build host only; never runs identity services |
| build1 | 12 vCPU / 16 GB during Plan 2 (spec: 6 / 8) | only VM on aero; shortens the compile |
| all | `sysctl_user_max_user_namespaces` left as dc2 tailoring has it (unselected) | mirror dc2 |
```

- [ ] **Step 5: Commit**

```bash
git add lab/kickstart lab/vm-deviations.md
git commit -m "Plan 2: dc2 reference kickstart/tailoring, build1 kickstart (validated), VM deviations"
```

---

### Task 2: Create build1 on aero (b7)

**Files:** Create `lab/host/b7-vm-build1.sh`; modify `lab/host/push.sh` (also copy `lab/kickstart/*.ks`)

**Interfaces:**
- Consumes: `lib.sh` (Plan 1), `build1.ks.in` (Task 1), the DVD ISO at `/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso`.
- Produces: a running VM `build1` at 192.168.100.20 with snapshot `golden`, plus the console log at `/data/libvirt/build1-install.log`.

- [ ] **Step 1: Render the kickstart on the Mac and copy it with the host scripts**

In `lab/host/push.sh`, after the `scp` of `*.sh`, add:
```bash
sed "s|@SSH_PUBKEY@|$(cat ~/.ssh/aero_ecdsa.pub)|" "$here/../kickstart/build1.ks.in" > /tmp/build1.ks
scp -q /tmp/build1.ks aero:/tmp/lab-host/build1.ks
```

- [ ] **Step 2: Write `lab/host/b7-vm-build1.sh`**

```bash
#!/usr/bin/env bash
# b7: unattended install of build1 from the local DVD, then start it and snapshot "golden".
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
KS=/tmp/lab-host/build1.ks; ISO=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso
DISK=/data/libvirt/images/build1.qcow2; LOG=/data/libvirt/build1-install.log
[[ -f $KS ]] || die "missing $KS (run via push.sh)"
if virsh dominfo build1 >/dev/null 2>&1; then log "build1 already exists"; exit 0; fi
(( CHECK )) && { log "[check] would: virt-install build1 (12 vCPU, 16 GB, 80 GB) from $ISO with $KS"; exit 0; }
run "install build1 (unattended; serial console logged to $LOG)" \
  virt-install --name build1 --memory 16384 --vcpus 12 --cpu host-passthrough \
    --osinfo detect=on,name=rhel9-unknown \
    --disk path="$DISK",size=80,format=qcow2 \
    --location "$ISO" --network bridge=br-lab \
    --initrd-inject "$KS" \
    --extra-args "inst.ks=file:/build1.ks fips=1 console=ttyS0,115200 inst.text" \
    --graphics none --console pty,target_type=serial --serial file,path="$LOG" \
    --noautoconsole --wait 90
state=$(virsh domstate build1)
[[ $state == "shut off" ]] || die "install did not finish in 90 min (state: $state); see $LOG"
run "start build1" virsh start build1
log "b7 done: install finished, build1 starting"
```

- [ ] **Step 3: Dry run, then install** (~20–40 minutes, run in the background)

Run:
```bash
chmod +x lab/host/b7-vm-build1.sh && shellcheck -x -P lab/host lab/host/*.sh
lab/host/push.sh b7-vm-build1 --check
lab/host/push.sh b7-vm-build1
```
Expected: `b7 done`. If it fails, read `ssh aero sudo tail -50 /data/libvirt/build1-install.log` and record the cause in the Q1 report (Review Focus #1).

- [ ] **Step 4: Reach build1 from the Mac and verify its posture**

Append to `~/.ssh/config`:
```
Host build1
    HostName 192.168.100.20
    User itadmin
    IdentityFile ~/.ssh/aero_ecdsa
    IdentitiesOnly yes
```
Run: `for i in $(seq 60); do ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new build1 true 2>/dev/null && break; sleep 5; done; ssh build1 'fips-mode-setup --check; getenforce; sysctl user.max_user_namespaces; ip route; rustc -V 2>&1 | head -1'`
Expected: `FIPS mode is enabled.`, `Enforcing`, a non-zero namespace count (mirrors dc2), **only** the 192.168.100.0/24 route, and `rustc: command not found`.

- [ ] **Step 5: Snapshot and commit**

Run: `ssh aero 'sudo virsh snapshot-create-as build1 golden "clean install, before Rust/Kanidm"'`
```bash
git add lab/host/b7-vm-build1.sh lab/host/push.sh
git commit -m "aero b7: unattended FIPS/CUI build1 VM from the local DVD; golden snapshot"
```

---

### Task 3: Rust 1.96 and inputs on build1

**Files:** Create `lab/vm/push-build1.sh`

**Interfaces:** Produces `~/inputs/` on build1 (Rust tarball, Kanidm source, vendor tarball, `MANIFEST.txt`, `verify.sh`) and `/opt/rust-1.96/bin/{rustc,cargo}`.

- [ ] **Step 1: Let `verify.sh` check a subset** (build1 gets only 3 of the 6 inputs)

Add a failing case to `lab/inputs/test_inputs.sh`: a manifest holding only the three Rust/Kanidm lines, run with `EXPECTED_OVERRIDE="rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz kanidm-1.11.2.tar.gz kanidm-1.11.2-vendor.tar.gz"`, must exit 0; the same manifest **without** the override must exit 1 (`NOTLISTED`).
Run: `bash lab/inputs/test_inputs.sh`. Expected: the new override case FAILS (still `NOTLISTED`).
Then in `verify.sh`, directly after the `EXPECTED=(...)` array, add:
```bash
[[ -n ${EXPECTED_OVERRIDE:-} ]] && read -r -a EXPECTED <<<"$EXPECTED_OVERRIDE"
```
Run `bash lab/inputs/test_inputs.sh` again. Expected: all cases pass.

- [ ] **Step 2: Write `lab/vm/push-build1.sh`**

```bash
#!/usr/bin/env bash
# Copy the verified build inputs and the build scripts from the Mac to build1, then re-verify there.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
want="rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz kanidm-1.11.2.tar.gz kanidm-1.11.2-vendor.tar.gz $*"   # extra input names as arguments
ssh build1 'mkdir -p ~/inputs ~/scripts'
for f in $want; do rsync -a "$IN/$f" build1:inputs/; done
grep -E '^(rust-1\.96|kanidm-1\.11\.2)' "$here/inputs/MANIFEST.txt" > /tmp/build1-manifest.txt
rsync -a /tmp/build1-manifest.txt build1:inputs/MANIFEST.txt
rsync -a "$here/inputs/verify.sh" build1:inputs/
rsync -a "$here/kanidm" "$here/kanidm-rpm" build1:scripts/
ssh build1 "IDM_INPUTS=~/inputs IDM_MANIFEST=~/inputs/MANIFEST.txt EXPECTED_OVERRIDE='$want' bash ~/inputs/verify.sh" \
  || { echo "inputs failed verification on build1"; exit 1; }
```
Task 8 pushes its extra tarball with `lab/vm/push-build1.sh kanidm-1.11.2-fips-vendor.tar.gz`.

- [ ] **Step 3: Push and install Rust**

Run:
```bash
chmod +x lab/vm/push-build1.sh && shellcheck lab/vm/push-build1.sh && lab/vm/push-build1.sh
ssh build1 'cd /tmp && tar -xJf ~/inputs/rust-1.96.0-x86_64-unknown-linux-gnu.tar.xz && sudo ./rust-1.96.0-x86_64-unknown-linux-gnu/install.sh --prefix=/opt/rust-1.96 --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu >/dev/null && /opt/rust-1.96/bin/rustc -V && /opt/rust-1.96/bin/cargo -V'
```
Expected: three `OK` lines from verify, then `rustc 1.96.0 …` and `cargo 1.96.0 …`.

- [ ] **Step 4: Commit**

```bash
git add lab/vm/push-build1.sh lab/inputs/verify.sh lab/inputs/test_inputs.sh
git commit -m "build1: verified input push; Rust 1.96 from the signed standalone installer"
```

---

### Task 4: Crypto inventory tool (static FIPS analysis)

**Files:** Create `tools/crypto_inventory.py`, `tests/test_crypto_inventory.py`

**Interfaces:** Produces `inventory(lock_text: str) -> list[dict]`, where each item is `{name, version, family}` and `family ∈ {"aws-lc", "aws-lc-fips", "ring", "openssl", "rustcrypto", "other-crypto"}`. The CLI `uv run python tools/crypto_inventory.py <Cargo.lock>` prints a markdown table.

- [ ] **Step 1: Write the failing test**

```python
from tools.crypto_inventory import inventory

LOCK = '''
[[package]]
name = "aws-lc-sys"
version = "0.44.0"

[[package]]
name = "ring"
version = "0.17.14"

[[package]]
name = "argon2"
version = "0.5.3"

[[package]]
name = "serde"
version = "1.0.228"

[[package]]
name = "aws-lc-fips-sys"
version = "0.13.0"
'''


def test_classifies_crypto_crates_and_ignores_others():
    got = {i["name"]: i["family"] for i in inventory(LOCK)}
    assert got == {"aws-lc-sys": "aws-lc", "ring": "ring", "argon2": "rustcrypto",
                   "aws-lc-fips-sys": "aws-lc-fips"}


def test_no_openssl_is_reported_as_absent():
    assert all(i["family"] != "openssl" for i in inventory(LOCK))
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `uv run pytest tests/test_crypto_inventory.py -q`
Expected: FAIL (`ModuleNotFoundError: No module named 'tools'`)

- [ ] **Step 3: Implement `tools/__init__.py` (empty) and `tools/crypto_inventory.py`**

```python
"""Which crypto implementations does a Rust build pull in? (ADR 0001 Q2, static half.)"""
import re
import sys

FAMILIES = [
    ("aws-lc-fips", re.compile(r"^aws-lc-fips-sys$")),
    ("aws-lc", re.compile(r"^aws-lc-(sys|rs)$")),
    ("ring", re.compile(r"^ring$")),
    ("openssl", re.compile(r"^openssl(-sys)?$")),
    ("rustcrypto", re.compile(r"^(argon2|sha1|sha2|sha3|hmac|hkdf|pbkdf2|aes|aes-gcm|chacha20poly1305|p256|p384|p521|ecdsa|ed25519-dalek|rsa|blake2|md-5|des|ctr|cbc)$")),
    ("other-crypto", re.compile(r"^(boring|boring-sys|mbedtls|nettle|libsodium-sys|tss-esapi)$")),
]


def inventory(lock_text):
    out = []
    for block in lock_text.split("[[package]]"):
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        ver = re.search(r'^version = "([^"]+)"', block, re.M)
        if not name:
            continue
        for fam, rx in FAMILIES:
            if rx.match(name.group(1)):
                out.append({"name": name.group(1), "version": ver.group(1) if ver else "?", "family": fam})
                break
    return sorted(out, key=lambda i: (i["family"], i["name"]))


def main():
    items = inventory(open(sys.argv[1]).read())
    print("| family | crate | version |\n|---|---|---|")
    for i in items:
        print(f"| {i['family']} | {i['name']} | {i['version']} |")
    fams = {i["family"] for i in items}
    print(f"\nOpenSSL present: {'yes' if 'openssl' in fams else 'NO'} · "
          f"AWS-LC FIPS module present: {'yes' if 'aws-lc-fips' in fams else 'NO'}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the tests, then the real inventory**

Run: `uv run pytest tests/test_crypto_inventory.py -q && uv run python tools/crypto_inventory.py <(tar -xzOf ~/idm-lab-inputs/kanidm-1.11.2.tar.gz kanidm-1.11.2/Cargo.lock)`
Expected: `2 passed`, then a table including `aws-lc-sys 0.44.0`, `ring 0.17.14`, `argon2 0.5.3`, and the line `OpenSSL present: NO · AWS-LC FIPS module present: NO`.

- [ ] **Step 5: Start the Q2 report, then commit**

Create `lab/adr0001-q2-fips.md` with the heading, the date, the inventory table from Step 4, and this finding:
> Kanidm 1.11.2 links **no OpenSSL**. TLS and primitives use **rustls + aws-lc-rs (non-FIPS AWS-LC build)**, plus `ring`; password hashing uses RustCrypto `argon2`. None of Kanidm's cryptography passes through Rocky's FIPS-validated OpenSSL provider, **regardless of the host's FIPS mode**. The runtime behaviour on a FIPS host is examined in Plan 3.
```bash
git add tools tests/test_crypto_inventory.py lab/adr0001-q2-fips.md
git commit -m "Crypto inventory tool; Q2 static finding: no OpenSSL, non-FIPS AWS-LC + ring + RustCrypto"
```

---

### Task 5: Offline baseline build on build1

**Files:** Create `lab/kanidm/build.sh`

**Interfaces:**
- Consumes: `~/inputs` and `/opt/rust-1.96` (Task 3).
- Produces: `~/kanidm-build/target/release/{kanidmd, kanidm, kanidm_unixd, kanidm_unixd_tasks, kanidm-unix, kanidm_ssh_authorizedkeys, kanidm_ssh_authorizedkeys_direct, libpam_kanidm.so, libnss_kanidm.so}`, plus `~/kanidm-build/build.log` (timings) and `~/kanidm-build/SHA256SUMS`.

- [ ] **Step 1: Write `lab/kanidm/build.sh`**

```bash
#!/usr/bin/env bash
# Runs ON build1. Offline build of Kanidm 1.11.2 with the release_linux profile.
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
: > "$W/build.log"
b() { local t=$1; shift; local s; s=$(date +%s); "$@" >>"$W/build.log" 2>&1 || { echo "FAILED: $t (see $W/build.log)"; tail -30 "$W/build.log"; exit 1; }; echo "$t $(( $(date +%s) - s )) s" | tee -a "$W/timings.txt"; }
: > "$W/timings.txt"
b kanidmd        cargo build --locked -p daemon --bin kanidmd --release
b kanidm         cargo build --locked -p kanidm_tools --bin kanidm --release
b pam_kanidm     cargo build --locked -p pam_kanidm --release
b nss_kanidm     cargo build --locked -p nss_kanidm --release
b unixd          cargo build --locked --features unix,selinux -p kanidm_unix_int --release --bin kanidm_unixd --bin kanidm_unixd_tasks --bin kanidm-unix
b ssh            cargo build --locked --release --bin kanidm_ssh_authorizedkeys --bin kanidm_ssh_authorizedkeys_direct
cd "$CARGO_TARGET_DIR/release"
sha256sum kanidmd kanidm kanidm_unixd kanidm_unixd_tasks kanidm-unix kanidm_ssh_authorizedkeys \
  kanidm_ssh_authorizedkeys_direct libpam_kanidm.so libnss_kanidm.so > "$W/SHA256SUMS"
echo "BUILD OK"; cat "$W/timings.txt"
```
(These are the Makefile's `release/*` targets expanded, with `--locked` added and `selinux` added to unixd's features.)

- [ ] **Step 2: Snapshot before building**

Run: `ssh aero 'sudo virsh snapshot-create-as build1 rust-ready "Rust 1.96 + inputs, before Kanidm build"'`

- [ ] **Step 3: Build** (long, in the background; a first build is expected to take 30–90 minutes)

Run: `lab/vm/push-build1.sh && ssh build1 'bash ~/scripts/kanidm/build.sh' > /tmp/kanidm-build.out 2>&1`
Expected: `BUILD OK` and six timing lines. Any `FAILED:` line: record the target, the tool and the last error lines in `lab/adr0001-q1-packaging.md` under "Defects" **before** changing anything. That covers a missing `-devel` package, a FIPS-mode tool failure (Review Focus #5), and a network attempt (Review Focus #2: it must fail with an offline/no-route error, never succeed). Then fix, record a ruling, and re-run (the build resumes from cargo's cache).

- [ ] **Step 4: Verify the binaries and their compiled-in profile** (Review Focus #3)

Run:
```bash
ssh build1 'cd ~/kanidm-build/target/release && ./kanidmd version; ./kanidm version;
  strings kanidmd | grep -m1 -F /etc/kanidm/server.toml; strings kanidm_unixd | grep -m1 -F /etc/kanidm/unixd;
  strings kanidmd | grep -m1 -F /usr/share/kanidm/ui/hpkg; ldd kanidm_unixd | grep -i selinux'
```
Expected: both report `1.11.2`, all three paths are found, and `libselinux.so` is linked (the `selinux` feature took effect).

- [ ] **Step 5: Commit**

```bash
git add lab/kanidm/build.sh
git commit -m "build1: offline Kanidm 1.11.2 build (release_linux profile, unixd +selinux)"
```

---

### Task 6: RPM packaging

**Files:** Create `lab/kanidm-rpm/kanidm.spec`, `lab/kanidm-rpm/build-rpms.sh`, and `lab/kanidm-rpm/units/{kanidmd,kanidm-unixd,kanidm-unixd-tasks}.service` (copied verbatim from upstream `platform/opensuse/`)

**Interfaces:** Produces `~/rpmbuild/RPMS/x86_64/kanidm-{server,clients,unixd}-1.11.2-1.lab.el9.x86_64.rpm` on build1.

- [ ] **Step 1: Copy the upstream units into the repo**

```bash
mkdir -p lab/kanidm-rpm/units
for u in kanidmd kanidm-unixd kanidm-unixd-tasks; do
  tar -xzOf ~/idm-lab-inputs/kanidm-1.11.2.tar.gz "kanidm-1.11.2/platform/opensuse/$u.service" > "lab/kanidm-rpm/units/$u.service"
done
grep -l StateDirectory lab/kanidm-rpm/units/*.service
```
Expected: kanidmd and kanidm-unixd list `StateDirectory` (the spike's defect #2 is handled upstream).

- [ ] **Step 2: Write `lab/kanidm-rpm/kanidm.spec`**

```spec
# Binary repack of an offline build (lab/kanidm/build.sh). Paths follow KANIDM_BUILD_PROFILE=release_linux.
%global debug_package %{nil}
Name:           kanidm
Version:        1.11.2
Release:        1.lab%{?dist}
Summary:        Kanidm identity management (lab build for Rocky 9, FIPS host)
License:        MPL-2.0
URL:            https://github.com/kanidm/kanidm
Source0:        kanidm-%{version}-staged.tar.gz
BuildRequires:  systemd-rpm-macros

%description
Kanidm %{version} built offline from source on a FIPS-mode Rocky 9.8 host.
Built without TPM support. Crypto is not provided by the OS OpenSSL; see adr0001-q2-fips.md.

%package server
Summary: Kanidm identity server (kanidmd)
%description server
The Kanidm server daemon and its web UI assets.

%package clients
Summary: Kanidm command-line and SSH tools
%description clients
kanidm CLI and SSH authorized-keys helpers.

%package unixd
Summary: Kanidm UNIX integration (PAM/NSS, unixd)
Requires: %{name}-clients = %{version}-%{release}
%description unixd
kanidm_unixd, kanidm_unixd_tasks, kanidm-unix, pam_kanidm.so and libnss_kanidm.so.2.

%prep
%setup -q -n staged

%install
install -Dm0755 bin/kanidmd                          %{buildroot}%{_sbindir}/kanidmd
install -Dm0755 bin/kanidm                           %{buildroot}%{_bindir}/kanidm
install -Dm0755 bin/kanidm_ssh_authorizedkeys        %{buildroot}%{_sbindir}/kanidm_ssh_authorizedkeys
install -Dm0755 bin/kanidm_ssh_authorizedkeys_direct %{buildroot}%{_sbindir}/kanidm_ssh_authorizedkeys_direct
install -Dm0755 bin/kanidm_unixd                     %{buildroot}%{_sbindir}/kanidm_unixd
install -Dm0755 bin/kanidm_unixd_tasks               %{buildroot}%{_sbindir}/kanidm_unixd_tasks
install -Dm0755 bin/kanidm-unix                      %{buildroot}%{_sbindir}/kanidm-unix
install -Dm0755 bin/libpam_kanidm.so                 %{buildroot}%{_libdir}/security/pam_kanidm.so
install -Dm0755 bin/libnss_kanidm.so                 %{buildroot}%{_libdir}/libnss_kanidm.so.2
mkdir -p %{buildroot}%{_datadir}/kanidm/ui/hpkg
cp -a ui/. %{buildroot}%{_datadir}/kanidm/ui/hpkg/
install -Dm0644 units/kanidmd.service            %{buildroot}%{_unitdir}/kanidmd.service
install -Dm0644 units/kanidm-unixd.service       %{buildroot}%{_unitdir}/kanidm-unixd.service
install -Dm0644 units/kanidm-unixd-tasks.service %{buildroot}%{_unitdir}/kanidm-unixd-tasks.service
install -dm0755 %{buildroot}%{_sysconfdir}/kanidm
install -Dm0644 examples/server.toml %{buildroot}%{_datadir}/kanidm/examples/server.toml
install -Dm0644 examples/unixd       %{buildroot}%{_datadir}/kanidm/examples/unixd
install -Dm0644 examples/kanidm      %{buildroot}%{_datadir}/kanidm/examples/config

%post server
%systemd_post kanidmd.service
%preun server
%systemd_preun kanidmd.service
%postun server
%systemd_postun_with_restart kanidmd.service
%post unixd
%systemd_post kanidm-unixd.service kanidm-unixd-tasks.service
%preun unixd
%systemd_preun kanidm-unixd.service kanidm-unixd-tasks.service
%postun unixd
%systemd_postun_with_restart kanidm-unixd.service kanidm-unixd-tasks.service

%files server
%{_sbindir}/kanidmd
%{_datadir}/kanidm/ui/hpkg
%{_datadir}/kanidm/examples/server.toml
%{_unitdir}/kanidmd.service
%dir %{_sysconfdir}/kanidm

%files clients
%{_bindir}/kanidm
%{_sbindir}/kanidm_ssh_authorizedkeys
%{_sbindir}/kanidm_ssh_authorizedkeys_direct
%{_datadir}/kanidm/examples/config

%files unixd
%{_sbindir}/kanidm_unixd
%{_sbindir}/kanidm_unixd_tasks
%{_sbindir}/kanidm-unix
%{_libdir}/security/pam_kanidm.so
%{_libdir}/libnss_kanidm.so.2
%{_unitdir}/kanidm-unixd.service
%{_unitdir}/kanidm-unixd-tasks.service
%{_datadir}/kanidm/examples/unixd

%changelog
* Sun Sep 27 2026 idm-assistant lab <lab@lab.test> - 1.11.2-1.lab
- Offline lab build on FIPS Rocky 9.8 (Plan 2)
```

- [ ] **Step 3: Write `lab/kanidm-rpm/build-rpms.sh`**

```bash
#!/usr/bin/env bash
# Runs ON build1: stage the built outputs + upstream assets into a tarball, then rpmbuild.
set -Eeuo pipefail
W=$HOME/kanidm-build; R=$W/target/release; SRC=$W/src; here="$(cd "$(dirname "$0")" && pwd)"
rpmdev-setuptree
S=$(mktemp -d)/staged; mkdir -p "$S/bin" "$S/ui" "$S/units" "$S/examples"
cp "$R"/{kanidmd,kanidm,kanidm_unixd,kanidm_unixd_tasks,kanidm-unix,kanidm_ssh_authorizedkeys,kanidm_ssh_authorizedkeys_direct,libpam_kanidm.so,libnss_kanidm.so} "$S/bin/"
cp -a "$SRC/server/core/static/." "$S/ui/"
cp "$here"/units/*.service "$S/units/"
cp "$SRC/examples/server.toml" "$S/examples/"
cp "$SRC/examples/unixd-safe-default" "$S/examples/unixd"
cp "$SRC/examples/kanidm-safe-default" "$S/examples/kanidm"
tar -czf ~/rpmbuild/SOURCES/kanidm-1.11.2-staged.tar.gz -C "$(dirname "$S")" staged
cp "$here/kanidm.spec" ~/rpmbuild/SPECS/
rpmbuild -bb ~/rpmbuild/SPECS/kanidm.spec
ls -la ~/rpmbuild/RPMS/x86_64/
```

- [ ] **Step 4: Build and check the packages** (Review Focus #4)

Run:
```bash
lab/vm/push-build1.sh && ssh build1 'bash ~/scripts/kanidm-rpm/build-rpms.sh' | tail -5
ssh build1 'cd ~/rpmbuild/RPMS/x86_64 && for p in *.rpm; do echo "== $p"; rpm -qpl "$p"; done; rpm -K *.rpm; rpmlint *.rpm | tail -5; systemd-analyze verify ~/rpmbuild/BUILDROOT/*/usr/lib/systemd/system/*.service 2>&1 | grep -v "not found" | head'
```
Expected:
- **three** RPMs;
- `/usr/lib64/security/pam_kanidm.so`, `/usr/lib64/libnss_kanidm.so.2`, `/usr/share/kanidm/ui/hpkg/…` and all three units are listed;
- `rpm -K` shows `digests OK` (the RPMs are unsigned by design);
- rpmlint output is saved (warnings are listed in the Q1 report; errors are fixed or ruled on);
- `systemd-analyze verify` shows no errors other than "binary not found" (the packages aren't installed on build1).

- [ ] **Step 5: Commit**

```bash
git add lab/kanidm-rpm
git commit -m "Kanidm 1.11.2 RPMs (server, clients, unixd): release_linux paths, upstream openSUSE units"
```

---

### Task 7: Publish the RPMs to aero's lab repo

**Files:** Create `lab/kanidm-rpm/BUILD-RECORD.md`

- [ ] **Step 1: Copy to aero and index**

Run:
```bash
scp 'build1:rpmbuild/RPMS/x86_64/*.rpm' /tmp/ && scp /tmp/kanidm-*1.11.2*.rpm aero:/tmp/
ssh aero 'sudo cp /tmp/kanidm-*1.11.2*.rpm /data/lab-inputs/rpms/ && sudo createrepo_c -q /data/lab-inputs/rpms && dnf -q repoquery --repo lab-local "kanidm*"'
```
Expected: the three `kanidm-*-1.11.2-1.lab.el9` packages are listed from `lab-local`.

- [ ] **Step 2: Record the build**

`BUILD-RECORD.md` holds: date, build1 facts (FIPS, SELinux, kernel), Rust version, feature flags, per-target timings (`timings.txt`), `SHA256SUMS` of the binaries, `sha256sum` of the three RPMs, and the rpmlint summary.
```bash
git add lab/kanidm-rpm/BUILD-RECORD.md && git commit -m "Kanidm RPMs published to aero lab-local repo; build record"
```

---

### Task 8: FIPS-variant experiment (rustls → AWS-LC FIPS module)

**Files:** Create `lab/kanidm/fips-variant.patch` and `lab/kanidm/build-fips.sh`; add `kanidm-1.11.2-fips-vendor.tar.gz` to the manifest.

**Interfaces:** Outcome recorded in `lab/adr0001-q2-fips.md` §"FIPS variant": **builds / fails (why)**, the binary's AWS-LC module identification, and what remains outside the module.

- [ ] **Step 1: On the Mac, make the variant's lockfile and vendor set** (network needed on the Mac only)

```bash
W=/tmp/kfips; rm -rf $W && mkdir -p $W && tar -xzf ~/idm-lab-inputs/kanidm-1.11.2.tar.gz -C $W --strip-components=1 && cd $W
cp Cargo.toml Cargo.toml.orig
perl -0pi -e 's/(rustls = \{ version = "0\.23\.37", default-features = false, features = \[\n    "std",\n    "aws_lc_rs",)/$1\n    "fips",/' Cargo.toml
diff -u Cargo.toml.orig Cargo.toml > ~/idm-assistant/lab/kanidm/fips-variant.patch; test -s ~/idm-assistant/lab/kanidm/fips-variant.patch
cargo fetch                      # adds only the new crates to Cargo.lock; existing pins stay
diff <(tar -xzOf ~/idm-lab-inputs/kanidm-1.11.2.tar.gz kanidm-1.11.2/Cargo.lock) Cargo.lock | grep '^[<>] name' 
cargo vendor --locked --versioned-dirs vendor > vendor-config.toml
tar -czf ~/idm-lab-inputs/kanidm-1.11.2-fips-vendor.tar.gz Cargo.toml Cargo.lock vendor vendor-config.toml
```
Expected: the patch is non-empty (one added line), and the lockfile diff shows **only added** packages, including `aws-lc-fips-sys`. Then add the tarball's line to `MANIFEST.txt` (same `name|ver|bytes|sha256|…` format as `fetch.sh` writes). If `cargo fetch` fails to resolve the feature, **stop the experiment** and record why. That alone answers "not buildable as-is".

- [ ] **Step 2: Build on build1** (needs Go, cmake and perl from the DVD; already installed)

`lab/kanidm/build-fips.sh` = `build.sh` with its own `$W=$HOME/kanidm-build-fips`, extracting the FIPS vendor tarball over the source, and building only `kanidmd` and `kanidm`.
Run: `lab/vm/push-build1.sh kanidm-1.11.2-fips-vendor.tar.gz && ssh build1 'bash ~/scripts/kanidm/build-fips.sh' > /tmp/kanidm-fips.out 2>&1`. Record the outcome **either way**.

- [ ] **Step 3: If it built, identify the module**

Run: `ssh build1 'strings ~/kanidm-build-fips/target/release/kanidmd | grep -m3 -iE "AWS-LC FIPS|FIPS 140"'`
Record the strings found. **Note what remains outside the module regardless:** `argon2` (password hashing), `ring` if still linked, and the WebAuthn/COSE code paths. Run `tools/crypto_inventory.py` on the variant's `Cargo.lock`.

- [ ] **Step 4: Commit**

```bash
git add lab/kanidm/fips-variant.patch lab/kanidm/build-fips.sh lab/adr0001-q2-fips.md lab/inputs/MANIFEST.txt
git commit -m "FIPS-variant experiment: rustls/aws-lc-rs 'fips' build of Kanidm 1.11.2 (outcome recorded)"
```

---

### Task 9: Q1 report and publication

**Files:** Create/complete `lab/adr0001-q1-packaging.md`

- [ ] **Step 1: Write the report**

Sections:
1. **Answer to Q1** (one paragraph).
2. **Environment:** build1 and FIPS facts.
3. **Procedure:** link the scripts.
4. **Defects found:** each with tool, error, cause and fix. Compare against the ADR's spike list: profile flag, `StateDirectory`, nsswitch ordering, POSIX password, and the unconfirmed fifth.
5. **Choices made:** `release_linux`, `+selinux`, `-tpm`, opensuse units, binary-repack spec.
6. **Timings.**
7. **What Plan 3 must verify at runtime**, including the virtual-TPM experiments (swtpm; Kanidm `tpm` feature; LUKS + clevis TPM2 unlock).

- [ ] **Step 2: Pre-publication scan, then push**

Run the same scan as Plan 1: secrets, emails, public IPs, personal paths. Then push the `plan2-kanidm-build` branch and open a PR to `main` (as Plan 1).

- [ ] **Step 3: Shrink build1 and snapshot**

Run: `ssh aero 'sudo virsh shutdown build1; sleep 30; sudo virsh setvcpus build1 6 --config --maximum; sudo virsh setvcpus build1 6 --config; sudo virsh setmaxmem build1 8G --config; sudo virsh setmem build1 8G --config; sudo virsh snapshot-create-as build1 built "Kanidm built and packaged"'`
Update `lab/vm-deviations.md`: build1 is back to the spec's 6 vCPU / 8 GB.

---

## Self-review notes
- Spec coverage for M2: build1 VM (§4.3), offline compile + RPMs (§4.4.1), Q1 report, the static half of Q2 plus the FIPS-variant experiment (§4.4.5), SELinux notes (§4.4.6: `+selinux` feature; policy questions are Plan 3). srv1 and clients are Plan 3.
- `verify.sh`'s all-six requirement conflicts with pushing a subset to build1; resolved by the `EXPECTED_OVERRIDE` addition in Task 3 (tested).
- The kickstart syntax is validated before any VM is created; unknown RHEL9 option gaps are handled by the validator step, not guessed.
