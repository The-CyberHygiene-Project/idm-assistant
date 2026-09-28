# Plan 3: srv1 Identity Stack + client2, Runtime FIPS/SELinux Evidence, Virtual TPM (M3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the dc2-style identity stack on **srv1** (BIND, step-ca, a separate SSH CA, Kanidm from our Plan 2 RPMs) and a reference client **client2** (kanidm-unixd). Both are FIPS + SELinux enforcing + CUI + fapolicyd enforcing. Create the lab users, prove logins end to end, and record **runtime** evidence for ADR Q1/Q2. Finish with golden snapshots, a `lab reset`, and the virtual-TPM + LUKS/clevis experiment.

**Architecture:**
- aero serves the DVD and our RPM repo to the VMs over the lab bridge (HTTP on 192.168.100.1 only).
- srv1 and client2 are installed unattended from the DVD by kickstarts built from one shared template. The template is derived from build1's proven kickstart (itself derived from dc2's).
- Everything is driven from the Mac over SSH, by small scripts in `lab/srv1/` and `lab/client/`.
- Secrets are the lab admin passwords, user passwords and TOTP seeds. They live only in `~/idm-lab-secrets` on the Mac (mode 0700) and **never in the repo**.

**Tech Stack:** Rocky 9.8 kickstart + libvirt (aero); BIND 9.16; step-ca 0.30.2 / step-cli 0.31.0 (Go 1.26.1); Kanidm 1.11.2 (our RPMs); OpenSSH CA (ECDSA P-384); authselect; `expect`; swtpm + clevis; Python 3 + pytest (TOTP helper, on the Mac).

**Spec:** `docs/superpowers/specs/2026-09-26-idm-diagnostic-lab-design.md` (rev 2: §4.3, §4.4 steps 2–6, §6 prerequisites, §7 M3, §8)

## Why run this test: what we will know afterwards that we don't know now

Plan 2 proved Kanidm can be **built and packaged**. It did not prove it **runs** on a dc2-hardened machine, or that the pieces of the dc2 stack work together.

| Question | What we know today | What we'll know after Plan 3 | Why it matters |
|---|---|---|---|
| **1. Do our RPMs install and run under full CUI hardening?** | Expected only: fapolicyd trusts RPM-installed files, but no Kanidm RPM has been installed yet. | Whether `kanidmd` and `kanidm-unixd` install and start under **FIPS + SELinux enforcing + fapolicyd enforcing**, and every denial or failure seen. | This is the real Q1 acceptance test. It's the claim Plan 2's report says Plan 3 must prove. |
| **2. Does the dc2 stack work together?** | ADR 0001 describes it; nobody has assembled it on a hardened host. | BIND → step-ca (TLS certificate via ACME, auto-renewal) → Kanidm → client login over SSH, with POSIX password and SSH certificates from a separate SSH CA. | It's the design Jeff will build on dc2. Problems found here are cheap. |
| **3. What does SELinux do to Kanidm?** | Upstream says Kanidm has **no SELinux policy** and suggests making a whole domain permissive. | The exact denials (AVCs) and a recorded choice (see Decisions). | This is the ISSO's decision for dc2 (spec §9, question 2); it needs evidence. |
| **4. Which cryptography is used at runtime, and is any of it refused under FIPS?** | Build-time only: non-FIPS AWS-LC + RustCrypto in Kanidm; step-ca is Go 1.26.1. | The TLS versions, ciphers and key exchange Kanidm and step-ca actually negotiate. Whether step-ca runs with Go's FIPS mode on. Whether TOTP, Argon2 and SSH CA signing work, or are refused, with FIPS on. | Evidence for the 3.13.11 position in the SSP. It also tests the "approved mode unverified" caveat in Plan 2's Q2 report. |
| **5. Is MFA enforced at a Linux login?** | Unknown. Kanidm's unix login uses a **separate POSIX password**; we don't know if its PAM module asks for TOTP. | Whether an SSH or console login through `pam_kanidm` asks for a TOTP code, for which account policies. | This is the question behind the dc1 MFA lockout, and a requirement for 800-171 3.5.3. |
| **6. Can a VM have a TPM, and can it unlock LUKS at boot?** | Unknown to us (your question from Plan 2). | Whether a **software TPM** (swtpm) works in a FIPS VM, and whether **clevis** unlocks a LUKS volume automatically at reboot. | This is how dc2 could have disk encryption *and* unattended reboots. |

**What Plan 3 will *not* tell us:**
- how your CHP build kit interacts with Kanidm (client1, Plan 4);
- the diagnostic collector and repairs (Plan 5);
- WebAuthn/passkey logins (see Decisions).

## Decisions (ISSO, approved 2026-09-27)

All five were approved as recommended. On the passkey: the ISSO has USB security keys, but enrolment is deferred as not needed at this stage.

1. **SELinux (spec §9.2). Recommended: a small lab-only policy module built from the exact denials observed.**
   - We record the denials first.
   - We then load a lab-only module that allows only those, and keep it in the repo as evidence.
   - Upstream's suggestion (`semanage permissive -a unconfined_service_t`) turns off enforcement for *every* unconfined service. We will **not** do that without your say-so.

   The plan **stops** at Task 8, Step 4 for your decision if denials block logins.
2. **WebAuthn user: deferred.** Enrolling a passkey needs a physical security key passed through to a VM. The sixth user is created with no credential and marked "WebAuthn: pending hardware".
3. **Lab-local repo without GPG signatures**, on the VMs as on aero; its integrity comes from the sha256 in the build record. Logged as a deviation.
4. **Kanidm TLS on port 443** (the upstream unit grants `CAP_NET_BIND_SERVICE`). Kanidm domain `idm.kanidm.lab.test` inside DNS zone `kanidm.lab.test`, because upstream advises against using the bare zone as the Kanidm domain.
5. **Kanidm's `tpm` feature stays off.** It needs `tpm2-tss-devel` from Rocky's CRB repository and another fapolicyd-relaxed rebuild. Task 11 tests the TPM itself (swtpm + clevis), which is the part that matters for dc2's disks.

## Global Constraints

- **Offline:** VMs have no default route. Packages come only from the DVD and `lab-local`, served by aero at `http://192.168.100.1:8080/`.
- **Fidelity on srv1 and client2:** `fips=1`, SELinux **enforcing**, CUI profile at install, dc2 tailoring (namespace rule), **fapolicyd enforcing** (never relaxed in Plan 3), root locked.
- **Addresses:** srv1 192.168.100.10 (`srv1.kanidm.lab.test`, aliases `idm` and `ca`), client2 192.168.100.13. Resolver: srv1. Time source: aero (192.168.100.1).
- **Sizes:** srv1 4 vCPU / 6 GB / 60 GB; client2 2 vCPU / 2 GB / 30 GB (spec §4.3). build1 stays shut down during Plan 3 to free memory.
- **srv1 never has compilers; build1 never runs identity services** (spec §8).
- **Secrets never enter the repo:** `~/idm-lab-secrets/` on the Mac only. `.gitignore` blocks `*secret*`, `*.token`, `*.key`. A pre-publication scan runs before any push.
- **SSH key types are FIPS-safe:** ECDSA P-384 (ed25519 is rejected under FIPS).
- **Independent cross-check:** don't read the dc2 repo's Kanidm runbooks. Upstream docs only. Findings go to this repo's `lab/` reports.

## Review Focus

1. **A login path that silently falls back to local accounts** (e.g. `pam_unix` succeeds for a Kanidm user because of a stale `/etc/shadow` entry), so "Kanidm login works" isn't proven. The login test uses users that exist **only** in Kanidm (`getent passwd lab01` must come from Kanidm, and `/etc/passwd` must not contain them). *Task 9, Step 2.*
2. **A lab secret leaks into the repo or the public PR:** a password, reset token, TOTP seed or CA private key. Scripts write secrets only under `~/idm-lab-secrets`, and a test greps the repo for anything that looks like one. *Task 1, Step 4 and Task 12, Step 2.*
3. **The TLS certificate renews but Kanidm keeps serving the old one:** credentials load at start, so renewal must restart kanidmd. The test forces a renewal and compares the served certificate's serial number before and after. *Task 6, Step 5.*
4. **An SSH login succeeds through the wrong mechanism** (a public key via `AuthorizedKeysCommand`, when the test meant the SSH **certificate**). The certificate test uses a key that is **not** registered in Kanidm and checks sshd's log for `Accepted publickey … ECDSA-CERT`. *Task 9, Step 4.*
5. **A FIPS refusal gets misread as a configuration error** (e.g. a key type or cipher rejected under FIPS). Every failure is recorded with its exact error text in the Q2 runtime section before any change. *Tasks 5, 6, 7 and 10.*

---

## File Structure

| Path | Responsibility |
|---|---|
| `lab/host/vm-lib.sh` | `create_vm NAME VCPUS MEM_MB DISK_GB KS [extra virt-install args]`, refactored out of b7 (same safeguards) |
| `lab/host/b7-vm-build1.sh` | now a thin wrapper around `create_vm` |
| `lab/host/b8-lab-repo.sh` | aero: HTTP repo service on 192.168.100.1:8080 (DVD + lab-local) |
| `lab/host/b9-vm-srv1-client2.sh` | aero: creates srv1 and client2 (client2 with a virtual TPM and a second disk) |
| `lab/host/lab-reset.sh` | aero: reverts srv1 + client2 to `golden` |
| `lab/host/test_vm_create.sh` | stub tests for `create_vm` (replaces `test_b7.sh`) and `lab-reset.sh` |
| `lab/kickstart/base.ks.in` + `lab/kickstart/render.sh` | shared kickstart template; `render.sh NAME` → `NAME.ks` |
| `lab/kickstart/test_render.sh` | rendered kickstarts validate and carry the right host facts |
| `lab/srv1/*.sh` | BIND, step-ca, Kanidm server, SSH CA, lab-data scripts (run from the Mac via `lab/srv1/run.sh STEP`) |
| `lab/client/*.sh` | client2 enrolment: repos, CA trust, unixd, authselect profile, sshd |
| `lab/tools/totp.py` + `tests/test_totp.py` | RFC 6238 TOTP code generator (stdlib only) used by the enrolment `expect` scripts |
| `lab/vm-deviations.md` | extended with srv1/client2 rows |
| `lab/adr0001-q1-packaging.md`, `lab/adr0001-q2-fips.md` | new "Runtime (Plan 3)" sections |
| `lab/selinux/` | recorded AVCs + (if approved) the lab-only policy module source |

---

### Task 1: Secrets hygiene and the TOTP helper

**Files:** Create `lab/tools/totp.py`, `tests/test_totp.py`, `lab/tools/secrets-scan.sh`; modify `.gitignore`

**Interfaces:**
- Produces: `totp(secret_b32: str, t: int | None = None, digits=6, step=30) -> str`. CLI: `python3 totp.py BASE32SECRET` prints the current code.
- Produces: `lab/tools/secrets-scan.sh [PATH...]`, which exits 1 on a hit.

- [ ] **Step 1: Write the failing tests** (RFC 6238 Appendix B vectors, SHA-1, 8 digits; secret = ASCII "12345678901234567890")

```python
import base64
from lab.tools.totp import totp

SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_rfc6238_sha1_vectors():
    for t, want in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                    (1234567890, "89005924"), (2000000000, "69279037")]:
        assert totp(SECRET, t=t, digits=8) == want


def test_default_is_six_digits_and_accepts_lowercase_unpadded_secret():
    assert totp(SECRET.lower().rstrip("="), t=59) == "287082"
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `uv run pytest tests/test_totp.py -q`
Expected: FAIL (`ModuleNotFoundError: No module named 'lab'`)

- [ ] **Step 3: Implement.** Create empty `lab/__init__.py` and `lab/tools/__init__.py`, then `lab/tools/totp.py`:

```python
"""RFC 6238 TOTP (HMAC-SHA1) for lab enrolment scripts. Stdlib only; lab secrets never leave ~/idm-lab-secrets."""
import base64
import hashlib
import hmac
import struct
import sys
import time


def totp(secret_b32, t=None, digits=6, step=30):
    s = secret_b32.strip().upper()
    key = base64.b32decode(s + "=" * (-len(s) % 8))
    counter = int((time.time() if t is None else t) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


if __name__ == "__main__":
    print(totp(sys.argv[1]))
```

- [ ] **Step 4: Secrets scan + .gitignore.** `lab/tools/secrets-scan.sh`:

```bash
#!/usr/bin/env bash
# Fail if anything that looks like a lab secret is in the given paths (default: the whole repo, tracked files).
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
files=("$@"); [[ ${#files[@]} -gt 0 ]] || mapfile -t files < <(git ls-files)
pat='BEGIN [A-Z ]*PRIVATE KEY|otpauth://|secret=[A-Z2-7]{16,}|new_password: *"[^"]+"|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
if grep -nE "$pat" "${files[@]}" 2>/dev/null; then echo "SECRETS-SCAN: FAIL"; exit 1; fi
echo "SECRETS-SCAN: clean (${#files[@]} files)"
```
Append to `.gitignore`:
```
# Lab secrets live in ~/idm-lab-secrets, never here.
*secret*
*.token
*.key
```
Test it: `printf 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DP\n' > /tmp/leak.txt; lab/tools/secrets-scan.sh /tmp/leak.txt; echo rc=$?` → Expected `SECRETS-SCAN: FAIL`, `rc=1`. Then `lab/tools/secrets-scan.sh` → Expected `SECRETS-SCAN: clean`.

- [ ] **Step 5: Run all tests, create the secrets folder, commit**

Run: `uv run pytest -q && mkdir -p ~/idm-lab-secrets && chmod 700 ~/idm-lab-secrets`
Expected: all pass (35).
```bash
git add lab/__init__.py lab/tools tests/test_totp.py .gitignore
git commit -m "Plan 3: TOTP helper (RFC 6238 vectors), secrets scan, secrets kept out of the repo"
```

---

### Task 2: aero serves the repos to the VMs (b8)

**Files:** Create `lab/host/b8-lab-repo.sh`; modify `lab/aero-deviations.md`

**Interfaces:** Produces `http://192.168.100.1:8080/dvd/BaseOS`, `…/dvd/AppStream`, `…/rpms` (lab-local).

- [ ] **Step 1: Write `lab/host/b8-lab-repo.sh`**

```bash
#!/usr/bin/env bash
# b8: serve /data/lab-inputs (DVD mount + lab-local rpms) read-only over HTTP on the lab bridge address only.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
UNIT=/etc/systemd/system/lab-repo.service
if (( CHECK )); then log "[check] would: write $UNIT (python3 http.server 192.168.100.1:8080 /data/lab-inputs), open 8080/tcp in firewalld"; exit 0; fi
cat > "$UNIT" <<'U'
[Unit]
Description=Lab package repo (DVD + lab-local) for br-lab VMs
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 8080 --bind 192.168.100.1 --directory /data/lab-inputs
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
U
run "enable lab-repo" systemctl daemon-reload
run "start lab-repo" systemctl enable --now lab-repo.service
zone=$(firewall-cmd --get-zone-of-interface=br-lab 2>/dev/null || firewall-cmd --get-default-zone)
run "open 8080/tcp in $zone" firewall-cmd --permanent --zone="$zone" --add-port=8080/tcp
run "reload firewall" firewall-cmd --reload
log "b8 done: http://192.168.100.1:8080/ (zone $zone)"
```

- [ ] **Step 2: Run it and prove access from build1** (build1 is the only VM so far; start it for this check)

Run:
```bash
chmod +x lab/host/b8-lab-repo.sh && shellcheck -x -P lab/host lab/host/b8-lab-repo.sh
lab/host/push.sh b8-lab-repo --check && lab/host/push.sh b8-lab-repo
ssh aero 'sudo virsh start build1' ; sleep 60
ssh build1 'curl -fsS http://192.168.100.1:8080/dvd/BaseOS/repodata/repomd.xml | head -c 80; echo; curl -fsS http://192.168.100.1:8080/rpms/repodata/repomd.xml | head -c 80; echo'
ssh aero 'sudo virsh shutdown build1'
```
Expected: two XML fragments beginning `<?xml`.

*If the DynamicUser can't read the root-only `/data/lab-inputs`* (401/permission error in `journalctl -u lab-repo`): **Ruling path:** switch to `User=root` with the same Protect* settings, and record it.

- [ ] **Step 3: Log the deviations and commit**

Add to `lab/aero-deviations.md`:
```
| 2026-09-2x | b8 | `lab-repo.service`: python3 http.server bound to 192.168.100.1:8080 serving /data/lab-inputs read-only; 8080/tcp opened in firewalld | VMs install from the DVD + lab-local repo over the bridge | `systemctl disable --now lab-repo; rm /etc/systemd/system/lab-repo.service; firewall-cmd --permanent --remove-port=8080/tcp --zone=<zone>` |
```
```bash
git add lab/host/b8-lab-repo.sh lab/aero-deviations.md
git commit -m "aero b8: lab repo over HTTP on the bridge address only (DVD + lab-local)"
```

---

### Task 3: Shared kickstart template and a generic VM creator

**Files:** Create `lab/kickstart/base.ks.in`, `lab/kickstart/render.sh`, `lab/kickstart/test_render.sh`, `lab/host/vm-lib.sh`, `lab/host/test_vm_create.sh`; modify `lab/host/b7-vm-build1.sh`, `lab/host/push.sh`; delete `lab/host/test_b7.sh` (its cases move to `test_vm_create.sh`)

**Interfaces:**
- `render.sh NAME` writes `/tmp/NAME.ks` from `base.ks.in` using the host table inside `render.sh`: `srv1` → IP .10, packages `bind bind-utils policycoreutils-python-utils setools-console`; `client2` → IP .13, packages `authselect expect policycoreutils-python-utils setools-console cryptsetup clevis clevis-luks clevis-systemd tpm2-tools`.
- `create_vm NAME VCPUS MEM_MB DISK_GB KS [extra virt-install args…]` (in `vm-lib.sh`) keeps every b7 safeguard: `--noreboot`, serial log in `/var/log/libvirt/qemu/NAME-install.log`, a timeout that destroys the VM, and refusal of a half-built VM with no `golden` snapshot.

- [ ] **Step 1: Write the failing render test** `lab/kickstart/test_render.sh`:

```bash
#!/usr/bin/env bash
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; fails=0
t() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fails=1; fi; }
for n in srv1 client2; do
  SSH_PUBKEY="ecdsa-sha2-nistp384 AAAA test" OUT=/tmp/test-$n.ks bash "$here/render.sh" $n >/dev/null
  t "$n renders" "[[ -s /tmp/test-$n.ks ]]"
  t "$n has no unreplaced placeholders" "! grep -q '@[A-Z_]*@' /tmp/test-$n.ks"
  t "$n validates (RHEL9)" "uvx --from pykickstart ksvalidator -v RHEL9 /tmp/test-$n.ks >/dev/null"
  t "$n keeps FIPS + CUI" "grep -q 'fips=1' /tmp/test-$n.ks && grep -q content_profile_cui /tmp/test-$n.ks"
  t "$n has no compilers" "! grep -qxE '(gcc|clang|golang|cmake|rpm-build)' /tmp/test-$n.ks"
done
t "srv1 IP .10 + bind" "grep -q 'ip=192.168.100.10 ' /tmp/test-srv1.ks && grep -qx bind /tmp/test-srv1.ks"
t "client2 IP .13 + resolver srv1" "grep -q 'ip=192.168.100.13 ' /tmp/test-client2.ks && grep -q 'nameserver=192.168.100.10' /tmp/test-client2.ks"
t "unknown host is rejected" "! OUT=/tmp/x.ks bash '$here/render.sh' nosuch 2>/dev/null"
exit $fails
```
Run: `bash lab/kickstart/test_render.sh` → Expected: FAIL (render.sh missing).

- [ ] **Step 2: Write `lab/kickstart/base.ks.in`.** It's `build1.ks.in` with these changes:
  - the `network` line becomes `network --bootproto=static --device=link --ip=@IP@ --netmask=255.255.255.0 --nameserver=192.168.100.10 --nodefroute --noipv6 --activate --hostname=@HOST@.kanidm.lab.test`;
  - the volume group becomes `rl_@HOST@`, with sizes `/` 9216, `/home` 3072, `/tmp` 2048, `/var` 5120 `--grow`, `/var/log` 2048, `/var/log/audit` 2048, `/var/tmp` 2048, swap 2048 (fits 30 GB; srv1's extra space goes to `/var`, where Kanidm's database lives);
  - `%packages` = `@^minimal-environment audit chrony crypto-policies firewalld openscap-scanner scap-security-guide openssh-server sudo fapolicyd tar rsync` + `@PACKAGES@` (one per line);
  - `%post` also writes `/etc/yum.repos.d/lab.repo`:

```
cat > /etc/yum.repos.d/lab.repo <<'R'
[lab-baseos]
name=Rocky 9.8 BaseOS (DVD via aero)
baseurl=http://192.168.100.1:8080/dvd/BaseOS
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
[lab-appstream]
name=Rocky 9.8 AppStream (DVD via aero)
baseurl=http://192.168.100.1:8080/dvd/AppStream
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9
[lab-local]
name=Lab-built RPMs (unsigned; sha256 in BUILD-RECORD.md)
baseurl=http://192.168.100.1:8080/rpms
gpgcheck=0
R
dnf config-manager --set-disabled baseos appstream extras >/dev/null 2>&1 || true
```
  (the sudoers drop-in, the chrony line, the namespace-sysctl removal and `dracut -f --regenerate-all` stay exactly as in `build1.ks.in`).

- [ ] **Step 3: Write `lab/kickstart/render.sh`**

```bash
#!/usr/bin/env bash
# render.sh NAME -> $OUT (default /tmp/NAME.ks) from base.ks.in. SSH_PUBKEY defaults to ~/.ssh/aero_ecdsa.pub.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; n="${1:?usage: render.sh NAME}"
case "$n" in
  srv1)    ip=192.168.100.10; pkgs="bind bind-utils policycoreutils-python-utils setools-console" ;;
  client2) ip=192.168.100.13; pkgs="authselect expect policycoreutils-python-utils setools-console cryptsetup clevis clevis-luks clevis-systemd tpm2-tools" ;;
  *) echo "unknown host: $n" >&2; exit 1 ;;
esac
key="${SSH_PUBKEY:-$(cat ~/.ssh/aero_ecdsa.pub)}"; out="${OUT:-/tmp/$n.ks}"
python3 - "$here/base.ks.in" "$out" "$n" "$ip" "$key" "$pkgs" <<'PY'
import sys
src, out, host, ip, key, pkgs = sys.argv[1:]
s = open(src).read()
for k, v in {"@HOST@": host, "@IP@": ip, "@SSH_PUBKEY@": key, "@PACKAGES@": "\n".join(pkgs.split())}.items():
    s = s.replace(k, v)
open(out, "w").write(s)
PY
echo "$out"
```
Run `bash lab/kickstart/test_render.sh` → Expected: all PASS.

- [ ] **Step 4: Refactor b7 into `vm-lib.sh`, with tests first.** Write `lab/host/test_vm_create.sh`:
  - carry over `test_b7.sh`'s stub harness and six cases, but call `create_vm t1 2 2048 20 /tmp/lab-host/t1.ks` through a small driver;
  - add one case: an `extra` argument (`--tpm emulator,model=tpm-crb,version=2.0`) reaches `virt-install` (the stub `virt-install` appends its arguments to `$STUBLOG`).

Run it on aero: RED, because `vm-lib.sh` doesn't exist. Then move b7's body into:

```bash
# shellcheck shell=bash
# create_vm NAME VCPUS MEM_MB DISK_GB KS [extra virt-install args...]  (source lib.sh first)
create_vm() {
  local name=$1 vcpus=$2 mem=$3 disk=$4 ks=$5; shift 5
  local iso=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso img=/data/libvirt/images/$1.qcow2
  local logf=/var/log/libvirt/qemu/$1-install.log state
  [[ -f $ks ]] || die "missing $ks (run via push.sh)"
  if virsh dominfo "$name" >/dev/null 2>&1; then
    virsh snapshot-info "$name" golden >/dev/null 2>&1 \
      || die "$name exists but has no golden snapshot (half-built?); remove it: virsh undefine $name --remove-all-storage"
    log "$name already exists (golden snapshot present)"; return 0
  fi
  (( CHECK )) && { log "[check] would: virt-install $name ($vcpus vCPU, $mem MB, $disk GB) from $iso with $ks $*; serial log $logf"; return 0; }
  run "install $name (unattended; serial console logged to $logf)" \
    virt-install --name "$name" --memory "$mem" --vcpus "$vcpus" --cpu host-passthrough \
      --osinfo detect=on,name=rhel9-unknown \
      --disk path="$img",size="$disk",format=qcow2 \
      --location "$iso" --network bridge=br-lab \
      --initrd-inject "$ks" \
      --extra-args "inst.ks=file:/$(basename "$ks") fips=1 console=ttyS0,115200 inst.text" \
      --graphics none --serial file,path="$logf" \
      --noautoconsole --noreboot --wait 90 "$@" \
    || log "virt-install exited non-zero (time limit or installer error); checking the VM"
  state=$(virsh domstate "$name" 2>/dev/null || echo missing)
  if [[ $state != "shut off" ]]; then
    virsh destroy "$name" >/dev/null 2>&1 || true
    die "$name install did not finish in 90 min (state: $state); see $logf. The stuck VM was stopped; remove it: virsh undefine $name --remove-all-storage"
  fi
  grep -qiE 'kernel panic|traceback|an error occurred' "$logf" && die "installer reported an error; see $logf"
  run "start $name" virsh start "$name"
}
```
`b7-vm-build1.sh` becomes `source lib.sh; source vm-lib.sh; need_root; create_vm build1 12 16384 80 /tmp/lab-host/build1.ks; log "b7 done"`. Delete `test_b7.sh`. In `push.sh`, render `srv1` and `client2` with `render.sh` and copy `/tmp/{build1,srv1,client2}.ks` to aero.
Run `test_vm_create.sh` on aero → Expected: 7/7 PASS. Then run `lab/host/push.sh b7-vm-build1` → Expected: `build1 already exists (golden snapshot present)` (regression check against the real VM).

- [ ] **Step 5: Commit**

```bash
git add lab/kickstart lab/host && git rm -q lab/host/test_b7.sh
git commit -m "Shared kickstart template (srv1, client2) and generic create_vm; b7 now a wrapper (tests carried over)"
```

---

### Task 4: Create srv1 and client2 (b9)

**Files:** Create `lab/host/b9-vm-srv1-client2.sh`; modify `lab/vm-deviations.md`, `~/.ssh/config`

- [ ] **Step 1: Write b9**

```bash
#!/usr/bin/env bash
# b9: srv1 (4 vCPU, 6 GB, 60 GB) and client2 (2 vCPU, 2 GB, 30 GB + 2 GB LUKS test disk + software TPM 2.0).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=vm-lib.sh
source "$(dirname "$0")/vm-lib.sh"; need_root
if ! rpm -q swtpm swtpm-tools >/dev/null 2>&1; then
  run "install swtpm (software TPM for VMs) from the DVD" dnf -y -q install swtpm swtpm-tools
fi
create_vm srv1 4 6144 60 /tmp/lab-host/srv1.ks
create_vm client2 2 2048 30 /tmp/lab-host/client2.ks \
  --tpm emulator,model=tpm-crb,version=2.0 \
  --disk path=/data/libvirt/images/client2-luks.qcow2,size=2,format=qcow2
log "b9 done"
```

- [ ] **Step 2: Dry run, then install** (build1 shut down first; ~15 min for both, run in the background)

Run: `ssh aero 'sudo virsh shutdown build1'; lab/host/push.sh b9-vm-srv1-client2 --check && lab/host/push.sh b9-vm-srv1-client2`
Expected: `b9 done`. *If swtpm can't start under aero's FIPS mode* (virt-install error mentioning swtpm or tpm), that is a **Task 11 finding**. Record the exact error, re-run b9 with the `--tpm` line removed for client2, and continue.

- [ ] **Step 3: Reach both and verify posture.** Append `Host srv1` (192.168.100.10) and `Host client2` (192.168.100.13) to `~/.ssh/config`, in the same form as `build1`.

Run: `for h in srv1 client2; do ssh -o StrictHostKeyChecking=accept-new $h 'hostname; fips-mode-setup --check; getenforce; systemctl is-active fapolicyd; sysctl -n user.max_user_namespaces; ip route; command -v gcc || echo no-compiler; dnf -q repolist'; done`
Expected, per host:
- the FQDN;
- `FIPS mode is enabled.`, `Enforcing`, `active`, a non-zero namespace count;
- only the 192.168.100.0/24 route;
- `no-compiler`;
- the repos `lab-baseos`, `lab-appstream`, `lab-local`.

- [ ] **Step 4: Snapshot `os-ready`, log the deviations, commit**

Run: `ssh aero 'for v in srv1 client2; do sudo virsh snapshot-create-as $v os-ready "OS installed, before identity stack"; done'`

Add rows to `lab/vm-deviations.md`:
- srv1/client2: lab-local repo `gpgcheck=0`;
- aero: `swtpm` installed;
- client2: a second 2 GB disk for the LUKS test.
```bash
git add lab/host/b9-vm-srv1-client2.sh lab/vm-deviations.md
git commit -m "aero b9: srv1 and client2 (vTPM + LUKS test disk), FIPS/CUI/fapolicyd verified; os-ready snapshots"
```

---

### Task 5: BIND on srv1 (zone kanidm.lab.test)

**Files:** Create `lab/srv1/run.sh`, `lab/srv1/10-bind.sh`, `lab/srv1/kanidm.lab.test.zone`

**Interfaces:** `lab/srv1/run.sh STEP [host]` copies `lab/srv1/` to `HOST:/tmp/srv1/` (no `--delete`, so separately staged files survive) and runs `sudo bash /tmp/srv1/STEP.sh`. Records: `srv1`, `idm`, `ca` → .10; `client2` → .13; `aero` → .1.

- [ ] **Step 1: Write the runner and the zone**

`lab/srv1/run.sh`:
```bash
#!/usr/bin/env bash
# run.sh STEP [host]: copy lab/srv1 to the host (default srv1) and run STEP.sh there with sudo.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; step="${1:?usage: run.sh STEP [host]}"; host="${2:-srv1}"
rsync -a "$here/" "$host:/tmp/srv1/"   # no --delete: files staged separately (secrets) survive
# shellcheck disable=SC2029  # step expands on the Mac
ssh "$host" "sudo bash /tmp/srv1/$step.sh"
```
`lab/srv1/kanidm.lab.test.zone`:
```
$TTL 300
@       IN SOA  srv1.kanidm.lab.test. hostmaster.kanidm.lab.test. ( 2026092801 3600 600 86400 300 )
        IN NS   srv1.kanidm.lab.test.
srv1    IN A    192.168.100.10
idm     IN A    192.168.100.10
ca      IN A    192.168.100.10
client1 IN A    192.168.100.12
client2 IN A    192.168.100.13
aero    IN A    192.168.100.1
```

- [ ] **Step 2: Write `lab/srv1/10-bind.sh`**

```bash
#!/usr/bin/env bash
# srv1: authoritative-only BIND for kanidm.lab.test, lab subnet only, no recursion (offline lab).
set -Eeuo pipefail
install -o root -g named -m 0640 /tmp/srv1/kanidm.lab.test.zone /var/named/kanidm.lab.test.zone
cat > /etc/named.conf <<'N'
options {
    listen-on port 53 { 127.0.0.1; 192.168.100.10; };
    listen-on-v6 { none; };
    directory "/var/named";
    allow-query { 127.0.0.1; 192.168.100.0/24; };
    recursion no;
    dnssec-validation no;
    pid-file "/run/named/named.pid";
};
logging { channel default_debug { file "data/named.run"; severity dynamic; }; };
zone "kanidm.lab.test" IN { type primary; file "kanidm.lab.test.zone"; allow-update { none; }; };
N
restorecon -R /var/named /etc/named.conf
named-checkconf && named-checkzone kanidm.lab.test /var/named/kanidm.lab.test.zone
systemctl enable --now named
firewall-cmd -q --permanent --add-service=dns && firewall-cmd -q --reload
dig +short @192.168.100.10 idm.kanidm.lab.test
```

- [ ] **Step 3: Run and verify from client2**

Run: `chmod +x lab/srv1/*.sh && shellcheck lab/srv1/*.sh && lab/srv1/run.sh 10-bind && ssh client2 'getent hosts idm.kanidm.lab.test ca.kanidm.lab.test; dig +short @192.168.100.10 example.com; echo "recursion-answer=[$?]"'`
Expected:
- `named-checkzone` reports `OK`;
- the script prints `192.168.100.10`;
- on client2, `idm` and `ca` resolve to .10;
- `example.com` gets no answer, because recursion is off (offline by design).

Record any FIPS error seen from `named` in the Q2 runtime notes. For example, DNSSEC algorithms: validation is off, but `named` may log that it refuses RSASHA1 keys at start.

- [ ] **Step 4: Commit**

```bash
git add lab/srv1 && git commit -m "srv1: authoritative BIND for kanidm.lab.test (no recursion), verified from client2"
```

---

### Task 6: step-ca on srv1 (root + intermediate, ACME, auto-renewal)

**Files:** Create `lab/srv1/20-step-ca.sh`, `lab/srv1/21-kanidm-cert.sh`, `lab/srv1/units/step-ca.service`, `lab/srv1/units/cert-renew-kanidm.service`, `lab/srv1/units/cert-renew-kanidm.timer`

**Interfaces:**
- CA URL `https://ca.kanidm.lab.test:9000`; root at `/etc/step-ca/certs/root_ca.crt`.
- Kanidm certificate: `/etc/pki/kanidm/chain.pem` + `/etc/pki/kanidm/key.pem` (root:root 0600), renewed by the timer, which restarts kanidmd on change.

- [ ] **Step 1: Install from lab-local and record the FIPS behaviour first**

Run:
```bash
ssh srv1 'sudo dnf -y -q install step-ca step-cli && step-ca version; step-cli version; GODEBUG=fips140=on step-cli crypto rand --format hex 16; echo "fips140=on rc=$?"; GODEBUG=fips140=only step-cli crypto keypair --kty EC --crv P-384 --no-password --insecure /tmp/k.pub /tmp/k.key; echo "fips140=only EC P-384 rc=$?"; GODEBUG=fips140=only step-cli crypto keypair --kty OKP --crv Ed25519 --no-password --insecure /tmp/e.pub /tmp/e.key; echo "fips140=only Ed25519 rc=$?"; rm -f /tmp/k.* /tmp/e.*'
```
Expected:
- the RPMs install under enforcing fapolicyd. They're from our trusted rpmdb, which is the first fapolicyd-trust datapoint;
- the version lines print;
- the three return codes get recorded **whatever they are**. That is the Go-FIPS evidence for Q2 (`fips140=on` = Go's FIPS mode; `only` = refuse non-approved algorithms).
Append the output verbatim to `/tmp/q2-runtime.txt` on the Mac.

- [ ] **Step 2: Write `lab/srv1/20-step-ca.sh`** (the CA password lives in `/etc/step-ca/password`, root 0600, generated on srv1; it never leaves srv1)

```bash
#!/usr/bin/env bash
# srv1: step-ca with an internal root + intermediate, ECDSA P-384 keys, JWK + ACME provisioners, run as user step.
set -Eeuo pipefail
export STEPPATH=/etc/step-ca
id step >/dev/null 2>&1 || useradd --system --home-dir /etc/step-ca --shell /sbin/nologin step
if [[ ! -f $STEPPATH/config/ca.json ]]; then
  mkdir -p $STEPPATH && chmod 700 $STEPPATH
  head -c 32 /dev/urandom | base64 > $STEPPATH/password && chmod 600 $STEPPATH/password
  step-cli ca init --name "kanidm.lab.test Lab CA" --dns ca.kanidm.lab.test --dns srv1.kanidm.lab.test \
    --address 192.168.100.10:9000 --provisioner lab-admin --password-file $STEPPATH/password \
    --provisioner-password-file $STEPPATH/password --kty EC --crv P-384 --deployment-type standalone
  step-cli ca provisioner add acme --type ACME --ca-config $STEPPATH/config/ca.json
  chown -R step:step $STEPPATH
fi
install -m 0644 /tmp/srv1/units/step-ca.service /etc/systemd/system/step-ca.service
systemctl daemon-reload && systemctl enable --now step-ca
firewall-cmd -q --permanent --add-port=9000/tcp && firewall-cmd -q --reload
cp $STEPPATH/certs/root_ca.crt /etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt && update-ca-trust
for i in $(seq 20); do step-cli ca health --ca-url https://ca.kanidm.lab.test:9000 --root $STEPPATH/certs/root_ca.crt 2>/dev/null && break; sleep 1; done
```
`lab/srv1/units/step-ca.service`:
```
[Unit]
Description=step-ca (kanidm.lab.test lab CA)
After=network-online.target
[Service]
User=step
Group=step
Environment=STEPPATH=/etc/step-ca
ExecStart=/usr/bin/step-ca /etc/step-ca/config/ca.json --password-file /etc/step-ca/password
Restart=on-failure
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
```
(Whether step-ca runs with `GODEBUG=fips140=on` is decided by Step 1's evidence. If `on` worked, add `Environment=GODEBUG=fips140=on` and record it. If it failed, leave it off and record why.)

- [ ] **Step 3: Run and verify**

Run: `lab/srv1/run.sh 20-step-ca && ssh srv1 'systemctl is-active step-ca; sudo ausearch -m AVC -ts recent 2>/dev/null | grep -c step-ca'`
Expected: `ok` (health), `active`, and an AVC count. Any denials: save them to `lab/selinux/step-ca-avc.txt` and tell the ISSO in the report. step-ca from the vendor RPM also has no SELinux policy.

- [ ] **Step 4: Kanidm TLS certificate via ACME, plus the renewal timer.** `lab/srv1/21-kanidm-cert.sh`:

```bash
#!/usr/bin/env bash
# srv1: issue idm.kanidm.lab.test via the ACME provisioner (http-01, standalone on :80), install the renewal timer.
set -Eeuo pipefail
export STEPPATH=/root/.step
R=/etc/step-ca/certs/root_ca.crt; D=/etc/pki/kanidm
mkdir -p $D && chmod 700 $D
step-cli ca bootstrap --ca-url https://ca.kanidm.lab.test:9000 --fingerprint "$(step-cli certificate fingerprint $R)" --force >/dev/null
if [[ ! -s $D/chain.pem ]]; then
  firewall-cmd -q --add-service=http   # runtime only: open :80 just for the http-01 challenge
  step-cli ca certificate idm.kanidm.lab.test $D/chain.pem $D/key.pem --provisioner acme --kty EC --crv P-384 --force
  firewall-cmd -q --remove-service=http
fi
chmod 600 $D/*.pem
install -m 0644 /tmp/srv1/units/cert-renew-kanidm.service /tmp/srv1/units/cert-renew-kanidm.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now cert-renew-kanidm.timer
step-cli certificate inspect $D/chain.pem --short
```
`units/cert-renew-kanidm.service`:
```
[Unit]
Description=Renew the Kanidm TLS certificate (step-ca) and restart kanidmd on change
[Service]
Type=oneshot
Environment=STEPPATH=/root/.step
ExecStart=/usr/bin/step-cli ca renew --force --expires-in 8h --exec "systemctl try-restart kanidmd" /etc/pki/kanidm/chain.pem /etc/pki/kanidm/key.pem
```
`units/cert-renew-kanidm.timer`:
```
[Unit]
Description=Check the Kanidm TLS certificate every 15 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true
[Install]
WantedBy=timers.target
```
Run: `lab/srv1/run.sh 21-kanidm-cert`
Expected: a short inspection line showing `idm.kanidm.lab.test`, the issuer (lab intermediate) and a validity of about 24 h. `systemctl list-timers cert-renew-kanidm.timer` lists it.

- [ ] **Step 5: Prove renewal changes what is served** (Review Focus #3). Runs after Task 7, once kanidmd is up. Kept here so the whole certificate story sits in one place:

Run: `ssh srv1 'S1=$(echo | openssl s_client -connect idm.kanidm.lab.test:443 2>/dev/null | openssl x509 -noout -serial); sudo STEPPATH=/root/.step step-cli ca renew --force --exec "systemctl try-restart kanidmd" /etc/pki/kanidm/chain.pem /etc/pki/kanidm/key.pem; sleep 5; S2=$(echo | openssl s_client -connect idm.kanidm.lab.test:443 2>/dev/null | openssl x509 -noout -serial); echo "$S1 -> $S2"; [ "$S1" != "$S2" ] && echo RENEWAL-SERVED'`
Expected: two different serials and `RENEWAL-SERVED`.

- [ ] **Step 6: Commit** (Step 5 is committed with Task 7)

```bash
git add lab/srv1 lab/selinux 2>/dev/null; git commit -m "srv1: step-ca (P-384 root+intermediate, JWK+ACME), Kanidm cert via ACME, 15-min renewal timer; Go FIPS evidence"
```

---

### Task 7: Kanidm server on srv1

**Files:** Create `lab/srv1/30-kanidmd.sh`, `lab/srv1/server.toml`, `lab/srv1/kanidmd-credentials.conf`

**Interfaces:**
- `https://idm.kanidm.lab.test` (443). Admin passwords go to the Mac at `~/idm-lab-secrets/{admin,idm_admin}.txt`.
- CLI config on srv1 is `/etc/kanidm/config` (`uri`, `ca_path`).

- [ ] **Step 1: Write the config and the credentials drop-in**

`lab/srv1/server.toml`:
```toml
version = "2"
bindaddress = "192.168.100.10:443"
db_path = "/var/lib/private/kanidm/kanidm.db"
tls_chain = "/run/credentials/kanidmd.service/tls_chain"
tls_key = "/run/credentials/kanidmd.service/tls_key"
domain = "idm.kanidm.lab.test"
origin = "https://idm.kanidm.lab.test"
log_level = "info"

[online_backup]
path = "/var/lib/private/kanidm/backups/"
schedule = "00 22 * * *"
versions = 7
```
`lab/srv1/kanidmd-credentials.conf` (goes to `/etc/systemd/system/kanidmd.service.d/credentials.conf`; systemd copies the root-only key into the DynamicUser's private credential directory at start):
```
[Service]
LoadCredential=tls_chain:/etc/pki/kanidm/chain.pem
LoadCredential=tls_key:/etc/pki/kanidm/key.pem
```

- [ ] **Step 2: Write `lab/srv1/30-kanidmd.sh`**

```bash
#!/usr/bin/env bash
# srv1: install kanidm-server + kanidm-clients from lab-local (fapolicyd ENFORCING), configure, start.
set -Eeuo pipefail
dnf -y -q install kanidm-server kanidm-clients
install -m 0640 /tmp/srv1/server.toml /etc/kanidm/server.toml
install -D -m 0644 /tmp/srv1/kanidmd-credentials.conf /etc/systemd/system/kanidmd.service.d/credentials.conf
printf 'uri = "https://idm.kanidm.lab.test"\nca_path = "/etc/step-ca/certs/root_ca.crt"\n' > /etc/kanidm/config
systemctl daemon-reload
kanidmd configtest -c /etc/kanidm/server.toml || true   # informative; the unit is the real test
systemctl enable --now kanidmd
firewall-cmd -q --permanent --add-service=https && firewall-cmd -q --reload
for i in $(seq 30); do curl -fsS https://idm.kanidm.lab.test/status >/dev/null 2>&1 && break; sleep 2; done
curl -fsS https://idm.kanidm.lab.test/status; echo
```

- [ ] **Step 3: Run it and record every failure before fixing** (Review Focus #5)

Run: `lab/srv1/run.sh 30-kanidmd; ssh srv1 'systemctl is-active kanidmd; sudo journalctl -u kanidmd --no-pager | tail -20; sudo ausearch -m AVC,FANOTIFY -ts boot 2>/dev/null | grep -E "kanidm|type=FANOTIFY" | head'`
Expected: `true` from `/status`, and `active`.

For **each** failure, record the tool, the exact error and the cause in the Q1 runtime section *before* changing anything. Candidates: fapolicyd `FANOTIFY` (would disprove the RPM-trust claim), AVCs, `DynamicUser` and credential paths, FIPS errors. Then fix it and ledger a ruling.

- [ ] **Step 4: Recover the admin accounts to the Mac's secrets folder, and verify the CLI**

Run:
```bash
for a in admin idm_admin; do ssh srv1 "sudo kanidmd recover-account $a -c /etc/kanidm/server.toml -o json" > ~/idm-lab-secrets/$a.json; done
chmod 600 ~/idm-lab-secrets/*.json; python3 -c 'import json,sys; [print(k, "password" in json.load(open(f"{__import__("os").path.expanduser("~")}/idm-lab-secrets/{k}.json")) ) for k in ("admin","idm_admin")]'
```
Expected: `admin True`, `idm_admin True`. If `-o json` isn't supported by this version, capture the plain output the same way and parse `new_password: "…"` (ruling). **Never print the passwords to the terminal or a log.**

Then log in on srv1 using an `expect` wrapper that reads the password from stdin (copied over ssh, never on a command line). Check with `kanidm self whoami --name idm_admin`. Expected: `idm_admin@idm.kanidm.lab.test`.

- [ ] **Step 5: Runtime TLS evidence for Q2** (runs in Task 10 Step 2, from client2, once it trusts the lab root)

Run: `ssh client2 'for v in tls1.2 tls1.3; do echo "== $v"; echo | openssl s_client -connect idm.kanidm.lab.test:443 -$v 2>&1 | grep -E "^(Protocol|Cipher|Server Temp Key|Peer signature type)|Verify return code"; done; echo | openssl s_client -connect ca.kanidm.lab.test:9000 2>&1 | grep -E "^(Protocol|Cipher|Server Temp Key)"'`
Expected: the negotiated protocol, cipher and **key-exchange group** for Kanidm (rustls/AWS-LC) and step-ca (Go). Client2's own OpenSSL runs in FIPS mode, so it only *offers* FIPS-approved groups and ciphers. Also record whether the handshake **fails** for either server. That would mean the server supports no FIPS-approved combination, a key Q2 datum.

- [ ] **Step 6: Run Task 6 Step 5 (renewal served), then commit**

```bash
git add lab/srv1 && git commit -m "srv1: Kanidm 1.11.2 from lab RPMs under FIPS + SELinux + fapolicyd enforcing; TLS via systemd credentials; renewal proven"
```

---

### Task 8: client2 enrolment (unixd, NSS, PAM, sshd)

**Files:** Create `lab/client/run.sh` (same shape as `lab/srv1/run.sh`: copies `lab/client/` to `client2:/tmp/client/`, no `--delete`), `lab/client/10-enrol.sh`, `lab/client/authselect/{nsswitch.conf,system-auth.patch.py}`, `lab/client/10-kanidm.conf` (sshd drop-in)

**Interfaces:**
- On srv1 (via `idm_admin`): service account `unixd-client2` in group `idm_unix_authentication_read`, token written to client2 `/etc/kanidm/token` (0600).
- POSIX login group `lab_users`; admin group `lab_admins`.

- [ ] **Step 1: Server side (on srv1 as idm_admin):** create the groups, make them POSIX, create the service account and its token. Put the commands in `lab/srv1/40-groups-svcacct.sh`; its `expect` login reads the idm_admin password from stdin:
```bash
kanidm group create lab_users --name idm_admin
kanidm group posix set lab_users --name idm_admin
kanidm group create lab_admins --name idm_admin
kanidm group posix set lab_admins --name idm_admin
kanidm service-account create unixd-client2 "unixd on client2" idm_admins --name idm_admin
kanidm group add-members idm_unix_authentication_read unixd-client2 --name idm_admin
kanidm service-account api-token generate unixd-client2 client2-token --name idm_admin
```
The token is captured to `~/idm-lab-secrets/unixd-client2.token` and never printed. Exact subcommand spellings are confirmed with `kanidm service-account --help` on srv1 first; differences become ledger rulings.

- [ ] **Step 1b: SSH CA on srv1** (`lab/srv1/50-ssh-ca.sh`). It's separate from step-ca, with its own key and folder:
```bash
#!/usr/bin/env bash
set -Eeuo pipefail
install -d -m 0700 /etc/ssh-ca
[[ -f /etc/ssh-ca/user_ca ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C 'kanidm.lab.test user CA' -f /etc/ssh-ca/user_ca
ssh-keygen -q -t ed25519 -N '' -f /tmp/ed-test 2>/tmp/ed-err; echo "ed25519 under FIPS rc=$? $(cat /tmp/ed-err)"; rm -f /tmp/ed-test* /tmp/ed-err
cat /etc/ssh-ca/user_ca.pub
```
Run: `lab/srv1/run.sh 50-ssh-ca > /tmp/ssh-ca.out; tail -1 /tmp/ssh-ca.out > ~/idm-lab-secrets/trusted_user_ca_keys; head -1 /tmp/ssh-ca.out`
Expected: an `ecdsa-sha2-nistp384 … user CA` public key saved for client2, plus the ed25519 result under FIPS (record it: refused or allowed).

- [ ] **Step 2: `lab/client/10-enrol.sh`** (runs on client2 as root):

```bash
#!/usr/bin/env bash
# client2: trust the lab root, install unixd from lab-local, configure Kanidm client + unixd, authselect profile, sshd.
set -Eeuo pipefail
install -m 0644 /tmp/client/kanidm-lab-root.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust
dnf -y -q install kanidm-unixd kanidm-clients
printf 'uri = "https://idm.kanidm.lab.test"\n' > /etc/kanidm/config
cat > /etc/kanidm/unixd <<'U'
version = '2'
[kanidm]
pam_allowed_login_groups = ["lab_users"]
U
install -m 0600 /tmp/client/token /etc/kanidm/token && shred -u /tmp/client/token
systemctl enable --now kanidm-unixd kanidm-unixd-tasks
kanidm-unix status
# authselect: custom profile from sssd (keeps the CUI features, e.g. faillock), with pam_kanidm inserted
[[ -d /etc/authselect/custom/kanidm ]] || authselect create-profile kanidm -b sssd
install -m 0644 /tmp/client/authselect/nsswitch.conf /etc/authselect/custom/kanidm/nsswitch.conf
python3 /tmp/client/authselect/system-auth.patch.py /etc/authselect/custom/kanidm/system-auth /etc/authselect/custom/kanidm/password-auth
authselect select custom/kanidm $(authselect current -r | cut -d' ' -f2-) --force
install -m 0600 /tmp/client/10-kanidm.conf /etc/ssh/sshd_config.d/10-kanidm.conf
install -m 0644 /tmp/client/trusted_user_ca_keys /etc/ssh/trusted_user_ca_keys
sshd -t && systemctl reload sshd
```
`authselect/nsswitch.conf`: upstream's order. **Kanidm first, systemd last.** Upstream: "kanidm provides a cached view of the files module".
```
passwd:     kanidm compat systemd
group:      kanidm compat systemd
shadow:     files
hosts:      files dns myhostname
services:   files
netgroup:   files
automount:  files
aliases:    files
ethers:     files
gshadow:    files
networks:   files dns
protocols:  files
publickey:  files
rpc:        files
```
`authselect/system-auth.patch.py`: for each file, insert `auth sufficient pam_kanidm.so ignore_unknown_user` immediately before the first `auth … pam_unix.so` line; `account sufficient pam_kanidm.so ignore_unknown_user` before the first `account … pam_unix.so`; `session optional pam_kanidm.so` before the first `session … pam_unix.so`. Idempotent: skip a file that already contains `pam_kanidm`. **Unit test first:** `tests/test_pam_patch.py` feeds the stock Rocky 9 sssd `system-auth` (a fixture copied from client2 in this step) and asserts the three insertions, their order relative to `pam_faillock`/`pam_unix`, and that a second run changes nothing.

`10-kanidm.conf`:
```
PubkeyAuthentication yes
UsePAM yes
AuthorizedKeysCommand /usr/sbin/kanidm_ssh_authorizedkeys %u
AuthorizedKeysCommandUser nobody
TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys
```
(`trusted_user_ca_keys` comes from Step 1b.)

- [ ] **Step 3: Run, and record denials**

Run (stage the three non-repo files first, straight from their sources, never via the repo):
```bash
rsync -a lab/client/ client2:/tmp/client/
scp -q ~/idm-lab-secrets/unixd-client2.token client2:/tmp/client/token
scp -q ~/idm-lab-secrets/trusted_user_ca_keys client2:/tmp/client/trusted_user_ca_keys
ssh srv1 'cat /etc/step-ca/certs/root_ca.crt' | ssh client2 'cat > /tmp/client/kanidm-lab-root.crt'
lab/client/run.sh 10-enrol
```
Then: `ssh client2 'kanidm-unix status; getent group lab_users; sudo ausearch -m AVC -ts recent 2>/dev/null | audit2why 2>/dev/null | head -40'`
Expected: `system: online`, `Kanidm: online`, and `lab_users` resolves with its GID. Save **all** AVCs verbatim to `lab/selinux/client2-avc-enrol.txt`.

- [ ] **Step 4: STOP POINT, the ISSO SELinux decision** (only if AVCs block unixd, NSS or PAM)

If Step 3 or Task 9 shows SELinux **denying** something needed (e.g. `sshd_t` → `/run/kanidm-unixd/sock`), stop and put the recorded AVCs to the ISSO with:
- **(A, recommended)** a lab-only policy module generated from exactly those AVCs, source in `lab/selinux/kanidm_lab.te`, loaded with `semodule -i`, reversible with `semodule -r`;
- **(B)** upstream's `semanage permissive -a unconfined_service_t` (all unconfined services unenforced).

Do whichever is approved, and record it in `lab/vm-deviations.md` and the Q1 runtime section.

- [ ] **Step 5: Commit**

```bash
git add lab/client lab/srv1/40-groups-svcacct.sh lab/srv1/50-ssh-ca.sh tests/test_pam_patch.py tests/fixtures lab/selinux
git commit -m "client2: kanidm-unixd enrolment (service-account token, upstream nsswitch order, authselect custom profile, sshd); AVCs recorded"
```

---

### Task 9: Lab users, SSH CA, and end-to-end logins

**Files:** Create `lab/srv1/60-users.sh`, `lab/srv1/enrol-user.exp`, `lab/client/test-logins.sh` (runs on the Mac)

**Interfaces:**
- Users `lab01`–`lab06` (fictitious display names "Lab User 1…6"), all in `lab_users`; `lab01` also in `lab_admins`.
- `lab01`–`lab04`: password + TOTP primary credential + POSIX password.
- `lab05`: no credential ("WebAuthn: pending hardware").
- `lab06`: password-only primary credential (if Kanidm allows it; the refusal is itself a finding) + POSIX password.
- Secrets: `~/idm-lab-secrets/labNN.json` = `{"password", "posix_password", "totp_secret"}`.

- [ ] **Step 1: Create the users** (`60-users.sh` + `enrol-user.exp`). For each user:
  - `kanidm person create labNN "Lab User N" --name idm_admin`, then `kanidm group add-members lab_users labNN`, and `kanidm person posix set labNN`;
  - `kanidm person credential create-reset-token labNN`, then `enrol-user.exp` runs `kanidm person credential use-reset-token <token>`. It sets the password (random, 24 chars, from the Mac). For lab01–04 it adds TOTP: it reads the otpauth secret from the screen, answers with `python3 totp.py <secret>`, then commits;
  - `kanidm person posix set-password labNN` sets the separate POSIX password (random).

  The prompts are matched by regex. First run the flow once for `lab01` under `script -q /tmp/enrol-lab01.typescript` to capture the real prompt text. Adjust the regexes to match it, **delete the typescript** (it contains secrets), then run all users.

  Run: `lab/srv1/run.sh 60-users` (inputs are fed from `~/idm-lab-secrets`)
  Expected: for each user, `kanidm person get labNN` shows `posixaccount` and a credential summary matching its plan (TOTP present for 01–04, none for 05, password-only for 06 or a recorded refusal).

- [ ] **Step 2: Resolution comes from Kanidm, not local files** (Review Focus #1)

Run: `ssh client2 'for u in lab01 lab05; do getent passwd $u; done; grep -c "^lab0" /etc/passwd; kanidm-unix status'`
Expected: both users resolve with Kanidm UIDs/home paths, and `/etc/passwd` count `0`.

- [ ] **Step 3: SSH password login + the MFA question** (`lab/client/test-logins.sh`, on the Mac, using macOS `/usr/bin/expect`; the password is read from the secrets JSON inside expect, never on a command line)

For lab01, capture every prompt shown during `ssh lab01@192.168.100.13 id`:
- `Password:` only, meaning the POSIX password with no MFA; or
- `Password:` then a TOTP prompt.

Record which, and repeat for a console login with `virsh console client2` on aero. Expected: `uid=… groups=…lab_users…`, and the prompt sequence recorded **as observed**. That observation is the answer to the "Is MFA enforced at a Linux login?" question.

Negative checks:
- a wrong POSIX password is rejected;
- `lab05` (no credential) is rejected;
- a user **not** in `lab_users` is refused by `pam_allowed_login_groups`. Create `lab07` in no group for this test, then delete it.

- [ ] **Step 4: SSH certificate login** (Review Focus #4)

Run on the Mac:
```bash
ssh-keygen -q -t ecdsa -b 384 -N '' -f ~/idm-lab-secrets/lab02_ecdsa
scp -q ~/idm-lab-secrets/lab02_ecdsa.pub srv1:/tmp/lab02.pub
ssh srv1 'sudo ssh-keygen -s /etc/ssh-ca/user_ca -I lab02-cert -n lab02 -V +1h /tmp/lab02.pub && cat /tmp/lab02-cert.pub && rm -f /tmp/lab02*' > ~/idm-lab-secrets/lab02_ecdsa-cert.pub
ssh -i ~/idm-lab-secrets/lab02_ecdsa -o IdentitiesOnly=yes -o PreferredAuthentications=publickey lab02@192.168.100.13 id
ssh client2 'sudo journalctl -u sshd --since -2min --no-pager | grep -E "Accepted publickey for lab02.*ECDSA-CERT"'
```
Expected: `id` shows lab02, and the log line shows `ECDSA-CERT` with serial and CA key. The key is **not** registered in Kanidm, so only the certificate can have admitted it.

- [ ] **Step 5: Commit** (scripts only; secrets stay in `~/idm-lab-secrets`)

Run `lab/tools/secrets-scan.sh` first → Expected `clean`.
```bash
git add lab/srv1 lab/client && git commit -m "Lab users lab01-06, separate SSH CA (P-384), end-to-end SSH password + certificate logins; MFA prompt behaviour recorded"
```

---

### Task 10: Runtime evidence into the reports; golden snapshots; lab reset

**Files:** Modify `lab/adr0001-q1-packaging.md`, `lab/adr0001-q2-fips.md`, `lab/vm-deviations.md`; create `lab/host/lab-reset.sh` (+ cases in `test_vm_create.sh`)

- [ ] **Step 1: Q1 "Runtime (Plan 3)" section:**
  - the install result under fapolicyd **enforcing**, which proves or disproves the RPM-trust claim, with the exact commands and output;
  - every runtime defect, in the same table format as D1–D5 (continue the numbering at D6);
  - the ADR spike defects: #3 (nsswitch: upstream order used, with the observed result), #4 (POSIX password: works as a separate credential, as observed), #5 (whatever appeared);
  - the SELinux outcome and which option the ISSO chose.

- [ ] **Step 2: Q2 "Runtime (Plan 3)" section:**
  - run Task 7 Step 5 now, and record its TLS evidence (protocol, cipher, key-exchange group per server; any handshake refused by the FIPS client);
  - the Go FIPS results (`fips140=on/only`);
  - the TOTP (HMAC-SHA1) and Argon2 behaviour (they worked or failed under FIPS; they are outside any FIPS module either way);
  - ed25519 refused or allowed by OpenSSH under FIPS;
  - `named` FIPS messages;
  - an updated "honest SSP position" paragraph that states *only* what was observed.

- [ ] **Step 3: `lab-reset.sh`, with tests first.** Add two stub cases to `test_vm_create.sh`:
  - `lab-reset.sh` reverts every named VM that has `golden` and exits 0;
  - it refuses (non-zero, names the VM) if any VM lacks `golden`, before reverting anything.

Run on aero: RED. Then implement:
```bash
#!/usr/bin/env bash
# lab-reset.sh [VM...]: revert lab VMs (default: srv1 client2) to their golden snapshots. All-or-nothing check first.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"; need_root
vms=(); for a in "$@"; do [[ $a == --check ]] || vms+=("$a"); done; (( ${#vms[@]} )) || vms=(srv1 client2)
for v in "${vms[@]}"; do virsh snapshot-info "$v" golden >/dev/null 2>&1 || die "$v has no golden snapshot; nothing reverted"; done
for v in "${vms[@]}"; do run "revert $v to golden" virsh snapshot-revert "$v" golden --running; done
log "lab reset done: ${vms[*]}"
```
Run the tests on aero: GREEN.

- [ ] **Step 4: Golden snapshots, then prove a reset**

Run:
```bash
ssh aero 'for v in srv1 client2; do sudo virsh snapshot-create-as $v golden "identity stack + users, Plan 3"; done'
ssh client2 'sudo touch /root/reset-marker'; lab/host/push.sh lab-reset
sleep 20; ssh client2 'test -e /root/reset-marker && echo MARKER-STILL-THERE || echo RESET-OK; kanidm-unix status'
```
Expected: `RESET-OK` and both providers `online`.

- [ ] **Step 5: Commit**

```bash
git add lab && git commit -m "Q1/Q2 runtime evidence (Plan 3); lab-reset (tested); golden snapshots of srv1 and client2"
```

---

### Task 11: Virtual TPM + LUKS/clevis experiment on client2

**Files:** Create `lab/client/20-vtpm-luks.sh`, `lab/tpm-luks-experiment.md`

- [ ] **Step 1: Is there a TPM, and does it work under FIPS?**

Run: `ssh client2 'ls -l /dev/tpm0 /dev/tpmrm0; sudo tpm2_getcap properties-fixed 2>&1 | grep -A1 -E "TPM2_PT_MANUFACTURER|TPM2_PT_FAMILY_INDICATOR"; sudo tpm2_getrandom --hex 16; echo "rc=$?"; sudo tpm2_pcrread sha256:0,7 2>&1 | head -4'`
Expected: device nodes, the manufacturer (swtpm reports its IBM-style ID), 16 random bytes, and the PCR values. Record everything. If there is no `/dev/tpm0` (b9 fell back without a TPM), record the swtpm error from Task 4 and **end the experiment**. That is itself the finding.

- [ ] **Step 2: Build a LUKS2 volume on the test disk and bind it to the TPM** (`20-vtpm-luks.sh`; the passphrase is generated on client2 into `/root/luks-lab.pass`, 0600: a lab-only fallback key)
```bash
#!/usr/bin/env bash
set -Eeuo pipefail
D=/dev/vdb; P=/root/luks-lab.pass
[[ -s $P ]] || { head -c 32 /dev/urandom | base64 > $P; chmod 600 $P; }
if ! cryptsetup isLuks $D; then
  cryptsetup luksFormat --type luks2 --batch-mode --key-file $P $D
fi
cryptsetup luksDump $D | grep -E 'PBKDF|Cipher|Hash' | sort -u      # FIPS evidence: which KDF did FIPS mode choose?
clevis luks list -d $D | grep -q tpm2 || clevis luks bind -y -k $P -d $D tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
clevis luks list -d $D
cryptsetup open --key-file $P $D labdata 2>/dev/null || true
blkid /dev/mapper/labdata >/dev/null 2>&1 || mkfs.xfs -q /dev/mapper/labdata
uuid=$(cryptsetup luksUUID $D)
grep -q '^labdata ' /etc/crypttab || echo "labdata UUID=$uuid none luks,_netdev" >> /etc/crypttab
mkdir -p /srv/labdata
grep -q '/srv/labdata' /etc/fstab || echo "/dev/mapper/labdata /srv/labdata xfs defaults,_netdev 0 0" >> /etc/fstab
systemctl enable clevis-luks-askpass.path
echo "tpm-bound" > /srv/labdata/marker 2>/dev/null || { mount /srv/labdata && echo "tpm-bound" > /srv/labdata/marker; }
```
Run: `lab/client/run.sh 20-vtpm-luks`
Expected: `luksDump` lines (record the PBKDF: FIPS mode is expected to force **PBKDF2** instead of Argon2id, so note exactly what appears); a `tpm2` slot in `clevis luks list`.

- [ ] **Step 3: Reboot, with no passphrase typed.**

Run: `ssh client2 'sudo systemctl reboot'; sleep 60; ssh client2 'lsblk -o NAME,TYPE,MOUNTPOINT /dev/vdb; cat /srv/labdata/marker'`
Expected: `labdata` is open and mounted, and the marker reads `tpm-bound`. That means **automatic unlock by the virtual TPM**.
Negative check: extend PCR 7 (`tpm2_pcrextend 7:sha256=$(printf 0%.0s {1..64})`), unmount, close and attempt `clevis luks unlock -d /dev/vdb`. Expected: **it fails**, because the TPM policy no longer matches. Then reboot to restore the PCRs.

- [ ] **Step 4: Write `lab/tpm-luks-experiment.md`**, a short record:
  - swtpm under FIPS on aero (worked, or the error);
  - the TPM in a FIPS guest;
  - the LUKS2 parameters FIPS mode chose;
  - clevis TPM2 binding, the unattended unlock result and the negative test;
  - **what this means for dc2**: physical TPM + clevis for data volumes; root-volume unlock needs `clevis-dracut` and is a separate test; PCR choice matters (7 = Secure Boot state; SeaBIOS lab VMs have no Secure Boot, so PCR 7 is weaker here than on dc2's UEFI hardware).

  Plus a revert line: `clevis luks unbind`, `cryptsetup erase`, and the crypttab/fstab lines to delete.

- [ ] **Step 5: Commit**

```bash
git add lab/client/20-vtpm-luks.sh lab/tpm-luks-experiment.md
git commit -m "vTPM (swtpm) + LUKS2/clevis TPM2 experiment on client2: unattended unlock + PCR-mismatch negative test"
```

---

### Task 12: Finish

- [ ] **Step 1:** Keep `golden` (taken in Task 10, before Task 11) as the reset target for Plans 4 and 5. Take an extra snapshot `vtpm-luks` of client2 after Task 11, for reference: `ssh aero 'sudo virsh snapshot-create-as client2 vtpm-luks "after the TPM/LUKS experiment"'`.
- [ ] **Step 2:** Run `lab/tools/secrets-scan.sh` (Expected `clean`), the full test suite (`uv run pytest -q`, `test_inputs.sh`, `test_push_subset.sh`, `test_render.sh`, and `test_vm_create.sh` on aero), and shellcheck on every script.
- [ ] **Step 3:** Pre-publication scan of the branch diff (secrets, emails, public IPs, personal paths), then push the `plan3-srv1-stack` branch and open a PR to `main`.

---

## Self-review notes
- **Spec §4.4 coverage:**
  - step 2 (srv1: BIND, step-ca with ACME + renewal timer, SSH CA, Kanidm with a step-ca cert) → Tasks 5–7 and 9;
  - step 3 (clients: unixd RPM, step-ca root, nsswitch order, POSIX password) → Tasks 8–9;
  - step 4 (6 users, TOTP for 4, WebAuthn user, POSIX groups, short-lived SSH certs) → Task 9. The WebAuthn enrolment is deferred by decision;
  - step 5 (Q1/Q2 reports, incl. step-ca Go crypto under FIPS) → Tasks 6, 7 and 10;
  - step 6 (SELinux denials recorded, options to the ISSO) → Tasks 6, 8 and 10.
- **§8 non-negotiables:** srv1 has no compilers (Task 4 Step 3); build1 runs no identity services (shut down, never enrolled).
- **Plan 2 carry-overs:** RPM trust under enforcing fapolicyd (Task 7 Step 3); the virtual-TPM + LUKS/clevis experiment (Task 11); Kanidm's `tpm` feature deferred (Decision 5).
- **Interactive CLI flows** (reset-token enrolment, POSIX password) are automated with `expect`. Prompt regexes are confirmed against one captured run first, because the exact prompt text for Kanidm 1.11.2 isn't in the book.
