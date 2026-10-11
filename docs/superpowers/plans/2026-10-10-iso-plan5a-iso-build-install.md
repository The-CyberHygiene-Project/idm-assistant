# ISO Plan 5a: Build the ISO, Install From Nothing, CUI Scan — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce `cyberhygiene-lab-installer-el9.iso` from the Rocky 9.8 DVD and our signed repo, prove it installs an
identity server and two clients from nothing on aero (UEFI + Secure Boot + vTPM VMs), and produce the CUI scan's
deviation table with an ISSO decision for every failure (spec §1 gates 1 and 3).

**Architecture:** `build-iso.sh` (aero) copies the DVD's boot chain **unchanged** (shim, grub, kernel, initrd), replaces
only the two boot menus (UEFI `grub.cfg` on the ISO and inside `images/efiboot.img`; a "UEFI required" isolinux
notice), and adds `/chp` (signed repo + `chp-site.pyz` + both kickstarts) with `xorriso … -boot_image any replay`.
The kickstart `%pre` now verifies the repo's `repomd.xml.asc` against the pinned project key before anything else
(row 37). The lab proof reuses the Plan 4 proof stages, swapping the install step for a boot from the ISO.

**Tech Stack:** bash, Python 3.9 stdlib (chp-site), gpgv, xorriso 1.5.4, libvirt/OVMF/swtpm on aero, OpenSCAP, pytest.

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md` (§1 gates, §5.1, §8, §9, §11, §12 item 5).
Requirements: `lab/iso-requirements.md` (row 37 is implemented here; rows 1, 15–17 are re-proven from the ISO).

## Split of spec Plan 5 (decided while writing this plan, 2026-10-10)

Spec §12 item 5 is split, like Plans 3 and 4:
- **5a (this plan):** row 37, `build-iso.sh`, install from nothing from the ISO (gate 1), CUI scan + deviation table (gate 3).
- **5b (next plan):** the regression on installed hosts (gate 2: 33/33 ×3 + row 36), then the release to For Jeff.
  Why separate: the diagnostic engine's scenarios and repairs are bound to the old lab (`srv1`/`client2`, `itadmin`
  with NOPASSWD sudo, SPN group names, paths such as `sshd_config.d/10-kanidm.conf` and
  `anchors/kanidm-lab-root.crt`). The appliance uses different names and paths (`10-chp.conf`, `chp-root.crt`,
  short names). Porting the engine to the appliance layout is a project of its own.
- **Assumed defaults (the user did not answer the question; overturn at review):**
  1. In 5b the test harness gets admin access through a **lab adapter added after the CUI scan**: a lab-only key +
     NOPASSWD account, never in the ISO, recorded as a lab deviation. The scan in this plan therefore runs on
     **pristine** hosts.
  2. **VMs only.** Real hardware is not a gate (spec §1). The first physical install is Jeff's dc2 box.

## Global Constraints

- Every shipped script/kickstart starts with `appliance/branding/file-header.txt` (3 lines). The product is never
  presented as Rocky Linux: menu titles must not contain "Rocky".
- ISO file name `cyberhygiene-lab-installer-el9.iso`; volume ID `CHP-LAB-EL9`.
- **Secure Boot chain unchanged (row 17):** `EFI/BOOT/BOOTX64.EFI`, `grubx64.efi`, `mmx64.efi`,
  `images/pxeboot/vmlinuz` and `initrd.img` are byte-identical to the DVD's, both on the ISO and inside `efiboot.img`.
- DVD input: `/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso`, sha256
  `d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f`, 15194259456 bytes (aero `MANIFEST.txt`).
- Pinned project key (primary fingerprint): `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (`appliance/release/trusted-keys.txt`).
- The boot menu **never installs on a timeout** (`timeout=-1`): installing erases a disk, so a person chooses.
- chp-site stays Python 3.9 **stdlib only** (it runs in the Anaconda environment); the zipapp has no shebang (fapolicyd).
- aero space: `/data` has ~43 GB free, `/var` ~45 GB. The ISO (~15 GB) goes to
  `/var/lib/libvirt/images/chp-iso/<ISO_V>/` (qemu-readable, `virt_image_t`). VM disks stay in `/data/libvirt/images`.
- Secrets never pass through logs, commits or the For Jeff share (spec §6.2). Escrow values move stick → pipe only.
- Python: `~/idm-assistant/.venv/bin/python`; tests `~/idm-assistant/.venv/bin/python -m pytest -q tests`.
  Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- zsh on the Mac does not word-split: run multi-host loops through `bash -c`.

## Review Focus

1. **The repo URL has a trailing slash, or is an `http://` lab URL**: verification works the same (test in Task 1).
2. **`gpgv` is missing or fails to run in the installer:** the install stops with a readable message before any disk is
   touched. It never continues unverified (test in Task 1; `gpgv` is present in the 9.8 `install.img`, checked 2026-10-10).
3. **The signature was made by a signing subkey:** the check compares the **primary** fingerprint (last `VALIDSIG`
   field), not the subkey's (test in Task 1).
4. **Somebody presses Enter on the default menu entry, or walks away:** nothing installs on a timeout. The default
   entry is the server install, but only an explicit Enter starts it (test in Task 3).
5. **The ISO is written to a USB stick, not a DVD:** UEFI USB boot uses GPT partition 2 → `/images/efiboot.img`, so
   our menu must be inside that image too, not only at `/EFI/BOOT/grub.cfg` (check in Task 4's `check-iso.sh`).

---

## File Structure

| File | Responsibility |
|---|---|
| `appliance/chp-site/chp_site/reposig.py` (new) | Row 37: fetch `repomd.xml` + `.asc`, verify with `gpgv` against the bundled key, require a pinned primary fingerprint |
| `appliance/chp-site/chp_site/keys/RPM-GPG-KEY-cyberhygiene` (new) | Bundled copy of the release key (must equal `appliance/release/RPM-GPG-KEY-cyberhygiene`) |
| `appliance/chp-site/chp_site/cli.py` | New `verify-repo` subcommand |
| `appliance/kickstart/chp.ks.in` (+ rendered `server.ks`, `client.ks`) | `%pre` runs `verify-repo` before `pre`; shows the banner |
| `appliance/iso/grub.cfg.in`, `appliance/iso/isolinux.cfg.in`, `appliance/iso/render-boot.sh` (new) | Boot menus |
| `appliance/iso/build-iso.sh`, `appliance/iso/check-iso.sh`, `appliance/iso/push.sh` (new) | Build, inspect and stage the ISO on aero |
| `lab/iso5/install-iso.sh` (new) | Lab: install a VM from the ISO, choosing the menu entry with `virsh send-key` |
| `lab/iso5/prove.sh`, `lab/iso5/hosts`, `lab/iso5/site.conf.in`, `lab/iso5/PROOF-RECORD.md` (new) | Lab proof of gate 1 |
| `lab/iso5/deviations.py`, `lab/iso5/decisions.tsv`, `lab/iso5/DEVIATIONS.md` (new) | Gate 3 |
| `lab/iso2/install.sh` | Name guard widened to `iso5-*` (negative row-37 test reuses it) |
| tests: `test_chp_site_reposig.py`, `test_iso_boot.py`, `test_iso_build_static.py`, `test_deviations.py` (new); `test_kickstarts.py` | |

---

### Task 1: `chp-site verify-repo` (row 37)

**Files:**
- Create: `appliance/chp-site/chp_site/reposig.py`, `appliance/chp-site/chp_site/keys/RPM-GPG-KEY-cyberhygiene`
- Modify: `appliance/chp-site/chp_site/cli.py` (add subcommand), `appliance/chp-site/chp_site/__init__.py` (`VERSION = "0.6.0"`),
  `appliance/chp-site/chp-site.spec` (Version 0.6.0, changelog)
- Test: `tests/test_chp_site_reposig.py`

**Interfaces:**
- Produces: `reposig.verify(url: str, armored_key: str, trusted: tuple[str, ...] = TRUSTED_PRIMARY, gpgv: str = "gpgv") -> str`
  (returns the primary fingerprint; raises `SiteError`), `reposig.dearmor(text: str) -> bytes`,
  `reposig.primary_from_status(status: str) -> str`, `reposig.bundled_key() -> str`, `reposig.TRUSTED_PRIMARY`.
  CLI: `chp-site verify-repo --url URL` → prints `REPO SIGNATURE OK: <url> (signed by <fpr>)`, exit 0; exit 2 on `SiteError`.

- [ ] **Step 1: Copy the key and write the failing tests**

```bash
mkdir -p appliance/chp-site/chp_site/keys
cp appliance/release/RPM-GPG-KEY-cyberhygiene appliance/chp-site/chp_site/keys/
```

`tests/test_chp_site_reposig.py`:

```python
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from chp_site import reposig
from chp_site.cli import main
from chp_site.sitefile import SiteError

TOP = Path(__file__).resolve().parents[1]
GPG = shutil.which("gpg")
needs_gpg = pytest.mark.skipif(GPG is None or shutil.which("gpgv") is None, reason="needs gpg + gpgv")


def test_bundled_key_is_the_release_key():
    assert reposig.bundled_key() == (TOP / "appliance/release/RPM-GPG-KEY-cyberhygiene").read_text()


def test_trusted_primary_matches_the_release_pin():
    pins = [ln.split()[0] for ln in (TOP / "appliance/release/trusted-keys.txt").read_text().splitlines()
            if ln.strip() and not ln.startswith("#") and ln.split()[1] == "cyberhygiene"]
    assert reposig.TRUSTED_PRIMARY == tuple(pins)


def test_primary_from_status_uses_the_last_validsig_field():      # Review Focus 3: subkey signature
    st = ("[GNUPG:] GOODSIG 1111222233334444 t\n"
          "[GNUPG:] VALIDSIG AAAA000000000000000000000000000000000000 2026-10-10 1 0 4 0 1 8 00 "
          "BBBB000000000000000000000000000000000000\n")
    assert reposig.primary_from_status(st) == "BBBB000000000000000000000000000000000000"


def test_primary_from_status_refuses_two_signatures_or_none():
    v = "[GNUPG:] VALIDSIG " + "A" * 40 + " d 1 0 4 0 1 8 00 " + "B" * 40 + "\n"
    with pytest.raises(SiteError):
        reposig.primary_from_status(v + v)
    with pytest.raises(SiteError):
        reposig.primary_from_status("[GNUPG:] NEWSIG\n")


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    if GPG is None:
        pytest.skip("needs gpg")
    home = tmp_path_factory.mktemp("gnupg"); os.chmod(home, 0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    def g(*a, **kw):
        return subprocess.run([GPG, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *a],
                              env=env, check=True, capture_output=True, **kw)
    g("--quick-gen-key", "repo test <t@example.invalid>", "rsa3072", "sign", "never")
    fpr = next(ln.split(":")[9] for ln in g("--with-colons", "--list-keys").stdout.decode().splitlines()
               if ln.startswith("fpr:"))
    armored = g("--armor", "--export", fpr).stdout.decode()
    binary = g("--export", fpr).stdout
    def make_repo(root, body=b"<repomd/>\n", sign=True):
        rd = root / "repodata"; rd.mkdir(parents=True)
        (rd / "repomd.xml").write_bytes(body)
        if sign:
            g("--armor", "--local-user", fpr, "--detach-sign", "-o", str(rd / "repomd.xml.asc"), str(rd / "repomd.xml"))
        return root
    return {"fpr": fpr, "armored": armored, "binary": binary, "make_repo": make_repo}


@needs_gpg
def test_dearmor_matches_gpg_binary_export(signer):
    assert reposig.dearmor(signer["armored"]) == signer["binary"]


@needs_gpg
@pytest.mark.parametrize("slash", ["", "/"])                        # Review Focus 1
def test_good_signature_by_a_pinned_key(signer, tmp_path, slash):
    r = signer["make_repo"](tmp_path / "repo")
    assert reposig.verify(r.as_uri() + slash, signer["armored"], (signer["fpr"],)) == signer["fpr"]


@needs_gpg
def test_tampered_metadata_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo")
    with open(r / "repodata/repomd.xml", "ab") as f:
        f.write(b"<!-- changed -->\n")
    with pytest.raises(SiteError, match="NOT valid"):
        reposig.verify(r.as_uri(), signer["armored"], (signer["fpr"],))


@needs_gpg
def test_valid_signature_by_an_unpinned_key_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo")
    with pytest.raises(SiteError, match="not a pinned"):
        reposig.verify(r.as_uri(), signer["armored"], ("0" * 40,))


@needs_gpg
def test_missing_signature_file_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo", sign=False)
    with pytest.raises(SiteError, match="cannot read"):
        reposig.verify(r.as_uri(), signer["armored"], (signer["fpr"],))


@needs_gpg
def test_signature_by_a_key_not_in_the_keyring_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo")
    other = reposig.bundled_key()                      # the real project key: did not make this signature
    with pytest.raises(SiteError, match="NOT valid"):
        reposig.verify(r.as_uri(), other, (signer["fpr"],))


def test_missing_gpgv_stops_with_a_readable_message(tmp_path):      # Review Focus 2
    rd = tmp_path / "repodata"; rd.mkdir()
    (rd / "repomd.xml").write_text("x"); (rd / "repomd.xml.asc").write_text("y")
    with pytest.raises(SiteError, match="gpgv"):
        reposig.verify(tmp_path.as_uri(), reposig.bundled_key(), gpgv="/nonexistent/gpgv")


@needs_gpg
def test_cli_ok_and_refusal(signer, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reposig, "bundled_key", lambda: signer["armored"])
    monkeypatch.setattr(reposig, "TRUSTED_PRIMARY", (signer["fpr"],))
    r = signer["make_repo"](tmp_path / "repo")
    assert main(["verify-repo", "--url", r.as_uri()]) == 0
    assert f"REPO SIGNATURE OK: {r.as_uri()} (signed by {signer['fpr']})" in capsys.readouterr().out
    (r / "repodata/repomd.xml").write_text("tampered")
    assert main(["verify-repo", "--url", r.as_uri()]) == 2
    assert "NOT valid" in capsys.readouterr().err
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_chp_site_reposig.py`
Expected: FAIL (`ModuleNotFoundError: No module named 'chp_site.reposig'`).

- [ ] **Step 3: Write `appliance/chp-site/chp_site/reposig.py`**

```python
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Row 37: verify the install repository BEFORE anything is installed. Anaconda installs with gpgcheck=0 and
repo_gpgcheck=0; every package's checksum is listed in metadata that repomd.xml pins, so a valid signature on
repomd.xml by a pinned PRIMARY key covers the whole repository. gpgv only: no keyring, no agent, no trust database."""
import base64
import os
import pkgutil
import subprocess
import tempfile
import urllib.error
import urllib.request

from .sitefile import SiteError

TRUSTED_PRIMARY = ("2DE0D71BF37D8F5E4201A590521276F43C908F8E",)   # == appliance/release/trusted-keys.txt (tested)


def bundled_key():
    return pkgutil.get_data("chp_site", "keys/RPM-GPG-KEY-cyberhygiene").decode()


def dearmor(text):
    """ASCII armour -> binary OpenPGP packets (gpgv wants a binary keyring)."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.startswith("-----BEGIN PGP PUBLIC KEY BLOCK"))
        end = next(i for i, ln in enumerate(lines) if i > start and ln.startswith("-----END PGP"))
    except StopIteration:
        raise SiteError("the bundled signing key is not an armoured OpenPGP public key") from None
    body = lines[start + 1:end]
    if "" in body:                                   # armour headers ("Version: …") end at the first blank line
        body = body[body.index("") + 1:]
    return base64.b64decode("".join(ln.strip() for ln in body if not ln.startswith("=")))


def primary_from_status(status):
    """The primary-key fingerprint from gpgv's status output: the LAST field of the one VALIDSIG line."""
    v = [ln.split() for ln in status.splitlines() if ln.startswith("[GNUPG:] VALIDSIG ")]
    if len(v) != 1:
        raise SiteError(f"expected exactly one valid signature on repomd.xml, found {len(v)}")
    return v[0][-1].upper()


def _fetch(url, what):
    try:
        with urllib.request.urlopen(url, timeout=60) as r:      # file:// (the ISO) and http:// (lab) alike
            return r.read()
    except (urllib.error.URLError, OSError) as e:
        raise SiteError(f"cannot read {what} ({url}): {getattr(e, 'reason', e)}") from None


def verify(url, armored_key, trusted=TRUSTED_PRIMARY, gpgv="gpgv"):
    base = url.rstrip("/")
    data = _fetch(f"{base}/repodata/repomd.xml", "the repository metadata")
    sig = _fetch(f"{base}/repodata/repomd.xml.asc", "the repository signature")
    with tempfile.TemporaryDirectory() as d:
        paths = {n: os.path.join(d, n) for n in ("keyring.gpg", "repomd.xml", "repomd.xml.asc")}
        for name, blob in (("keyring.gpg", dearmor(armored_key)), ("repomd.xml", data), ("repomd.xml.asc", sig)):
            with open(paths[name], "wb") as f:
                f.write(blob)
        try:
            r = subprocess.run([gpgv, "--status-fd", "1", "--keyring", paths["keyring.gpg"], paths["repomd.xml.asc"],
                                paths["repomd.xml"]], capture_output=True, text=True, env=dict(os.environ, GNUPGHOME=d))
        except OSError as e:
            raise SiteError(f"cannot run gpgv ({e.strerror}): the repository cannot be verified") from None
    if r.returncode != 0:
        raise SiteError(f"the install repository's signature is NOT valid ({base}): it was changed, or not signed "
                        "by the project key")
    fpr = primary_from_status(r.stdout)
    if fpr not in tuple(t.upper() for t in trusted):
        raise SiteError(f"repomd.xml is signed by {fpr}, which is not a pinned project key")
    return fpr
```

- [ ] **Step 4: Wire the CLI** in `appliance/chp-site/chp_site/cli.py`: add the handler next to `_pre`, the parser
  line next to the `pre` parser, and the dispatch entry; update the module docstring's command list.

```python
def _verify_repo(a):
    from . import reposig
    fpr = reposig.verify(a.url, reposig.bundled_key())
    print(f"REPO SIGNATURE OK: {a.url} (signed by {fpr})")
```

```python
    vr = sub.add_parser("verify-repo", help="row 37: the repo's repomd.xml must be signed by a pinned project key")
    vr.add_argument("--url", required=True)
```

  Dispatch map: add `"verify-repo": _verify_repo,`.

  Set `VERSION = "0.6.0"` in `__init__.py`; in `chp-site.spec` set `Version: 0.6.0`, `Release: 1.chp%{?dist}` and add a
  changelog entry: `* Sat Oct 10 2026 The CyberHygiene Project - 0.6.0-1.chp` / `- verify-repo: the installer checks the
  repo signature before installing (row 37).`

- [ ] **Step 5: Run the tests**

Run: `.venv/bin/python -m pytest -q tests/test_chp_site_reposig.py tests/test_chp_site_cli.py`
Expected: all PASS (the gpg tests need Homebrew `gpg`/`gpgv`, present on the Mac). Then build the zipapp and check that
the key is inside it: `bash appliance/chp-site/build.sh && python3 -c "import zipfile; print('chp_site/keys/RPM-GPG-KEY-cyberhygiene' in zipfile.ZipFile('appliance/chp-site/dist/chp-site.pyz').namelist())"`
→ `True`.

- [ ] **Step 6: Full suite, then commit**

Run: `.venv/bin/python -m pytest -q tests` → all PASS.

```bash
git add appliance/chp-site tests/test_chp_site_reposig.py
git commit -m "ISO Plan 5a Task 1: chp-site verify-repo (row 37): pinned primary key, gpgv, file:// and http://

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Kickstart `%pre` verifies the repo first

**Files:**
- Modify: `appliance/kickstart/chp.ks.in` (`%pre`), re-render `server.ks` and `client.ks`
- Test: `tests/test_kickstarts.py`

**Interfaces:**
- Consumes: `python3 "$pyz" verify-repo --url "$repo"` (Task 1).
- Produces: `%pre` order: banner → stick mount → `verify-repo` → `pre`. A refusal prints
  `CHP: install stopped before any disk was touched.` (the existing lab stop marker).

- [ ] **Step 1: Failing tests** (append to `tests/test_kickstarts.py`)

```python
BANNER = (Path(__file__).resolve().parents[1] / "appliance" / "branding" / "boot-banner.txt").read_text()


@pytest.mark.parametrize("role", ["server", "client"])
def test_pre_verifies_the_repo_before_the_site_gate(role):
    pre = (KS / f"{role}.ks").read_text().split("%pre", 1)[1].split("%end", 1)[0]
    assert 'verify-repo --url "$repo"' in pre
    assert pre.index("verify-repo") < pre.index(f"pre --role {role}")     # before any escrow is written


@pytest.mark.parametrize("role", ["server", "client"])
def test_pre_shows_the_banner(role):
    pre = (KS / f"{role}.ks").read_text().split("%pre", 1)[1].split("%end", 1)[0]
    for line in (ln for ln in BANNER.splitlines() if ln.strip()):
        assert line in pre
```

- [ ] **Step 2: Run them**: `.venv/bin/python -m pytest -q tests/test_kickstarts.py` → the two new tests FAIL.

- [ ] **Step 3: Edit `%pre` in `appliance/kickstart/chp.ks.in`.** After `set -uo pipefail`, add the banner; after the
  `pyz` lookup (the `if [ ! -f "$pyz" ]` line), insert the verification:

```bash
cat > /dev/console <<'CHP_BANNER'

CyberHygiene Project Lab Installer
Internal test image — not an official Rocky Linux product

Built for use with Rocky Linux 9
Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.

CHP_BANNER
```

```bash
# Row 37: Anaconda installs with gpgcheck=0. Verify the repo actually used (the ISO's, or a chp.repo= lab override)
# against the pinned project key BEFORE the site gate writes any escrow and before any disk is touched.
python3 "$pyz" verify-repo --url "$repo" 2>&1 | tee /dev/console
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
  echo "CHP: install stopped before any disk was touched." | tee /dev/console; exit 1
fi
```

  The banner text must match `appliance/branding/boot-banner.txt` line for line (the test checks it).

- [ ] **Step 4: Re-render and test**

Run: `bash appliance/kickstart/render-ks.sh && .venv/bin/python -m pytest -q tests/test_kickstarts.py`
Expected: all PASS (including the pykickstart `ksvalidator` test when `uvx` is available).

- [ ] **Step 5: Commit**

```bash
git add appliance/kickstart tests/test_kickstarts.py
git commit -m "ISO Plan 5a Task 2: %pre verifies the repo signature before the site gate; banner on the console

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Boot menus

**Files:**
- Create: `appliance/iso/grub.cfg.in`, `appliance/iso/isolinux.cfg.in`, `appliance/iso/render-boot.sh`
- Test: `tests/test_iso_boot.py`

**Interfaces:**
- Produces: `render-boot.sh OUT_DIR [VOLID]` writes `OUT_DIR/grub.cfg` and `OUT_DIR/isolinux.cfg` (VOLID default
  `CHP-LAB-EL9`). Menu order (the lab's `send-key` relies on it): 0 server, 1 client, 2 server (serial console),
  3 client (serial console), 4 boot from local disk.

- [ ] **Step 1: Failing tests** `tests/test_iso_boot.py`

```python
import re
import subprocess
from pathlib import Path

import pytest

ISO = Path(__file__).resolve().parents[1] / "appliance" / "iso"
BANNER = (Path(__file__).resolve().parents[1] / "appliance/branding/boot-banner.txt").read_text()


@pytest.fixture(scope="module")
def out(tmp_path_factory):
    d = tmp_path_factory.mktemp("boot")
    subprocess.run(["bash", str(ISO / "render-boot.sh"), str(d)], check=True, capture_output=True)
    return d


def entries(cfg):
    return re.findall(r"menuentry '([^']+)'[^{]*\{(.*?)\n\}", cfg, re.S)


def test_menu_order_and_kernel_arguments(out):
    e = entries((out / "grub.cfg").read_text())
    titles = [t for t, _ in e]
    assert titles[0].startswith("Install identity server") and titles[1].startswith("Install client workstation")
    assert "serial console" in titles[2] and titles[2].startswith("Install identity server")
    assert "serial console" in titles[3] and titles[3].startswith("Install client workstation")
    assert titles[4] == "Boot from the local disk"
    for i, role in ((0, "server"), (1, "client"), (2, "server"), (3, "client")):
        body = e[i][1]
        assert "inst.stage2=hd:LABEL=CHP-LAB-EL9 " in body
        assert f"inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/{role}.ks" in body
        assert "fips=1" in body and "quiet" not in body and "rd.live.check" not in body
        assert ("console=ttyS0,115200" in body) == (i >= 2)       # serial only on the serial entries
    assert "exit" in e[4][1]


def test_never_installs_on_a_timeout(out):                           # Review Focus 4
    cfg = (out / "grub.cfg").read_text()
    assert re.search(r"^set timeout=-1$", cfg, re.M) and "set default=\"0\"" in cfg


def test_label_and_branding(out):
    cfg = (out / "grub.cfg").read_text()
    assert "search --no-floppy --set=root -l 'CHP-LAB-EL9'" in cfg
    assert not any("Rocky" in t for t, _ in entries(cfg))           # never presented as Rocky Linux
    for line in (ln for ln in BANNER.splitlines() if ln.strip()):
        assert f"echo '{line}'" in cfg


def test_bios_boot_only_says_uefi_is_required(out):
    t = (out / "isolinux.cfg").read_text()
    assert "UEFI" in t and not re.search(r"^\s*(kernel|append|label)\b", t, re.M | re.I)


def test_volid_override(tmp_path):
    subprocess.run(["bash", str(ISO / "render-boot.sh"), str(tmp_path), "TEST-VOL"], check=True, capture_output=True)
    assert "hd:LABEL=TEST-VOL:/chp/ks/server.ks" in (tmp_path / "grub.cfg").read_text()
```

- [ ] **Step 2: Run them**: `.venv/bin/python -m pytest -q tests/test_iso_boot.py` → FAIL (no `render-boot.sh`).

- [ ] **Step 3: Write `appliance/iso/grub.cfg.in`**

```
# CyberHygiene Project Lab Installer — UEFI boot menu (rendered by render-boot.sh; @VOLID@ = the ISO volume ID).
# Rocky Linux's signed shim, grub and kernel are used unchanged; only this menu differs. Nothing installs on a timeout.
set default="0"
set timeout=-1
function load_video {
  insmod efi_gop
  insmod efi_uga
  insmod video_bochs
  insmod video_cirrus
  insmod all_video
}
load_video
set gfxpayload=keep
insmod gzio
insmod part_gpt
insmod ext2
search --no-floppy --set=root -l '@VOLID@'
@BANNER_ECHO@
menuentry 'Install identity server  (erases the disk of this machine)' --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=@VOLID@ inst.ks=hd:LABEL=@VOLID@:/chp/ks/server.ks fips=1
	initrdefi /images/pxeboot/initrd.img
}
menuentry 'Install client workstation  (erases the disk of this machine)' --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=@VOLID@ inst.ks=hd:LABEL=@VOLID@:/chp/ks/client.ks fips=1
	initrdefi /images/pxeboot/initrd.img
}
menuentry 'Install identity server, serial console ttyS0' --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=@VOLID@ inst.ks=hd:LABEL=@VOLID@:/chp/ks/server.ks fips=1 console=ttyS0,115200
	initrdefi /images/pxeboot/initrd.img
}
menuentry 'Install client workstation, serial console ttyS0' --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=@VOLID@ inst.ks=hd:LABEL=@VOLID@:/chp/ks/client.ks fips=1 console=ttyS0,115200
	initrdefi /images/pxeboot/initrd.img
}
menuentry 'Boot from the local disk' --class os {
	exit
}
```

  Why serial entries: a headless server installs over a serial line; the lab uses them so the escrowed LUKS
  passphrase can be answered over the serial console on first boot (Anaconda copies `console=` to the installed
  system). The plain entries keep `/dev/console` on the screen for a person at the machine.

- [ ] **Step 4: Write `appliance/iso/isolinux.cfg.in`**

```
# CyberHygiene Project Lab Installer — legacy BIOS boot: refuse, with a message (row 17: UEFI + Secure Boot only).
@BANNER_SAY@
say
say This installer starts only in UEFI mode with Secure Boot on.
say Restart, open the firmware boot menu, and choose the UEFI entry for this DVD or USB stick.
prompt 1
timeout 0
```

- [ ] **Step 5: Write `appliance/iso/render-boot.sh`**

```bash
#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# render-boot.sh OUT_DIR [VOLID]: grub.cfg and isolinux.cfg for the ISO (banner from appliance/branding/boot-banner.txt).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; out=$1; volid=${2:-CHP-LAB-EL9}
mkdir -p "$out"
python3 - "$here" "$out" "$volid" <<'PY'
import sys
here, out, volid = sys.argv[1:]
banner = [ln for ln in open(f"{here}/../branding/boot-banner.txt").read().splitlines() if ln.strip()]
for ln in banner:
    assert "'" not in ln, "banner lines must not contain a single quote (grub echo quoting)"
echo = "\n".join(f"echo '{ln}'" for ln in banner)
say = "\n".join(f"say {ln}" for ln in banner)
g = open(f"{here}/grub.cfg.in").read().replace("@VOLID@", volid).replace("@BANNER_ECHO@", echo)
i = open(f"{here}/isolinux.cfg.in").read().replace("@BANNER_SAY@", say)
open(f"{out}/grub.cfg", "w").write(g)
open(f"{out}/isolinux.cfg", "w").write(i)
PY
echo "rendered: $out/grub.cfg $out/isolinux.cfg ($volid)"
```

- [ ] **Step 6: Run the tests**: `.venv/bin/python -m pytest -q tests/test_iso_boot.py` → all PASS.

- [ ] **Step 7: Commit**

```bash
git add appliance/iso tests/test_iso_boot.py
git commit -m "ISO Plan 5a Task 3: boot menus (server/client, serial variants, no timeout install; BIOS refuses)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `build-iso.sh` and `check-iso.sh`

**Files:**
- Create: `appliance/iso/build-iso.sh`, `appliance/iso/check-iso.sh`, `appliance/iso/push.sh`
- Test: `tests/test_iso_build_static.py`; the real test is `check-iso.sh` on aero (Task 6)

**Interfaces:**
- `push.sh` (Mac): builds `chp-site.pyz`, renders kickstarts and boot menus, copies them plus
  `appliance/branding/NOTICE.txt` and the two scripts to `aero:/data/chp-release/iso-src/` (replacing it).
- `sudo build-iso.sh REPO_V ISO_V` (aero): output `/var/lib/libvirt/images/chp-iso/$ISO_V/` with
  `cyberhygiene-lab-installer-el9.iso`, `SHA256SUMS`, `BUILD-RECORD.txt`. Refuses an existing output dir.
- `sudo check-iso.sh ISO DVD` (aero): prints one `OK …`/`BAD …` line per check, then `ISO OK` (exit 0) or `ISO BAD` (exit 1).

- [ ] **Step 1: Failing static tests** `tests/test_iso_build_static.py`

```python
from pathlib import Path

ISO = Path(__file__).resolve().parents[1] / "appliance" / "iso"
HEADER = (Path(__file__).resolve().parents[1] / "appliance/branding/file-header.txt").read_text()


def test_scripts_carry_the_header_and_strict_mode():
    for s in ("build-iso.sh", "check-iso.sh", "push.sh", "render-boot.sh"):
        t = (ISO / s).read_text()
        assert t.startswith("#!/usr/bin/env bash\n" + HEADER), s
        assert "set -Eeuo pipefail" in t, s


def test_build_keeps_the_boot_chain_and_pins_inputs():
    t = (ISO / "build-iso.sh").read_text()
    assert "-boot_image any replay" in t and "discard" not in t
    assert "d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f" in t
    assert "verify-repo.sh" in t and "refusing:" in t
    assert "VOLID=CHP-LAB-EL9" in t and '-volid "$VOLID"' in t
    for p in ("/EFI/BOOT/grub.cfg", "/isolinux/isolinux.cfg", "/images/efiboot.img", "/chp", "/NOTICE.txt"):
        assert p in t


def test_check_compares_the_secure_boot_chain_with_the_dvd():
    t = (ISO / "check-iso.sh").read_text()
    for f in ("BOOTX64.EFI", "grubx64.efi", "mmx64.efi", "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img"):
        assert f in t
    assert "efiboot" in t and "isohybrid-gpt-basdat" in t                # Review Focus 5: USB boot path
```

- [ ] **Step 2: Run**: `.venv/bin/python -m pytest -q tests/test_iso_build_static.py` → FAIL.

- [ ] **Step 3: Write `appliance/iso/build-iso.sh`**

```bash
#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# build-iso.sh REPO_V ISO_V (RUNS ON AERO, sudo): the Rocky 9.8 DVD + signed repo REPO_V + /data/chp-release/iso-src
# -> /var/lib/libvirt/images/chp-iso/ISO_V/cyberhygiene-lab-installer-el9.iso. The boot chain (shim, grub, kernel,
# initrd, El Torito and GPT boot records) is replayed from the DVD unchanged; only the menus and /chp are new.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
REPO_V=$1 ISO_V=$2
DVD=/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso
DVD_SHA=d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f
REPO=/data/chp-release/$REPO_V/repo TOOLS=/data/chp-release/tools SRC=/data/chp-release/iso-src
OUT=/var/lib/libvirt/images/chp-iso/$ISO_V NAME=cyberhygiene-lab-installer-el9.iso VOLID=CHP-LAB-EL9
[[ -e $OUT ]] && { echo "refusing: $OUT exists"; exit 1; }
for f in grub.cfg isolinux.cfg server.ks client.ks chp-site.pyz NOTICE.txt; do
  [[ -f $SRC/$f ]] || { echo "refusing: $SRC/$f missing (run appliance/iso/push.sh on the Mac)"; exit 1; }
done
avail=$(df --output=avail -B1G /var/lib/libvirt/images | tail -1 | tr -d ' ')
(( avail >= 20 )) || { echo "refusing: only ${avail} GB free under /var/lib/libvirt/images (need 20)"; exit 1; }
echo "== DVD: sha256 (takes about a minute)"
[[ $(sha256sum "$DVD" | cut -d' ' -f1) == "$DVD_SHA" ]] || { echo "refusing: DVD sha256 differs from the pin"; exit 1; }
echo "== repo $REPO_V: signatures"
bash "$TOOLS/verify-repo.sh" "$REPO" "$TOOLS"
W=$(mktemp -d -p /var/tmp chp-iso.XXXXXX); m=$W/mnt; mkdir "$m"
trap 'mountpoint -q "$m" && umount "$m"; rm -rf "$W"' EXIT
echo "== stage /chp"
mkdir -p "$W/chp/ks"
cp -a "$REPO"/. "$W/chp/"
install -m 0644 "$SRC/chp-site.pyz" "$W/chp/chp-site.pyz"
install -m 0644 "$SRC/server.ks" "$SRC/client.ks" "$W/chp/ks/"
echo "== efiboot.img: our grub.cfg (USB/UEFI boot reads this copy; the EFI binaries are not touched)"
xorriso -osirrox on -indev "$DVD" -extract /images/efiboot.img "$W/efiboot.img" 2>/dev/null
chmod u+w "$W/efiboot.img"
mount -o loop "$W/efiboot.img" "$m"
[[ -f $m/EFI/BOOT/grub.cfg ]] || { echo "efiboot.img has no EFI/BOOT/grub.cfg"; exit 1; }
cp "$SRC/grub.cfg" "$m/EFI/BOOT/grub.cfg"; sync; umount "$m"
echo "== ISO"
mkdir -p "$OUT"
xorriso -indev "$DVD" -outdev "$OUT/$NAME" -volid "$VOLID" \
  -map "$W/chp" /chp \
  -map "$SRC/grub.cfg" /EFI/BOOT/grub.cfg \
  -map "$SRC/isolinux.cfg" /isolinux/isolinux.cfg \
  -map "$W/efiboot.img" /images/efiboot.img \
  -map "$SRC/NOTICE.txt" /NOTICE.txt \
  -boot_image any replay 2>&1 | tail -3
(cd "$OUT" && sha256sum "$NAME" > SHA256SUMS)
{ echo "ISO $ISO_V built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname -s)"
  echo "DVD Rocky-9.8-x86_64-dvd.iso sha256 $DVD_SHA"
  echo "repo $REPO_V repomd.xml sha256 $(sha256sum "$REPO/repodata/repomd.xml" | cut -d' ' -f1)"
  for f in chp-site.pyz server.ks client.ks grub.cfg isolinux.cfg NOTICE.txt; do echo "$f sha256 $(sha256sum "$SRC/$f" | cut -d' ' -f1)"; done
  echo "xorriso $(xorriso -version 2>/dev/null | head -1)"
  cat "$OUT/SHA256SUMS"; } > "$OUT/BUILD-RECORD.txt"
chmod 0644 "$OUT"/*
echo "built: $OUT/$NAME"
```

- [ ] **Step 4: Write `appliance/iso/check-iso.sh`**

```bash
#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# check-iso.sh ISO DVD (RUNS ON AERO, sudo): inspect a built ISO. The Secure Boot chain must be byte-identical to the
# DVD's (on the ISO and inside efiboot.img), both menus must be ours, /chp must hold a signed repo, and the boot records
# must still point at /images/efiboot.img (El Torito for DVD, GPT partition for USB). One line per check; exit 1 on any BAD.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
ISO=$1 DVD=$2 bad=0
W=$(mktemp -d -p /var/tmp chp-check.XXXXXX); trap 'for d in "$W"/m*; do mountpoint -q "$d" && umount "$d"; done; rm -rf "$W"' EXIT
ok() { echo "OK   $1"; }
no() { echo "BAD  $1"; bad=1; }
x() { xorriso -osirrox on -indev "$1" -extract "$2" "$3" 2>/dev/null; }
[[ $(xorriso -indev "$ISO" -pvd_info 2>/dev/null | sed -n "s/^Volume Id *: *//p" | tr -d "'") == CHP-LAB-EL9 ]] && ok "volume ID CHP-LAB-EL9" || no "volume ID"
el=$(xorriso -indev "$ISO" -report_el_torito as_mkisofs 2>/dev/null)
[[ $el == *"-e '/images/efiboot.img'"* && $el == *"-isohybrid-gpt-basdat"* ]] && ok "boot records: El Torito EFI + GPT partition -> /images/efiboot.img" || no "boot records"
for p in /chp/repodata/repomd.xml.asc /chp/chp-site.pyz /chp/ks/server.ks /chp/ks/client.ks /NOTICE.txt; do
  x "$ISO" "$p" "$W/f" && ok "present: $p" || no "missing: $p"; rm -f "$W/f"
done
for f in EFI/BOOT/BOOTX64.EFI EFI/BOOT/grubx64.efi EFI/BOOT/mmx64.efi images/pxeboot/vmlinuz images/pxeboot/initrd.img; do
  x "$DVD" "/$f" "$W/a"; x "$ISO" "/$f" "$W/b"
  cmp -s "$W/a" "$W/b" && ok "unchanged from the DVD: $f" || no "CHANGED: $f"; rm -f "$W/a" "$W/b"
done
x "$DVD" /images/efiboot.img "$W/e1"; x "$ISO" /images/efiboot.img "$W/e2"; mkdir "$W/m1" "$W/m2"
mount -o loop,ro "$W/e1" "$W/m1"; mount -o loop,ro "$W/e2" "$W/m2"
for f in EFI/BOOT/BOOTX64.EFI EFI/BOOT/grubx64.efi EFI/BOOT/mmx64.efi; do
  cmp -s "$W/m1/$f" "$W/m2/$f" && ok "efiboot.img unchanged: $f" || no "efiboot.img CHANGED: $f"
done
x "$ISO" /EFI/BOOT/grub.cfg "$W/g"
cmp -s "$W/g" "$W/m2/EFI/BOOT/grub.cfg" && ok "efiboot.img grub.cfg == ISO grub.cfg (USB boot shows our menu)" || no "efiboot.img grub.cfg differs"
grep -q "CHP-LAB-EL9:/chp/ks/server.ks" "$W/g" && ! grep -q "Install Rocky" "$W/g" && ok "menu is ours" || no "menu"
mkdir "$W/repo"; xorriso -osirrox on -indev "$ISO" -extract /chp "$W/repo" 2>/dev/null
bash /data/chp-release/tools/verify-repo.sh "$W/repo" /data/chp-release/tools >/dev/null && ok "repo on the ISO verifies" || no "repo on the ISO"
python3 "$W/repo/chp-site.pyz" verify-repo --url "file://$W/repo" >/dev/null && ok "chp-site verify-repo accepts it" || no "chp-site verify-repo"
if (( bad )); then echo "ISO BAD"; exit 1; fi
echo "ISO OK"
```

- [ ] **Step 5: Write `appliance/iso/push.sh`**

```bash
#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# push.sh (RUNS ON THE MAC): build/render the ISO inputs and copy them, with the build scripts, to aero.
set -Eeuo pipefail
top="$(cd "$(dirname "$0")/../.." && pwd)"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
bash "$top/appliance/chp-site/build.sh" >/dev/null
bash "$top/appliance/kickstart/render-ks.sh" >/dev/null
bash "$top/appliance/iso/render-boot.sh" "$T" >/dev/null
cp "$top/appliance/chp-site/dist/chp-site.pyz" "$top/appliance/kickstart/server.ks" "$top/appliance/kickstart/client.ks" \
   "$top/appliance/branding/NOTICE.txt" "$top/appliance/iso/build-iso.sh" "$top/appliance/iso/check-iso.sh" "$T/"
ssh aero 'rm -rf /data/chp-release/iso-src && mkdir -p /data/chp-release/iso-src'
scp -q "$T"/* aero:/data/chp-release/iso-src/
echo "pushed to aero:/data/chp-release/iso-src/: $(ls "$T" | tr '\n' ' ')"
```

- [ ] **Step 6: Run the static tests**: `.venv/bin/python -m pytest -q tests/test_iso_build_static.py` → all PASS.

- [ ] **Step 7: Commit**

```bash
git add appliance/iso tests/test_iso_build_static.py
git commit -m "ISO Plan 5a Task 4: build-iso.sh (DVD boot chain replayed unchanged), check-iso.sh, push.sh

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Signed repo 0.6.0 and the first ISO

**Files:** Create `appliance/release/RELEASE-RECORD-0.6.0.md`. No code.

- [ ] **Step 1: Build the chp-site 0.6.0 RPM**: `bash appliance/chp-site/build-rpm.sh`.
  Expected: the `rpm -qlp` listing names `/usr/bin/chp-site` and `/etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene`, and the RPM
  file is `chp-site-0.6.0-1.chp.el9.noarch.rpm`.

- [ ] **Step 2: Sign repo 0.6.0 (the user touches the YubiKey).** Tell the user first: "a PIN dialog (click inside it
  first; it may be behind other windows), then about 15 touches".

```bash
bash appliance/release/push.sh
FPR=$(awk '$2=="cyberhygiene"{print $1}' appliance/release/trusted-keys.txt)
ssh aero 'bash /data/chp-release/tools/assemble-repo.sh /data/chp-release/0.6.0/stage /data/chp-release/built /data/lab-inputs/rpms'
bash appliance/release/sign-session.sh "bash /data/chp-release/tools/sign-repo.sh /data/chp-release/0.6.0/stage /data/chp-release/0.6.0/repo $FPR /data/chp-release/tools"
ssh aero 'sudo cp -a /data/chp-release/0.6.0/repo /data/lab-inputs/chp/0.6.0 && curl -fsI http://192.168.100.1:8080/chp/0.6.0/repodata/repomd.xml.asc | head -1'
```

  Expected: 11 packages staged (`chp-site ← chp-site-0.6.0-1…`), `REPO OK: 11 packages…`, `HTTP/1.0 200 OK`.

- [ ] **Step 3: Build and check the ISO**

```bash
bash appliance/iso/push.sh
ssh aero 'sudo bash /data/chp-release/iso-src/build-iso.sh 0.6.0 0.1.0-rc1'
ssh aero 'sudo bash /data/chp-release/iso-src/check-iso.sh /var/lib/libvirt/images/chp-iso/0.1.0-rc1/cyberhygiene-lab-installer-el9.iso /data/lab-inputs/Rocky-9.8-x86_64-dvd.iso'
```

  Expected: `built: …`, then every check `OK` and the last line `ISO OK`. If any line says `BAD`, stop and debug
  (superpowers:systematic-debugging); do not continue to Task 6 with a BAD ISO.

- [ ] **Step 4: Write `appliance/release/RELEASE-RECORD-0.6.0.md`** in the 0.5.8 record's format (why 0.6.0: chp-site
  0.6.0 adds `verify-repo`; package table with key IDs and sha256 from `rpm -K`/`sha256sum` on aero; repomd sha256;
  the `verify-repo.sh` line), plus a section "ISO 0.1.0-rc1" pasting `BUILD-RECORD.txt` and the `check-iso.sh` output.

- [ ] **Step 5: Commit** `appliance/release/RELEASE-RECORD-0.6.0.md` with the message
  `ISO Plan 5a Task 5: signed repo 0.6.0 (chp-site 0.6.0); ISO 0.1.0-rc1 built and checked`.

---

### Task 6: Install from nothing, from the ISO (gate 1)

**Files:**
- Create: `lab/iso5/install-iso.sh`, `lab/iso5/hosts`, `lab/iso5/site.conf.in`, `lab/iso5/prove.sh`, `lab/iso5/PROOF-RECORD.md`
- Modify: `lab/iso2/install.sh` (name guard `iso[2345]-*`)

**Interfaces:**
- `sudo install-iso.sh NAME MAC ENTRY STICK_IMG NDISKS ISO [--expect-stop]` (aero): ENTRY is the menu index (Task 3).
  Same serial log path as `lab/iso2/install.sh` (`/var/log/libvirt/qemu/NAME-install.log`), so `unlock.sh` works
  unchanged. Prints `INSTALLED and started NAME (stick + ISO detached)`, or `STOPPED: …` + disk zero-checks.
- Lab site `iso5.lab.test`: `iso5-srv` 52:54:00:c4:05:50 / .50 server; `iso5-cli1` …:51 / .51 client;
  `iso5-cli2` …:52 / .52 client.

- [ ] **Step 1: Write `lab/iso5/install-iso.sh`**

```bash
#!/usr/bin/env bash
# install-iso.sh NAME MAC ENTRY STICK_IMG NDISKS ISO [--expect-stop] (RUNS ON AERO, sudo): install one iso5-* VM by
# BOOTING THE ISO, the way a person would: wait for our menu on the serial console, choose ENTRY with the keyboard
# (virsh send-key), and let the kickstart run. Firmware as in lab/iso2/install.sh: q35, UEFI Secure Boot with enrolled
# keys, vTPM; the stick is a removable USB disk. Afterwards the stick and the ISO are detached ("removed").
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
name=$1 mac=$2 entry=$3 stick=$4 ndisks=$5 iso=$6 expect_stop=${7:-}
[[ $name == iso5-* ]] || { echo "refusing: only iso5-* lab VMs are managed here"; exit 1; }
log=/var/log/libvirt/qemu/$name-install.log
rm_vm() { virsh destroy "$1" >/dev/null 2>&1 || true; virsh undefine "$1" --nvram >/dev/null 2>&1 || true; rm -f /data/libvirt/images/"$1"-[0-9].qcow2; }
if virsh dominfo "$name" >/dev/null 2>&1; then rm_vm "$name"; fi
rm -f "$log"
disks=(); for i in $(seq 1 "$ndisks"); do disks+=(--disk "path=/data/libvirt/images/$name-$i.qcow2,size=120,format=qcow2"); done
virt-install --name "$name" --memory 4096 --vcpus 2 --cpu host-passthrough --osinfo detect=on,name=rhel9-unknown \
  --machine q35 --features smm.state=on \
  --boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes \
  --tpm emulator,model=tpm-crb,version=2.0 --check disk_size=off \
  "${disks[@]}" --disk "path=$stick,format=raw,bus=usb,removable=on" --cdrom "$iso" \
  --network "bridge=br-lab,mac=$mac" --graphics none --serial "pty,log.file=$log" \
  --noautoconsole --noreboot --wait 0 >"/tmp/iso2/$name-virt-install.out" 2>&1
# Our menu on the serial console (OVMF mirrors grub there), then the keyboard: ENTRY x Down, Enter.
for _ in $(seq 60); do grep -q "Boot from the local disk" "$log" 2>/dev/null && break; sleep 2; done
grep -q "Boot from the local disk" "$log" || { echo "MENU NOT SEEN in $log"; exit 1; }
sleep 2
for _ in $(seq 1 "$entry"); do virsh send-key "$name" KEY_DOWN >/dev/null; sleep 0.3; done
virsh send-key "$name" KEY_ENTER >/dev/null
for _ in $(seq 60); do grep -q "inst.ks=hd:LABEL=CHP-LAB-EL9" "$log" 2>/dev/null && break; sleep 2; done
grep -o -m1 "inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/[a-z]*.ks" "$log" | sed 's/^/BOOTED: /' || { echo "ENTRY NOT BOOTED"; exit 1; }
if [[ $expect_stop == --expect-stop ]]; then
  for _ in $(seq 120); do grep -q "CHP: install stopped" "$log" 2>/dev/null && break; sleep 5; done
  grep -q "CHP: install stopped" "$log" && echo "STOPPED: $(grep -m1 -o 'chp-site: .*' "$log" | tr -d '\r')" || echo "NOT STOPPED"
  virsh destroy "$name" >/dev/null 2>&1 || true
  for i in $(seq 1 "$ndisks"); do
    d=/data/libvirt/images/$name-$i.qcow2
    sz=$(qemu-img info --output=json "$d" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
    f=$(qemu-io -r -f qcow2 -c "read -P 0 0 1M" -c "read -P 0 $((sz - 1048576)) 1M" "$d" 2>&1 | grep -c "Pattern verification failed" || true)
    echo "disk $i zero-check-failures=$f"
  done
  rm_vm "$name"; exit 0
fi
for _ in $(seq 540); do [[ $(virsh domstate "$name" 2>/dev/null) == "shut off" ]] && break; sleep 10; done   # <= 90 min
state=$(virsh domstate "$name" 2>/dev/null || echo missing)
[[ $state == "shut off" ]] || { virsh destroy "$name" >/dev/null 2>&1 || true; echo "INSTALL DID NOT FINISH (state $state); see $log"; exit 1; }
virt-xml "$name" --remove-device --disk "path=$stick" >/dev/null
virt-xml "$name" --remove-device --disk device=cdrom >/dev/null 2>&1 || true
virsh dumpxml "$name" | grep -q "device='cdrom'" && { echo "cdrom still attached"; exit 1; }
virsh start "$name" >/dev/null
echo "INSTALLED and started $name (stick + ISO detached)"
```

- [ ] **Step 2: Lab site files.** `lab/iso5/hosts`:

```
# iso5 lab test site (ISO Plan 5a: install from nothing, from the ISO).
52:54:00:c4:05:50  iso5-srv   192.168.100.50  server
52:54:00:c4:05:51  iso5-cli1  192.168.100.51  client
52:54:00:c4:05:52  iso5-cli2  192.168.100.52  client
```

  `lab/iso5/site.conf.in`: copy `lab/iso4/site.conf.in` with `DOMAIN=iso5.lab.test` (all other lines identical).

- [ ] **Step 3: `lab/iso5/prove.sh` from the Plan 4 proof.** Copy, then make these exact changes:

```bash
cp lab/iso4/prove.sh lab/iso5/prove.sh
sed -i '' -e 's/iso4/iso5/g' -e 's/c4:04:4/c4:05:5/g' -e 's/192\.168\.100\.4\([0-2]\)/192.168.100.5\1/g' \
  -e 's/^export CHP_REPO=.*/export CHP_REPO=0.6.0; ISO=\/var\/lib\/libvirt\/images\/chp-iso\/0.1.0-rc1\/cyberhygiene-lab-installer-el9.iso/' \
  lab/iso5/prove.sh
```

  Then, by hand:
  - Header comment: "ISO Plan 5a proof: install from nothing **from the ISO** (gate 1)"; list the stages below.
  - `prep`: keep everything (the embedded-pyz kickstarts are still pushed: `negrepo` uses them). Two helpers stay in
    `lab/iso4/` (not copied): change `"$here/rsx.sh" "$here/ssh-ki.exp"` to `"$top/lab/iso4/rsx.sh" "$top/lab/iso4/ssh-ki.exp"`.
    Also `scp "$here/install-iso.sh" aero:/tmp/iso2/`. Check: `grep -n '\$here/' lab/iso5/prove.sh` lists only
    `site.conf.in`, `hosts` and `install-iso.sh`.
  - `server`: replace the `install.sh` line with
    `out=$(A "sudo bash /tmp/iso2/install-iso.sh $SRV 52:54:00:c4:05:50 2 $STICK 1 $ISO")` (entry 2 = server, serial)
    and check `[[ $out == *"BOOTED: inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/server.ks"* && $out == *"INSTALLED and started $SRV"* ]]`
    with the PASS text `"$SRV: installed from the ISO (menu entry chosen, nothing typed)"`.
  - `client1|client2`: the same replacement with entry `3`, the client's MAC and `client.ks` in the check.
  - Delete the `ops` stage (superseded by `ga` since Plan 4b; the header says so).
  - New stage `negrepo` (row 37 negative, before `server`), using the lab path, which honours `chp.repo=`:

```bash
  negrepo)
    A 'sudo rm -rf /data/lab-inputs/chp/0.6.0-tampered && sudo cp -a /data/lab-inputs/chp/0.6.0 /data/lab-inputs/chp/0.6.0-tampered && echo "<!-- tampered -->" | sudo tee -a /data/lab-inputs/chp/0.6.0-tampered/repodata/repomd.xml >/dev/null'
    out=$(A "sudo CHP_REPO=0.6.0-tampered bash /tmp/iso2/install.sh iso5-neg 52:54:00:c4:05:50 server $STICK 1 --expect-stop")
    [[ $out == *"STOPPED: chp-site: the install repository's signature is NOT valid"* ]] && pass "row 37: tampered repo refused in %pre" || fail "row 37 stop" "$out"
    [[ $out == *"disk 1 zero-check-failures=0"* ]] && pass "row 37: disk untouched" || fail "row 37 disk" "$out"
    check "row 37: no escrow written for the refused install" "$(A "sudo bash /tmp/iso2/stick.sh has $STICK escrow/iso5-srv.txt && echo yes || echo no")" "no"
    A 'sudo rm -rf /data/lab-inputs/chp/0.6.0-tampered' ;;
```

  - `cleanup`: also remove `iso5-neg` if present.
  - Final summary line: `echo "stage $1: $( ((fails)) && echo FAIL || echo ALL PASS )"`, exit `$fails` (as in iso4).

- [ ] **Step 4: Widen the guard in `lab/iso2/install.sh`**: `[[ $name == iso[2345]-* ]]` and the message
  `only iso2-*…iso5-* lab VMs`.

- [ ] **Step 5: Check aero has room and memory** (stop and ask the user if not):
  `ssh aero 'df -h /data /var | tail -2; free -g | sed -n 2p'` → `/data` ≥ 35 GB free (3 thin disks), `/var` ≥ 20 GB,
  available memory ≥ 13 GB (3 × 4 GB VMs). The old lab VMs `srv1`, `client1`, `client2` stay as they are (5b needs them for
  comparison); ask the user before shutting any down.

- [ ] **Step 6: Run the proof, stage by stage** (each prints PASS/FAIL; stop at the first FAIL and debug):

```bash
bash -c 'cd ~/idm-assistant && for s in prep negrepo server firstboot reboot export client1 client2 ga negtrust; do
  echo "=== $s"; bash lab/iso5/prove.sh $s || break; done' 2>&1 | tee ~/idm-lab-secrets/iso5-proof-run1.log
```

  Expected: every stage `ALL PASS`. The `server` stage line shows `BOOTED: inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/server.ks`.
  The TPM lines in `reboot` and `client1|client2` prove rows 15/17 under Secure Boot **from the ISO's boot chain**
  (spec §9 "mkksiso preserves Secure Boot": here xorriso replay). The OEMDRV stick is a USB VM disk (spec §9 second
  verification, VM half).

  **Known exception to record, not to hide:** the first boot after each install asks once for the escrowed LUKS
  passphrase (Plan 3a design: the TPM is bound on that first boot). `unlock.sh` types it over the serial console. Gate 1
  says "no console typing beyond choosing the boot entry", so the record states this exception for the ISSO's review.

- [ ] **Step 7: Secrets scan the log** before anything leaves `~/idm-lab-secrets`:
  `grep -nE 'LUKS_PASSPHRASE=[^<]|ROOT_CONSOLE_PASSWORD=[^<]|BEGIN (OPENSSH|EC) PRIVATE' ~/idm-lab-secrets/iso5-proof-run1.log`
  → no output.

- [ ] **Step 8: Write `lab/iso5/PROOF-RECORD.md`** in the iso4 record's format: date, ISO 0.1.0-rc1 + repo 0.6.0, the VM
  table, every stage's PASS lines (copied from the log), what each stage proves (rows 1, 15–17, 31, 35–43; row 37 negative;
  spec §9 verifications), the first-boot passphrase exception above, and "not proven here": real hardware, a real USB
  stick, the regression (5b).

- [ ] **Step 9: Mark row 37 proven** in `lab/iso-requirements.md` (append to its evidence cell:
  `ISO Plan 5a: chp-site verify-repo in %pre; tampered repo stopped before disks (lab/iso5/PROOF-RECORD.md)`) and add an
  "ISO Plan 5a (date) proved …" paragraph under the table like the 4a/4b ones.

- [ ] **Step 10: Commit**

```bash
git add lab/iso5 lab/iso2/install.sh lab/iso-requirements.md
git commit -m "ISO Plan 5a Task 6: install from nothing from the ISO (server + 2 clients, Secure Boot, TPM); row 37 negative

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: CUI scan and deviation table (gate 3)

**Files:**
- Modify: `lab/iso5/prove.sh` (new `scan` stage)
- Create: `lab/iso5/deviations.py`, `lab/iso5/decisions.tsv`, `lab/iso5/DEVIATIONS.md`,
  `lab/iso5/scan-results/` (the three XCCDF results files; they hold no secrets, checked in Step 4)
- Test: `tests/test_deviations.py`

**Interfaces:**
- `deviations.py RESULTS.xml… --decisions decisions.tsv` → Markdown on stdout; exit 0 only when every failing rule has a
  decision `accept` (a `fix` decision means "not yet fixed": the gate is not met).
- `decisions.tsv` columns: `rule_id<TAB>decision(accept|fix)<TAB>decided_by<TAB>reason`; `#` lines are comments.

- [ ] **Step 1: Failing tests** `tests/test_deviations.py`

```python
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "lab" / "iso5" / "deviations.py"
NS = "http://checklists.nist.gov/xccdf/1.2"


def results(tmp_path, host, rows):
    rr = "".join(f'<rule-result idref="{r}" severity="{s}"><result>{res}</result></rule-result>' for r, s, res in rows)
    rules = "".join(f'<Rule id="{r}"><title>Title of {r}</title></Rule>' for r, _, _ in rows)
    p = tmp_path / f"{host}.xml"
    p.write_text(f'<Benchmark xmlns="{NS}">{rules}<TestResult><target>{host}</target>{rr}</TestResult></Benchmark>')
    return p


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)


def test_every_failure_decided_accept_passes(tmp_path):
    a = results(tmp_path, "srv", [("r1", "high", "fail"), ("r2", "low", "pass")])
    b = results(tmp_path, "cli", [("r1", "high", "fail")])
    d = tmp_path / "d.tsv"; d.write_text("# c\nr1\taccept\tD. Shannon (ISSO)\tGUI is required on both roles\n")
    r = run(a, b, "--decisions", d)
    assert r.returncode == 0, r.stderr
    assert "| r1 | high | cli, srv | accept | D. Shannon (ISSO) | GUI is required on both roles |" in r.stdout
    assert "Title of r1" in r.stdout and "r2" not in r.stdout.split("## Failures")[1]


def test_undecided_or_fix_fails_the_gate(tmp_path):
    a = results(tmp_path, "srv", [("r1", "medium", "fail"), ("r3", "low", "fail")])
    d = tmp_path / "d.tsv"; d.write_text("r1\tfix\tD. Shannon (ISSO)\tchange the RPM\n")
    r = run(a, "--decisions", d)
    assert r.returncode == 1
    assert "UNDECIDED: r3" in r.stdout and "NOT YET FIXED: r1" in r.stdout


def test_error_and_notchecked_are_listed_separately(tmp_path):
    a = results(tmp_path, "srv", [("r4", "low", "error"), ("r5", "low", "notchecked")])
    d = tmp_path / "d.tsv"; d.write_text("")
    r = run(a, "--decisions", d)
    assert "## Not evaluated" in r.stdout and "r4 (error)" in r.stdout and "r5 (notchecked)" in r.stdout


def test_bad_decision_word_is_refused(tmp_path):
    a = results(tmp_path, "srv", [("r1", "low", "fail")])
    d = tmp_path / "d.tsv"; d.write_text("r1\tmaybe\tx\ty\n")
    assert run(a, "--decisions", d).returncode == 2
```

- [ ] **Step 2: Run**: `.venv/bin/python -m pytest -q tests/test_deviations.py` → FAIL.

- [ ] **Step 3: Write `lab/iso5/deviations.py`**

```python
"""Gate 3: the CUI scan's failures as a deviation table, each with the ISSO's decision. Exit 0 only if every failing
rule is decided 'accept'; 'fix' = not yet fixed (gate not met); undecided = gate not met; bad input = exit 2."""
import argparse
import sys
import xml.etree.ElementTree as ET

NS = {"x": "http://checklists.nist.gov/xccdf/1.2"}


def load(path):
    root = ET.parse(path).getroot()
    titles = {r.get("id"): (r.findtext("x:title", default="", namespaces=NS) or "").strip()
              for r in root.iter(f"{{{NS['x']}}}Rule")}
    tr = root.find(".//x:TestResult", NS)
    host = (tr.findtext("x:target", default=path, namespaces=NS) or path).strip()
    rows = [(rr.get("idref"), rr.get("severity", "unknown"), rr.findtext("x:result", namespaces=NS))
            for rr in tr.findall("x:rule-result", NS)]
    return host, titles, rows


def decisions(path):
    out = {}
    for n, line in enumerate(open(path), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) != 4 or f[1] not in ("accept", "fix"):
            sys.exit(f"decisions line {n}: want rule<TAB>accept|fix<TAB>who<TAB>reason")
        out[f[0]] = f[1:]
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("results", nargs="+"); ap.add_argument("--decisions", required=True)
    a = ap.parse_args()
    try:
        dec = decisions(a.decisions)
    except SystemExit as e:
        print(e, file=sys.stderr); return 2
    fails, other, titles, hosts = {}, [], {}, []
    for p in a.results:
        host, t, rows = load(p); titles.update(t); hosts.append(host)
        for rid, sev, res in rows:
            if res == "fail":
                fails.setdefault(rid, [sev, set()])[1].add(host)
            elif res in ("error", "unknown", "notchecked"):
                other.append(f"{host}: {rid} ({res})")
    out = [f"# CUI scan deviations ({', '.join(sorted(hosts))})", "", "## Failures", "",
           "| rule | severity | hosts | decision | decided by | reason | title |", "|---|---|---|---|---|---|---|"]
    problems = []
    for rid in sorted(fails):
        sev, hs = fails[rid]; d = dec.get(rid)
        if d is None:
            problems.append(f"UNDECIDED: {rid}"); d = ["UNDECIDED", "", ""]
        elif d[0] == "fix":
            problems.append(f"NOT YET FIXED: {rid}")
        out.append(f"| {rid} | {sev} | {', '.join(sorted(hs))} | {d[0]} | {d[1]} | {d[2]} | {titles.get(rid, '')} |")
    out += ["", "## Not evaluated", ""] + [f"- {o}" for o in other] + [""]
    out += [f"**Gate 3: {'MET' if not problems else 'NOT MET'}** ({len(fails)} failing rules)"] + problems
    print("\n".join(out))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Add a `scan` stage to `lab/iso5/prove.sh`** and run it on the **pristine** hosts (before any 5b lab
  adapter). OpenSCAP runs as root; the results file is handed to `chpadmin` and fetched over SSH (megabytes: not through
  the root-console helper).

```bash
  scan)
    out=$here/scan-results; mkdir -p "$out"
    DS=/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml; PROF=xccdf_net.cyberinabox_profile_cui_dc2
    tb=$(base64 < "$top/lab/kickstart/dc2-reference/dc2-cui-tailoring.xml" | tr -d '\n')
    for v in "$SRV $SIP" "$C1 $C1IP" "$C2 $C2IP"; do
      set -- $v
      rc=$(Rh "$1" "$2" "install -d -m 0700 /root/chp-scan && echo $tb | base64 -d > /root/chp-scan/tailoring.xml && oscap xccdf eval --tailoring-file /root/chp-scan/tailoring.xml --profile $PROF --results /root/chp-scan/$1.xml $DS >/dev/null 2>&1; echo oscap-rc=\$?; install -m 0644 -o chpadmin /root/chp-scan/$1.xml /home/chpadmin/$1.xml")
      check "$1: oscap evaluated (rc 2 = some rules fail)" "$rc" "oscap-rc=2"
      Vh "$2" "cat ~/$1.xml && rm -f ~/$1.xml" > "$out/$1.xml"
      echo "$1: $(grep -c '<result>fail</result>' "$out/$1.xml") failing, $(grep -c '<result>pass</result>' "$out/$1.xml") passing"
    done
    check "scan results hold no secrets" "$(grep -lE 'LUKS_PASSPHRASE|ROOT_CONSOLE_PASSWORD|PRIVATE KEY' "$out"/*.xml | wc -l | tr -d ' ')" "0" ;;
```

  Run: `bash lab/iso5/prove.sh scan` → `ALL PASS` and three files in `lab/iso5/scan-results/`.

- [ ] **Step 5: ISSO decision round (the user decides; one rule at a time).** Generate the table with an empty
  decisions file: `.venv/bin/python lab/iso5/deviations.py lab/iso5/scan-results/*.xml --decisions lab/iso5/decisions.tsv`.
  For each failing rule, present the decision form (Problem / Cause / Action / Downside / Choice), recommending
  `accept` (with the design decision that explains it, e.g. GUI on both roles, ISSO #12 POA&M, row 43) or `fix`.
  Record each answer as a line in `decisions.tsv` with `decided_by` = `D. Shannon (ISSO)`.
  **If any rule is decided `fix`:** make the change in the owning RPM or the kickstart (with its own test), bump that
  package, sign a new repo (Task 5 Step 2 with the next version), build the next ISO (`0.1.0-rc2`), and re-run Task 6
  Step 6 and this task's Step 4 on fresh installs. Repeat until the table has only `accept`.

- [ ] **Step 6: Write `lab/iso5/DEVIATIONS.md`**: the generator's output (exit 0 = **Gate 3: MET**), plus a header
  naming the ISO version, the scan date, the profile (`cui` + dc2 tailoring, which unselects
  `sysctl_user_max_user_namespaces`) and the scanner/content versions (`oscap --version | head -1`,
  `rpm -q scap-security-guide` on a host).

- [ ] **Step 7: Run all tests and commit**

```bash
.venv/bin/python -m pytest -q tests
git add lab/iso5 tests/test_deviations.py
git commit -m "ISO Plan 5a Task 7: CUI scan of the three installed hosts; deviation table, every failure ISSO-decided (gate 3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Finish

- [ ] **Step 1: Final review** (whole branch, most capable model): spec §1 gates 1 and 3, §5.1, §8 items 1–4, §9,
  row 37, and this plan's Review Focus. Fix Important findings; list minors in the PR body.
- [ ] **Step 2:** If any fix touched an RPM, kickstart or boot file: new repo/ISO and a fresh proof run (Task 6 Step 6,
  Task 7 Step 4) so the records match what is shipped.
- [ ] **Step 3:** `git push -u origin iso-plan5a` and open a PR to `main` titled
  `ISO Plan 5a: build the ISO, install from nothing, CUI deviations`, body: what is proven (gates 1 and 3), the first-boot
  passphrase exception, the ISO size (~15 GB: the full DVD is kept; slimming is a later option), what 5b does next, minors.
  End with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- [ ] **Step 4:** Leave the three iso5 VMs running and **take no snapshot yet**: Plan 5b starts from them (lab adapter →
  golden snapshots → regression). Do not copy anything to For Jeff in this plan (the release is 5b, after gate 2).
