# Security Bundle Plan Y1: YARA Malware Scanning (0.3.0-update1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add YARA malware scanning (Wazuh file events plus a weekly full scan, alert only) to the security add-on, and release it to existing 0.3.0 sites as `0.3.0-update1` (repo 0.8.0).

**Architecture:** Wazuh real-time file monitoring on a few risky folders triggers one scan-only active response, `chp-yara-scan`, a thin wrapper around a new `chp-site yara-scan` command. That command checks the path, runs YARA with a compiled signature-base rule set from a new `chp-yara-rules` package, and writes JSON lines that Wazuh decodes into alerts (match = level 12, so `ALERT_HOOK`). A systemd timer runs the same command weekly over every local file system. `chp-site security enable` installs and configures it all, and re-running it on an enabled host adds YARA (the update path).

**Tech Stack:** Python 3.9 stdlib (chp-site zipapp), bash (monitor checks, build scripts), YARA 4.x from EPEL 9, Neo23x0 signature-base, Wazuh 4.14.9, RPM, the iso5 KVM lab on aero.

**Spec:** `docs/superpowers/specs/2026-11-01-security-bundle-yara-design.md` (frame: `docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md`).

## Global Constraints

- On a match: **alert only**. Nothing is moved, deleted or quarantined.
- Rules: **Neo23x0 signature-base only**, pinned to one upstream commit; licence Detection Rule License 1.1, shipped with attribution.
- The appliance never downloads rules. Rule updates are monthly signed updates of `chp-yara-rules` only.
- Real-time folders: `/home`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/srv`, `/data`. Wazuh's data folder is never watched or scanned.
- Every other active response stays off.
- Match alert level **12**, scan error level **7**, weekly summary level **3**.
- The monitor alerts when the weekly scan has not completed in **8 days**.
- `SECURITY_ADDONS=no` changes nothing.
- SELinux enforcing, fapolicyd trusts only signed packages, FIPS mode on, no new network access.
- chp-site stays Python 3.9 stdlib-only.
- Versions: chp-site **0.10.0**, chp-security **0.2.0**, chp-yara-rules **<signature-base commit date as YYYY.MM.DD>**, repo **0.8.0**; `chp-identity-server` **0.1.2-2** (PR #38) rides along.
- The owner says "go" before every YubiKey signing; restart gpg-agent first (`gpgconf --kill gpg-agent`).
- The owner merges PRs. Pre-publication scan before every push (public repo).

## Review Focus

1. **A file path with spaces, quotes, newlines or non-ASCII characters** arriving from Wazuh must be scanned as that exact path, with no shell involved (Task 3 test `test_odd_file_names_are_passed_as_one_argument`).
2. **A symlink inside a watched folder pointing outside it** (e.g. `/tmp/x -> /etc/shadow`) must be refused, not scanned (Task 3 test `test_symlink_out_of_the_watched_folders_is_refused`).
3. **A file deleted before the scan runs** (very common in `/tmp`) must produce no alert at all, not an error alert (Task 3 test `test_file_gone_before_the_scan_is_silent`).
4. **A FIFO, device or socket in `/dev/shm` or `/tmp`** must be refused without opening it (opening a FIFO blocks) (Task 3 test `test_fifo_is_refused_without_opening_it`).
5. **YARA or its rules missing** (package half-removed) must give one error line, not a crash or a retry loop (Task 3 test `test_missing_rules_gives_one_error_line`).

---

## File Structure

| File | Responsibility |
|---|---|
| `lab/security/SPIKE-YARA.md` (create) | Task 1 findings: YARA under FIPS, rule compile count, scan time, false alarms, the pinned commit |
| `lab/inputs/fetch-epel.sh` (modify) | also fetch the `yara` RPM and its EPEL-only dependencies |
| `lab/inputs/fetch-signature-base.sh` (create) | fetch signature-base at the pinned commit, check its sha256 |
| `appliance/rpm/chp-yara-rules/build-rules.py` (create) | compile signature-base into `rules.yarc`, write `SKIPPED.txt` |
| `appliance/rpm/chp-yara-rules/exclude.txt` (create) | rule files excluded for false alarms, with reasons |
| `appliance/rpm/chp-yara-rules/chp-yara-rules.spec`, `build-rpm.sh`, `NOTICE` (create) | the rules package |
| `appliance/chp-site/chp_site/yara_scan.py` (create) | path checks, single-file scan, full scan, JSON log lines |
| `appliance/chp-site/chp_site/wazuh.py` (modify) | syscheck on watched folders, the YARA log, the active response, the YARA rules XML |
| `appliance/chp-site/chp_site/security.py` (modify) | install and configure the YARA pieces in `enable` |
| `appliance/chp-site/chp_site/cli.py` (modify) | `chp-site yara-scan` |
| `appliance/rpm/chp-security/chp-yara-scan` (create) | the Wazuh active-response wrapper |
| `appliance/rpm/chp-security/chp-yara-fullscan.service`, `.timer` (create) | the weekly scan |
| `appliance/rpm/chp-security/monitor.d/73-yara-scan.sh` (create) | alert if the weekly scan is overdue |
| `appliance/release/PACKAGES.txt`, `UPDATE-0.3.0-update1.md.in`, `RELEASE-RECORD-0.8.0.md`, `RULES-UPDATE.md` (modify/create) | repo contents, update notes, release record, the monthly procedure |
| `appliance/site-stick-kit/SITE-STICK.md` (modify) | a "From 0.3.0 update 1 on" section |
| `lab/iso5/prove.sh` (modify) | stages `yara-on`, `yaracatch`, `yarafull` |
| `lab/security/PROOF-RECORD-Y1.md` (create) | the proofs |

---

### Task 1: Spike: YARA under FIPS, rule compile count, scan time

No product code. It produces the facts later tasks use, and the pinned commit.

**Files:**
- Modify: `lab/inputs/fetch-epel.sh` (the `PKGS` array)
- Create: `lab/inputs/fetch-signature-base.sh`
- Create: `lab/security/SPIKE-YARA.md`

**Interfaces:**
- Produces: `SIG_COMMIT`, `SIG_SHA256` (constants in `fetch-signature-base.sh`); the YARA version-release (`YARA_EVR`) used by Task 2; the measured `MAX_BYTES`, `TIMEOUT` and the initial `exclude.txt` lines used by Tasks 2 and 3.

- [ ] **Step 1: Find the EPEL 9 yara package and its EPEL-only dependencies.** On the Mac:

```bash
curl -fsSL https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/Packages/y/ | grep -o 'yara-[0-9][^"]*x86_64.rpm' | sort -u
```

Expected: one or more `yara-4.x.y-z.el9.x86_64.rpm` names (and possibly `yara-libs`). Add each to `PKGS` in `lab/inputs/fetch-epel.sh`, e.g. `PKGS=(g/google-authenticator-1.09-5.el9.x86_64.rpm y/yara-4.5.2-1.el9.x86_64.rpm y/yara-libs-4.5.2-1.el9.x86_64.rpm)` (use the names the listing shows). Run `bash lab/inputs/fetch-epel.sh`, copy the RPMs to aero's `/data/lab-inputs/rpms`, and run `lab/inputs/verify-epel.sh` there. Expected: `OK signed by EPEL 9` for each, and a requirements list. Any requirement not on the Rocky DVD (check with `dnf --disablerepo='*' --enablerepo=dvd* provides <req>` on aero) is fetched the same way.

- [ ] **Step 2: Write `lab/inputs/fetch-signature-base.sh`**

```bash
#!/usr/bin/env bash
# Fetch Neo23x0 signature-base at the pinned commit (YARA spec §2) and check its sha256. Mac only (needs internet).
set -Eeuo pipefail
IN="${IDM_INPUTS:-$HOME/idm-lab-inputs}"
SIG_COMMIT=<40-hex commit, chosen in Step 3>
SIG_SHA256=<sha256 of the tarball, recorded in Step 3>
out="$IN/signature-base-$SIG_COMMIT.tar.gz"
[[ -s $out ]] || curl -fsSL "https://github.com/Neo23x0/signature-base/archive/$SIG_COMMIT.tar.gz" -o "$out"
got=$(shasum -a 256 "$out" | cut -d' ' -f1)
[[ $got == "$SIG_SHA256" ]] || { echo "signature-base sha256 $got is not the pinned $SIG_SHA256"; exit 1; }
echo "OK signature-base $SIG_COMMIT"
```

- [ ] **Step 3: Pin the commit.** Use the latest commit on signature-base's default branch:

```bash
git ls-remote https://github.com/Neo23x0/signature-base HEAD
```

Put that hash in `SIG_COMMIT`, run the script once with `SIG_SHA256=x` to download, take the printed `got` value as `SIG_SHA256`, and run it again. Expected: `OK signature-base <commit>`. Copy the tarball to aero `/data/lab-inputs/`.

- [ ] **Step 4: Install YARA on the iso5 client and check FIPS.** On aero, revert `iso5-cli2` to `golden` (`bash lab/iso5/reset.sh`), copy the YARA RPMs to it and install them with `dnf install -y ./yara*.rpm`. Then, on iso5-cli2:

```bash
cat /proc/sys/crypto/fips_enabled                 # expect 1
yara --version
printf 'rule t { strings: $a = "X5O!P%%@AP" condition: $a }\n' > /tmp/t.yar
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' > /tmp/eicar.txt
yara /tmp/t.yar /tmp/eicar.txt                    # expect: t /tmp/eicar.txt
printf 'import "hash"\nrule h { condition: hash.sha256(0, filesize) != "" }\n' > /tmp/h.yar
yara /tmp/h.yar /tmp/eicar.txt                    # does the hash module work under FIPS?
ldd "$(command -v yara)" | grep -i -E 'ssl|crypto'
journalctl -b | grep -c 'fapolicyd.*deny'; ausearch -m AVC -ts recent 2>/dev/null | grep -c yara
yara --help | grep -E 'scan-list|timeout|define'
```

Record every result in `SPIKE-YARA.md`. Expected: FIPS 1; the EICAR rule matches; the crypto library is the system OpenSSL (inside the FIPS boundary) or none; 0 fapolicyd denials; 0 AVCs; `--scan-list`, `--timeout` and `--define` exist. If the hash module fails under FIPS, record it (Task 2 then skips rules that `import "hash"` and use MD5/SHA-1).

- [ ] **Step 5: Measure the rule compile count.** On aero (the build host; it is a disposable lab machine, so install the YARA RPMs there too, and record that in `lab/aero-deviations.md`):

```bash
mkdir -p /tmp/sb && tar -xzf /data/lab-inputs/signature-base-*.tar.gz -C /tmp/sb --strip-components=1
cd /tmp/sb/yara; ok=0; bad=0
for f in *.yar; do if yarac -w -d filename= -d filepath= -d extension= -d filetype= -d owner= "$f" /tmp/x.yarc 2>/tmp/err; then ok=$((ok+1)); else bad=$((bad+1)); echo "$f: $(tail -1 /tmp/err)"; fi; done > /tmp/compile.txt
echo "ok=$ok bad=$bad"; cut -d: -f2- /tmp/compile.txt | sed 's/"[^"]*"/"…"/g' | sort | uniq -c | sort -rn | head
```

Record `ok`, `bad` and the failure reasons.

- [ ] **Step 6: Measure a full scan and false alarms.** Compile the passing files into one `rules.yarc` (as Task 2's `build-rules.py` will) and copy it to iso5-srv and iso5-cli2 (install YARA on iso5-srv as in Step 4). On each host:

```bash
find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/ossec -o -path /srv/wazuh -o -path /data/wazuh -o -path /var/lib/chp/repo \) -prune -o -type f -size -256M -print > /tmp/list
wc -l /tmp/list; time nice -n 19 ionice -c3 yara -w -C /tmp/rules.yarc --timeout=60 --scan-list /tmp/list > /tmp/hits 2>/tmp/errs
wc -l /tmp/hits /tmp/errs; cut -d' ' -f1 /tmp/hits | sort | uniq -c | sort -rn | head -20
```

Record the file count, wall time, hits (each one is a false alarm on a clean appliance) and errors. For each hit, find the rule's file (`grep -l "rule <name>" /tmp/sb/yara/*.yar`): those files become the first lines of `exclude.txt` in Task 2, with the hit as the reason. Set `MAX_BYTES` (default 256 MiB) and `TIMEOUT` (default 60 s) from what you see; record both.

- [ ] **Step 7: Check that Wazuh can run a root-owned script.** On iso5-cli2, the active-response script will be owned `root:root 0750` by the `chp-security` RPM (Task 5). Wazuh's `wazuh-execd` runs as root, so check:

```bash
ps -o user= -C wazuh-execd                        # expect root
```

Record it.

- [ ] **Step 8: Revert the lab and commit.** Run `bash lab/iso5/reset.sh` (the hosts return to golden). Then:

```bash
git add lab/inputs/fetch-epel.sh lab/inputs/fetch-signature-base.sh lab/security/SPIKE-YARA.md lab/aero-deviations.md
git commit -m "Y1 spike: YARA under FIPS, signature-base compile count, full-scan time"
```

**Stop rule:** if YARA cannot run under FIPS (Step 4), stop the plan and report to the owner. Every later task depends on it.

---

### Task 2: The `chp-yara-rules` package

**Files:**
- Create: `appliance/rpm/chp-yara-rules/build-rules.py`
- Create: `appliance/rpm/chp-yara-rules/exclude.txt`
- Create: `appliance/rpm/chp-yara-rules/NOTICE`
- Create: `appliance/rpm/chp-yara-rules/chp-yara-rules.spec`
- Create: `appliance/rpm/chp-yara-rules/build-rpm.sh`
- Modify: `appliance/release/PACKAGES.txt`
- Test: `tests/test_chp_yara_rules.py`

**Interfaces:**
- Consumes: Task 1's `SIG_COMMIT`, `YARA_EVR`, and the measured false-alarm files.
- Produces: `/usr/share/chp-yara-rules/rules.yarc` (compiled with externals `filename`, `filepath`, `extension`, `filetype`, `owner`, all defaulting to the empty string), `/usr/share/chp-yara-rules/SKIPPED.txt` (`<file>\t<reason>` lines), `/usr/share/chp-yara-rules/COMMIT` (the 40-hex commit). The package `Requires: yara = <YARA_EVR>`, because a compiled rules file only loads in the YARA version that compiled it.

- [ ] **Step 1: Write the failing tests**

```python
import importlib.util
from pathlib import Path
from types import SimpleNamespace

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-yara-rules"
spec = importlib.util.spec_from_file_location("build_rules", D / "build-rules.py")
br = importlib.util.module_from_spec(spec); spec.loader.exec_module(br)


def fake_yarac(bad=(), dup=None):
    """A stand-in for yarac: files named in bad fail alone; dup = a file whose rules clash in the combined compile."""
    def run(argv, **kw):
        srcs = [a for a in argv[1:-1] if a.endswith(".yar")]
        out = Path(argv[-1])
        for s in srcs:
            if Path(s).name in bad:
                return SimpleNamespace(returncode=1, stdout="", stderr=f'{s}(3): error: undefined identifier "x"\n')
        if dup and len(srcs) > 1 and any(Path(s).name == dup for s in srcs):
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr=f'{Path(srcs[0]).parent}/{dup}(9): error: duplicated identifier "r"\n')
        out.write_bytes(b"compiled")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def tree(tmp_path, names):
    src = tmp_path / "src"; src.mkdir()
    for n in names:
        (src / n).write_text("rule r_%s { condition: true }\n" % n.replace(".", "_"))
    out = tmp_path / "out"; out.mkdir()
    return src, out


def test_excluded_and_uncompilable_files_are_skipped_with_reasons(tmp_path):
    src, out = tree(tmp_path, ["a.yar", "b.yar", "c.yar"])
    kept, skipped = br.build(src, {"b.yar": "matched /usr/lib64/libfoo.so on a clean server"}, out,
                             run=fake_yarac(bad={"c.yar"}))
    assert (kept, skipped) == (1, 2)
    s = (out / "SKIPPED.txt").read_text()
    assert "b.yar\tfalse alarm on the appliance: matched /usr/lib64/libfoo.so on a clean server" in s
    assert "c.yar\tdoes not compile with plain YARA: " in s
    assert (out / "rules.yarc").read_bytes() == b"compiled"


def test_a_clash_in_the_combined_compile_drops_that_file_and_retries(tmp_path):
    src, out = tree(tmp_path, ["a.yar", "b.yar", "c.yar"])
    kept, skipped = br.build(src, {}, out, run=fake_yarac(dup="b.yar"))
    assert (kept, skipped) == (2, 1)
    assert "b.yar\tclashes with another rule file: " in (out / "SKIPPED.txt").read_text()


def test_externals_are_defined_empty_at_compile_time(tmp_path):
    src, out = tree(tmp_path, ["a.yar"])
    seen = []
    def run(argv, **kw):
        seen.append(argv); Path(argv[-1]).write_bytes(b"c")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    br.build(src, {}, out, run=run)
    for name in ("filename", "filepath", "extension", "filetype", "owner"):
        assert f"--define={name}=" in seen[-1]


def test_exclude_file_format():
    ex = br.load_excludes("# comment\nfoo.yar matched a clean file  # note\n\nbar.yar\n")
    assert ex == {"foo.yar": "matched a clean file", "bar.yar": "excluded"}


def test_spec_pins_yara_and_ships_licence_and_notice():
    s = (D / "chp-yara-rules.spec").read_text()
    assert "Requires:       yara = %{yara_evr}" in s
    for f in ("rules.yarc", "SKIPPED.txt", "COMMIT", "LICENSE", "NOTICE"):
        assert f in s, f
    n = (D / "NOTICE").read_text()
    assert "Neo23x0/signature-base" in n and "Detection Rule License" in n


def test_packages_list_has_the_new_packages():
    p = (Path(__file__).resolve().parents[1] / "appliance" / "release" / "PACKAGES.txt").read_text().splitlines()
    assert "chp-yara-rules ours" in p and "yara epel" in p
```

- [ ] **Step 2: Run them.** Run: `.venv/bin/python -m pytest -q tests/test_chp_yara_rules.py`. Expected: FAIL (`build-rules.py` not found).

- [ ] **Step 3: Write `build-rules.py`**

```python
#!/usr/bin/env python3
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Compile signature-base into one rules file for chp-yara-rules (YARA spec §2). Runs on the build host, which has
yarac. Usage: build-rules.py SRC_DIR EXCLUDE_TXT OUT_DIR. Every file left out is listed in OUT_DIR/SKIPPED.txt."""
import re
import subprocess
import sys
from pathlib import Path

EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")
DEFINES = [f"--define={n}=" for n in EXTERNALS]


def load_excludes(text):
    out = {}
    for ln in text.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if ln:
            name, _, why = ln.partition(" ")
            out[name] = why.strip() or "excluded"
    return out


def _yarac(run, srcs, dest):
    return run(["yarac", "-w", *DEFINES, *map(str, srcs), str(dest)], capture_output=True, text=True)


def build(src, excludes, out, run=subprocess.run):
    src, out = Path(src), Path(out)
    kept, skipped = [], []
    for f in sorted(src.glob("*.yar")):
        if f.name in excludes:
            skipped.append((f.name, "false alarm on the appliance: " + excludes[f.name]))
            continue
        r = _yarac(run, [f], out / "probe.yarc")
        if r.returncode != 0:
            why = (r.stderr.strip().splitlines() or ["no message"])[-1]
            skipped.append((f.name, "does not compile with plain YARA: " + why))
            continue
        kept.append(f)
    (out / "probe.yarc").unlink(missing_ok=True)
    while True:
        r = _yarac(run, kept, out / "rules.yarc")
        if r.returncode == 0:
            break
        m = re.search(r"([^\s/]+\.yar)\(\d+\)", r.stderr)
        bad = next((f for f in kept if m and f.name == m.group(1)), None)
        if bad is None:
            raise SystemExit("combined compile failed: " + r.stderr[-500:])
        kept.remove(bad)
        skipped.append((bad.name, "clashes with another rule file: " + r.stderr.strip().splitlines()[-1]))
    (out / "SKIPPED.txt").write_text("".join(f"{n}\t{w}\n" for n, w in sorted(skipped)))
    return len(kept), len(skipped)


if __name__ == "__main__":
    s, e, o = sys.argv[1:4]
    k, n = build(s, load_excludes(Path(e).read_text()), o)
    print(f"compiled {k} rule files, skipped {n} (see SKIPPED.txt)")
```

Correct the clash fake in the test if the real yarac error format seen in Task 1 differs; the parser takes the first `<name>.yar(<line>)` in the message.

- [ ] **Step 4: Write `exclude.txt`, `NOTICE`, the spec and `build-rpm.sh`.**

`exclude.txt`: one line per file Task 1 Step 6 found, e.g. `gen_suspicious_strings.yar matched /usr/lib64/<file> on a clean iso5-srv (2026-11-0x)`, under the header comment `# <file.yar> <reason>: rule files left out for false alarms on a clean appliance (YARA spec §2)`.

`NOTICE`:

```
chp-yara-rules contains YARA rules from Neo23x0/signature-base (https://github.com/Neo23x0/signature-base),
by Florian Roth and contributors, compiled unmodified, at the commit named in COMMIT. The rules are licensed under
the Detection Rule License (DRL) 1.1 (LICENSE). Rule files left out are listed in SKIPPED.txt with the reason.
Packaged by the CyberHygiene Project.
```

`chp-yara-rules.spec`:

```
Name:           chp-yara-rules
Version:        %{rules_version}
Release:        1.chp%{?dist}
Summary:        CyberHygiene Project YARA rules (Neo23x0 signature-base, compiled)
License:        DRL-1.1
BuildArch:      noarch
Source0:        rules.yarc
Source1:        SKIPPED.txt
Source2:        COMMIT
Source3:        LICENSE
Source4:        NOTICE
Requires:       yara = %{yara_evr}

%description
signature-base YARA rules compiled once at build time for the CHP security add-on (YARA spec §2). Alert only.

%install
install -d %{buildroot}%{_datadir}/chp-yara-rules
for f in %{SOURCE0} %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4}; do install -m0644 "$f" %{buildroot}%{_datadir}/chp-yara-rules/; done

%files
%dir %{_datadir}/chp-yara-rules
%{_datadir}/chp-yara-rules/rules.yarc
%{_datadir}/chp-yara-rules/SKIPPED.txt
%{_datadir}/chp-yara-rules/COMMIT
%{_datadir}/chp-yara-rules/LICENSE
%{_datadir}/chp-yara-rules/NOTICE

%changelog
* Sun Nov 01 2026 The CyberHygiene Project - %{rules_version}-1.chp
- First release: signature-base at the commit in COMMIT.
```

`build-rpm.sh` (runs on the Mac, builds on aero, like `appliance/rpm/chp-security/build-rpm.sh`; copy that script's ssh and rpmbuild pattern):

```bash
#!/usr/bin/env bash
# Build chp-yara-rules on aero: unpack the pinned signature-base, compile it with build-rules.py, package the result.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
SIG_COMMIT=$(sed -n 's/^SIG_COMMIT=//p' "$here/../../../lab/inputs/fetch-signature-base.sh")
scp -q "$here/build-rules.py" "$here/exclude.txt" "$here/NOTICE" "$here/chp-yara-rules.spec" aero:/tmp/
ssh aero bash -s "$SIG_COMMIT" <<'EOF'
set -Eeuo pipefail
C=$1; W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
tar -xzf "/data/lab-inputs/signature-base-$C.tar.gz" -C "$W" --strip-components=1
mkdir -p ~/rpmbuild/SOURCES ~/rpmbuild/SPECS; S=~/rpmbuild/SOURCES
python3 /tmp/build-rules.py "$W/yara" /tmp/exclude.txt "$S"
cp "$W/LICENSE" "$S/LICENSE"; cp /tmp/NOTICE "$S/"; echo "$C" > "$S/COMMIT"
V=$(cd "$W" && git log -1 --format=%cd --date=format:%Y.%m.%d 2>/dev/null || date -u +%Y.%m.%d)
E=$(rpm -q --qf '%{VERSION}-%{RELEASE}' yara)
rpmbuild -bb --define "rules_version $V" --define "yara_evr $E" /tmp/chp-yara-rules.spec
cp ~/rpmbuild/RPMS/noarch/chp-yara-rules-"$V"-1.chp*.noarch.rpm /data/chp-release/built/
EOF
```

The GitHub tarball has no git history, so `git log` fails and the date falls back to today. Replace that line with the commit date recorded in `SPIKE-YARA.md` (`V=<YYYY.MM.DD>` from Task 1 Step 3) if you want the upstream date. Record which you used as a ledger ruling.

`PACKAGES.txt`: add `yara epel` (and `yara-libs epel` if Task 1 found it), and `chp-yara-rules ours`.

- [ ] **Step 5: Run the tests.** Run: `.venv/bin/python -m pytest -q tests/test_chp_yara_rules.py`. Expected: PASS (6). Then the whole suite: `.venv/bin/python -m pytest -q`. Expected: all pass.

- [ ] **Step 6: Build it.** Run: `bash appliance/rpm/chp-yara-rules/build-rpm.sh`. Expected: `compiled <N> rule files, skipped <M>`, with N and M matching Task 1's counts minus the exclusions, and the RPM in `/data/chp-release/built/`.

- [ ] **Step 7: Commit**

```bash
git add appliance/rpm/chp-yara-rules appliance/release/PACKAGES.txt tests/test_chp_yara_rules.py
git commit -m "chp-yara-rules: signature-base compiled at build time, skip list, licence and notice"
```

---

### Task 3: `chp-site yara-scan`

**Files:**
- Create: `appliance/chp-site/chp_site/yara_scan.py`
- Modify: `appliance/chp-site/chp_site/cli.py` (a `yara-scan` sub-command)
- Test: `tests/test_chp_site_yara_scan.py`

**Interfaces:**
- Consumes: `/usr/share/chp-yara-rules/rules.yarc` (Task 2).
- Produces:
  - `yara_scan.check_path(path, watched=WATCHED, never=NEVER, max_bytes=MAX_BYTES) -> (str | None, str | None)`: the real path, or `None` and a reason (`"gone"`, `"outside the watched folders"`, `"not a regular file"`, `"larger than the scan limit"`);
  - `yara_scan.scan_file(path, *, run, log, state_dir, now) -> dict | None`: the event written (`{"event": "match"|"error"|"skipped", ...}`), or `None` for nothing written;
  - `yara_scan.full_scan(*, run, log, state_dir, now, walk_root="/", mounts_text=None) -> dict`: the summary event;
  - `yara_scan.from_wazuh(stdin_text) -> str | None`: the file path from a Wazuh active-response message;
  - log lines: one JSON object per line, `{"chp_yara": {...}}`, in `LOG = "/var/log/chp-yara.json"`;
  - `STATE = "/var/lib/chp/yara"`, holding `recent.json` (rate limit) and `last-full` (epoch seconds of the last completed full scan);
  - CLI: `chp-site yara-scan --wazuh` (reads the active-response JSON on stdin), `chp-site yara-scan --full`, `chp-site yara-scan PATH`.

- [ ] **Step 1: Write the failing tests**

```python
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_site import yara_scan as y


def yara(stdout="", rc=0, stderr="", seen=None):
    def run(argv, **kw):
        if seen is not None:
            seen.append(argv)
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)
    return run


def setup(tmp_path):
    w = tmp_path / "home"; w.mkdir()
    log = tmp_path / "chp-yara.json"; st = tmp_path / "state"
    return w, log, st


def lines(log):
    return [json.loads(ln)["chp_yara"] for ln in log.read_text().splitlines()] if log.exists() else []


def scan(p, w, log, st, run, now=1000.0):
    return y.scan_file(str(p), run=run, log=log, state_dir=st, now=lambda: now, watched=(str(w),), never=())


def test_match_writes_one_line_with_rules_file_and_sha256(tmp_path):
    w, log, st = setup(tmp_path); f = w / "evil.bin"; f.write_bytes(b"x")
    ev = scan(f, w, log, st, yara(stdout=f"Rule_A {f}\nRule_B {f}\n"))
    assert ev["event"] == "match" and ev["rules"] == "Rule_A,Rule_B" and ev["file"] == str(f)
    assert ev["sha256"] == "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    assert lines(log) == [ev]


def test_clean_file_writes_nothing(tmp_path):
    w, log, st = setup(tmp_path); f = w / "ok.txt"; f.write_text("hi")
    assert scan(f, w, log, st, yara()) is None and lines(log) == []


def test_file_gone_before_the_scan_is_silent(tmp_path):                       # Review Focus 3
    w, log, st = setup(tmp_path)
    assert scan(w / "vanished", w, log, st, yara()) is None and lines(log) == []


def test_symlink_out_of_the_watched_folders_is_refused(tmp_path):              # Review Focus 2
    w, log, st = setup(tmp_path); out = tmp_path / "secret"; out.write_text("s")
    (w / "link").symlink_to(out)
    seen = []
    ev = scan(w / "link", w, log, st, yara(seen=seen))
    assert ev["event"] == "skipped" and ev["detail"] == "outside the watched folders" and seen == []


def test_fifo_is_refused_without_opening_it(tmp_path):                         # Review Focus 4
    w, log, st = setup(tmp_path); p = w / "pipe"; os.mkfifo(p)
    ev = scan(p, w, log, st, yara())                                          # would block if it opened the FIFO
    assert ev["event"] == "skipped" and ev["detail"] == "not a regular file"


def test_odd_file_names_are_passed_as_one_argument(tmp_path):                  # Review Focus 1
    w, log, st = setup(tmp_path); f = w / "a b'\"\n$(x)é.txt"; f.write_text("x")
    seen = []
    scan(f, w, log, st, yara(seen=seen))
    assert seen[0][-1] == str(f) and isinstance(seen[0], list)


def test_missing_rules_gives_one_error_line(tmp_path):                        # Review Focus 5
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    ev = scan(f, w, log, st, yara(rc=1, stderr="error: could not open file: /usr/share/chp-yara-rules/rules.yarc\n"))
    assert ev["event"] == "error" and "rules.yarc" in ev["detail"] and len(lines(log)) == 1


def test_yara_missing_gives_one_error_line(tmp_path):
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    def run(argv, **kw):
        raise FileNotFoundError("yara")
    ev = scan(f, w, log, st, run)
    assert ev["event"] == "error" and "yara is not installed" in ev["detail"]


def test_repeat_within_a_minute_is_scanned_once(tmp_path):
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    seen = []
    scan(f, w, log, st, yara(seen=seen), now=1000.0)
    scan(f, w, log, st, yara(seen=seen), now=1030.0)
    scan(f, w, log, st, yara(seen=seen), now=1061.0)
    assert len(seen) == 2


def test_wazuh_data_folder_is_never_scanned(tmp_path):
    w, log, st = setup(tmp_path); d = w / "wazuh"; d.mkdir(); f = d / "alerts.json"; f.write_text("{}")
    ev = y.scan_file(str(f), run=yara(), log=log, state_dir=st, now=lambda: 1.0, watched=(str(w),), never=(str(d),))
    assert ev["event"] == "skipped"


def test_scan_passes_per_file_externals(tmp_path):
    w, log, st = setup(tmp_path); f = w / "doc.pdf"; f.write_text("x")
    seen = []
    scan(f, w, log, st, yara(seen=seen))
    a = seen[0]
    assert "--define=filename=doc.pdf" in a and f"--define=filepath={w}" in a and "--define=extension=.pdf" in a
    assert "-C" in a and y.RULES in a and f"--timeout={y.TIMEOUT}" in a


def test_from_wazuh_reads_the_syscheck_path():
    msg = {"version": 1, "command": "add",
           "parameters": {"alert": {"syscheck": {"path": "/home/u/a b.exe", "event": "added"}}}}
    assert y.from_wazuh(json.dumps(msg)) == "/home/u/a b.exe"
    assert y.from_wazuh(json.dumps(dict(msg, command="delete"))) is None
    assert y.from_wazuh("not json") is None


def test_full_scan_skips_system_folders_and_writes_summary_and_last_full(tmp_path):
    root = tmp_path / "r"
    for d in ("home/u", "proc", "var/ossec/logs", "etc"):
        (root / d).mkdir(parents=True)
    (root / "home/u/bad").write_text("x"); (root / "etc/ok").write_text("y")
    (root / "proc/x").write_text("p"); (root / "var/ossec/logs/a").write_text("w")
    log = tmp_path / "log"; st = tmp_path / "st"
    listed = {}
    def run(argv, **kw):
        listed["files"] = Path(argv[argv.index("--scan-list") + 1]).read_text().splitlines()
        return SimpleNamespace(returncode=0, stdout=f"Rule_X {root}/home/u/bad\n", stderr="")
    s = y.full_scan(run=run, log=log, state_dir=st, now=lambda: 5000.0, walk_root=str(root),
                    skip=(str(root / "proc"), str(root / "var/ossec")), mounts_text="")
    assert sorted(listed["files"]) == [f"{root}/etc/ok", f"{root}/home/u/bad"]
    evs = lines(log)
    assert evs[0]["event"] == "match" and evs[0]["file"] == f"{root}/home/u/bad"
    assert evs[-1] == s and s["event"] == "summary" and s["files"] == 2 and s["matches"] == 1 and s["errors"] == 0
    assert (st / "last-full").read_text().strip() == "5000"


def test_full_scan_skips_network_mounts(tmp_path):
    root = tmp_path / "r"; (root / "mnt/nfs").mkdir(parents=True); (root / "mnt/nfs/f").write_text("x")
    log = tmp_path / "log"; st = tmp_path / "st"
    listed = {}
    def run(argv, **kw):
        listed["files"] = Path(argv[argv.index("--scan-list") + 1]).read_text().splitlines()
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    y.full_scan(run=run, log=log, state_dir=st, now=lambda: 1.0, walk_root=str(root), skip=(),
                mounts_text=f"srv:/x {root}/mnt/nfs nfs4 rw 0 0\n")
    assert listed["files"] == []


def test_log_lines_are_not_world_readable(tmp_path):
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    scan(f, w, log, st, yara(stdout=f"R {f}\n"))
    assert oct(log.stat().st_mode & 0o777) == "0o640"
```

- [ ] **Step 2: Run them.** Run: `.venv/bin/python -m pytest -q tests/test_chp_site_yara_scan.py`. Expected: FAIL (`cannot import name 'yara_scan'`).

- [ ] **Step 3: Write `yara_scan.py`**

```python
"""YARA malware scanning (YARA spec §4). Scan only: it never changes, moves or deletes a file. Wazuh starts a
single-file scan for a file added or changed in a watched folder; a weekly timer starts a full scan. Every result
worth recording is one JSON line in LOG, which Wazuh reads (match = level 12 -> ALERT_HOOK)."""
import hashlib
import json
import os
import stat
import time
from pathlib import Path

RULES = "/usr/share/chp-yara-rules/rules.yarc"
LOG = "/var/log/chp-yara.json"
STATE = "/var/lib/chp/yara"
WATCHED = ("/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/srv", "/data")
NEVER = ("/var/ossec", "/srv/wazuh", "/data/wazuh", "/root/chp-onboard", "/root/chp-escrow-pending",
         "/var/lib/chp/repo")
FULL_SKIP = ("/proc", "/sys", "/dev", "/run") + NEVER
REMOTE_FS = ("nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "9p")
MAX_BYTES = 256 * 1024 * 1024        # Task 1 measures; files above it are not scanned
TIMEOUT = 60                         # seconds per file
RATE_S = 60                          # the same file again within this many seconds: not scanned again


def _under(p, roots):
    return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)


def check_path(path, watched=WATCHED, never=NEVER, max_bytes=MAX_BYTES):
    real = os.path.realpath(path)                         # a symlink cannot reach outside the watched folders
    try:
        st = os.lstat(real)
    except OSError:
        return None, "gone"
    if not _under(real, watched) or _under(real, never):
        return None, "outside the watched folders"
    if not stat.S_ISREG(st.st_mode):
        return None, "not a regular file"                 # never opened: a FIFO would block
    if st.st_size > max_bytes:
        return None, "larger than the scan limit"
    return real, None


def _write(log, ev):
    log = Path(log)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps({"chp_yara": ev}, sort_keys=True) + "\n")
    return ev


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _yara(run, args):
    try:
        return run(["yara", "-w", "-C", RULES, f"--timeout={TIMEOUT}", *args], capture_output=True, text=True)
    except FileNotFoundError:
        return None


def _recent(state_dir, path, t):
    p = Path(state_dir) / "recent.json"
    Path(state_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        seen = json.loads(p.read_text())
    except (OSError, ValueError):
        seen = {}
    seen = {k: v for k, v in seen.items() if t - v < RATE_S}
    hit = path in seen
    if not hit:
        seen[path] = t
    p.write_text(json.dumps(seen))
    return hit


def scan_file(path, *, run, log=LOG, state_dir=STATE, now=time.time, watched=WATCHED, never=NEVER):
    real, why = check_path(path, watched, never)
    if real is None:
        return None if why == "gone" else _write(log, {"event": "skipped", "file": path, "detail": why})
    if _recent(state_dir, real, now()):
        return None
    name = os.path.basename(real)
    ext = os.path.splitext(name)[1]
    r = _yara(run, [f"--define=filename={name}", f"--define=filepath={os.path.dirname(real)}",
                    f"--define=extension={ext}", real])
    if r is None:
        return _write(log, {"event": "error", "file": real, "detail": "yara is not installed"})
    if r.returncode != 0:
        return _write(log, {"event": "error", "file": real,
                            "detail": (r.stderr.strip().splitlines() or ["yara failed"])[-1]})
    rules = sorted({ln.split(" ", 1)[0] for ln in r.stdout.splitlines() if ln.strip()})
    if not rules:
        return None
    return _write(log, {"event": "match", "file": real, "rules": ",".join(rules), "sha256": _sha256(real)})


def _remote_mounts(text):
    out = []
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 3 and (f[2] in REMOTE_FS or f[2].startswith("fuse.")):
            out.append(f[1].replace("\\040", " "))
    return out


def full_scan(*, run, log=LOG, state_dir=STATE, now=time.time, walk_root="/", skip=FULL_SKIP, mounts_text=None,
              max_bytes=MAX_BYTES):
    t0 = now()
    if mounts_text is None:
        mounts_text = Path("/proc/mounts").read_text()
    skip = tuple(skip) + tuple(_remote_mounts(mounts_text))
    files = []
    for d, dirs, names in os.walk(walk_root):
        dirs[:] = [x for x in dirs if not _under(os.path.join(d, x), skip)]
        for n in names:
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_size <= max_bytes:
                files.append(p)
    sd = Path(state_dir); sd.mkdir(parents=True, exist_ok=True, mode=0o700)
    lst = sd / "scan-list"
    lst.write_text("".join(p + "\n" for p in files))
    r = _yara(run, ["--scan-list", str(lst)])
    matches = errors = 0
    if r is None:
        _write(log, {"event": "error", "file": "", "detail": "yara is not installed"}); errors = 1
    else:
        hits = {}
        for ln in r.stdout.splitlines():
            rule, _, p = ln.partition(" ")
            if p:
                hits.setdefault(p, set()).add(rule)
        for p, rules in sorted(hits.items()):
            try:
                h = _sha256(p)
            except OSError:
                h = ""
            _write(log, {"event": "match", "file": p, "rules": ",".join(sorted(rules)), "sha256": h}); matches += 1
        for ln in r.stderr.splitlines()[:20]:
            if "error" in ln.lower():
                _write(log, {"event": "error", "file": "", "detail": ln.strip()}); errors += 1
    lst.unlink(missing_ok=True)
    s = {"event": "summary", "files": len(files), "matches": matches, "errors": errors, "seconds": int(now() - t0)}
    _write(log, s)
    (sd / "last-full").write_text(f"{int(now())}\n")
    return s


def from_wazuh(text):
    try:
        msg = json.loads(text)
    except ValueError:
        return None
    if msg.get("command") != "add":
        return None
    return ((msg.get("parameters") or {}).get("alert") or {}).get("syscheck", {}).get("path")
```

- [ ] **Step 4: Wire the CLI.** In `cli.py`, add a handler and a parser line next to `wazuh-forward`:

```python
def _yara_scan(a):
    import subprocess
    from . import yara_scan as ys
    if a.full:
        s = ys.full_scan(run=subprocess.run)
        print(f"full scan: {s['files']} files, {s['matches']} matches, {s['errors']} errors, {s['seconds']} s")
        return 0
    path = ys.from_wazuh(sys.stdin.read()) if a.wazuh else a.path
    if path:
        ys.scan_file(path, run=subprocess.run)
    return 0
```

```python
    ys_ = sub.add_parser("yara-scan", help="(security add-on) YARA scan of one file, a Wazuh event (--wazuh), or "
                                           "every local file system (--full); alert only, never moves a file")
    ys_.add_argument("path", nargs="?"); ys_.add_argument("--wazuh", action="store_true"); ys_.add_argument("--full", action="store_true")
```

and add `"yara-scan": _yara_scan` to the dispatch dictionary. Add a CLI test to `tests/test_chp_site_yara_scan.py`:

```python
def test_cli_wazuh_mode_reads_stdin(monkeypatch, tmp_path):
    from chp_site import cli
    got = {}
    monkeypatch.setattr(y, "scan_file", lambda p, run: got.setdefault("p", p))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(
        {"command": "add", "parameters": {"alert": {"syscheck": {"path": "/tmp/z"}}}})))
    assert cli.main(["yara-scan", "--wazuh"]) == 0 and got["p"] == "/tmp/z"
```

- [ ] **Step 5: Run the tests.** Run: `.venv/bin/python -m pytest -q tests/test_chp_site_yara_scan.py`, then `.venv/bin/python -m pytest -q`. Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add appliance/chp-site/chp_site/yara_scan.py appliance/chp-site/chp_site/cli.py tests/test_chp_site_yara_scan.py
git commit -m "chp-site yara-scan: path checks, single-file and full scans, JSON log lines (alert only)"
```

---

### Task 4: Wazuh settings for YARA

**Files:**
- Modify: `appliance/chp-site/chp_site/wazuh.py`
- Test: `tests/test_chp_site_wazuh.py`

**Interfaces:**
- Consumes: `yara_scan.WATCHED`, `yara_scan.NEVER`, `yara_scan.LOG` (Task 3).
- Produces: `harden_manager(text)` and `harden_agent(text, server_ip)` also configure:
  - `<syscheck>`: `disabled=no`, `frequency=43200`, `scan_on_start=no`, every old `<directories>` removed, one `<directories realtime="yes" check_all="yes">` with the watched folders joined by commas, and one `<ignore>` per `NEVER` path;
  - `<localfile><log_format>json</log_format><location>/var/log/chp-yara.json</location></localfile>` (once);
  - manager only: `<command><name>chp-yara-scan</name><executable>chp-yara-scan</executable><timeout_allowed>no</timeout_allowed></command>` and `<active-response><command>chp-yara-scan</command><location>local</location><rules_id>550,554</rules_id></active-response>`, after every other active-response block is removed;
  - agent: `active-response/disabled = no`.
- Produces: `YARA_RULES` (the XML text written to `/var/ossec/etc/rules/chp_yara_rules.xml` on the server by Task 5).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_chp_site_wazuh.py`)

```python
from chp_site import yara_scan as ys


def _blocks(text):
    return w.parse_conf(text)


def _check_syscheck(out):
    b = _blocks(out)
    assert w.setting(b, "syscheck/disabled") == "no" and w.setting(b, "syscheck/scan_on_start") == "no"
    dirs = [e for x in b for e in x.findall("syscheck/directories")]
    assert len(dirs) == 1 and dirs[0].get("realtime") == "yes"
    assert dirs[0].text.split(",") == list(ys.WATCHED)
    assert set(ys.NEVER) <= {e.text for x in b for e in x.findall("syscheck/ignore")}


def test_manager_syscheck_watches_only_the_risky_folders_in_real_time():
    _check_syscheck(w.harden_manager(MGR))
    _check_syscheck(w.harden_manager(w.harden_manager(MGR)))                  # idempotent: still one <directories>


def test_agent_syscheck_watches_only_the_risky_folders_in_real_time():
    _check_syscheck(w.harden_agent(AGT, "192.0.2.10"))


def test_both_roles_read_the_yara_log_once():
    for out in (w.harden_manager(MGR), w.harden_agent(AGT, "192.0.2.10"),
                w.harden_manager(w.harden_manager(MGR))):                     # idempotent
        locs = [e.findtext("location") for x in _blocks(out) for e in x.findall("localfile")
                if e.findtext("location") == ys.LOG]
        assert len(locs) == 1


def test_manager_has_only_the_scan_only_active_response():
    b = _blocks(w.harden_manager(w.harden_manager(MGR)))
    ars = [e for x in b for e in x.findall("active-response")]
    assert len(ars) == 1
    assert ars[0].findtext("command") == "chp-yara-scan" and ars[0].findtext("location") == "local"
    assert ars[0].findtext("rules_id") == "550,554"
    cmds = [e for x in b for e in x.findall("command") if e.findtext("name") == "chp-yara-scan"]
    assert len(cmds) == 1 and cmds[0].findtext("executable") == "chp-yara-scan"


def test_agent_allows_active_response():
    assert w.setting(_blocks(w.harden_agent(AGT, "192.0.2.10")), "active-response/disabled") == "no"


def test_yara_rules_levels():
    r = w.YARA_RULES
    assert 'level="12"' in r and "^match$" in r and 'level="7"' in r and "^error$" in r
    assert "<decoded_as>json</decoded_as>" in r
```

Also change the existing `test_manager_settings` parameter `("syscheck/disabled", "yes")` to `("syscheck/disabled", "no")`, and any agent test that expects `active-response/disabled` = `yes` to expect `no` (YARA spec §3 replaces those two W1 settings; ledger it as a ruling).

- [ ] **Step 2: Run them.** Run: `.venv/bin/python -m pytest -q tests/test_chp_site_wazuh.py`. Expected: FAIL (syscheck still disabled; no `YARA_RULES`).

- [ ] **Step 3: Implement in `wazuh.py`.** Change `("syscheck", "disabled", "yes")` to `("syscheck", "disabled", "no")` in `_MANAGER` and `_AGENT`, and `("active-response", "disabled", "yes")` to `("active-response", "disabled", "no")` in `_AGENT`. Then add:

```python
from . import yara_scan as _ys

YARA_RULES = """<!-- Managed by chp-security (YARA spec §5): YARA scan results from /var/log/chp-yara.json -->
<group name="chp,yara,">
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="chp_yara.event">\\.+</field>
    <description>CHP YARA: $(chp_yara.event)</description>
  </rule>
  <rule id="100501" level="12">
    <if_sid>100500</if_sid>
    <field name="chp_yara.event">^match$</field>
    <description>YARA match: $(chp_yara.rules) in $(chp_yara.file)</description>
    <group>malware,</group>
  </rule>
  <rule id="100502" level="7">
    <if_sid>100500</if_sid>
    <field name="chp_yara.event">^error$</field>
    <description>YARA scan error: $(chp_yara.detail)</description>
  </rule>
</group>
"""


def _syscheck(blocks):
    sc = _first(blocks, "syscheck")
    for tag in ("directories", "ignore"):
        for e in list(sc.findall(tag)):
            sc.remove(e)
    for child, value in (("frequency", "43200"), ("scan_on_start", "no")):
        c = sc.find(child) if sc.find(child) is not None else ET.SubElement(sc, child)
        c.text = value
    d = ET.SubElement(sc, "directories", {"realtime": "yes", "check_all": "yes"})
    d.text = ",".join(_ys.WATCHED)
    for p in _ys.NEVER:
        ET.SubElement(sc, "ignore").text = p


def _yara_log(blocks):
    for b in blocks:
        for e in b.findall("localfile"):
            if e.findtext("location") == _ys.LOG:
                return
    lf = ET.SubElement(blocks[0], "localfile")
    ET.SubElement(lf, "log_format").text = "json"
    ET.SubElement(lf, "location").text = _ys.LOG


def _yara_response(blocks):
    for b in blocks:
        for e in list(b.findall("command")):
            if e.findtext("name") == "chp-yara-scan":
                b.remove(e)
    c = ET.SubElement(blocks[0], "command")
    for k, v in (("name", "chp-yara-scan"), ("executable", "chp-yara-scan"), ("timeout_allowed", "no")):
        ET.SubElement(c, k).text = v
    ar = ET.SubElement(blocks[0], "active-response")
    for k, v in (("command", "chp-yara-scan"), ("location", "local"), ("rules_id", "550,554")):
        ET.SubElement(ar, k).text = v
```

In `harden_manager`, after the loop that removes every `active-response` block and after `_wodles_off(blocks)`, call `_syscheck(blocks); _yara_log(blocks); _yara_response(blocks)`. In `harden_agent`, after `_wodles_off(blocks)`, call `_syscheck(blocks); _yara_log(blocks)`.

- [ ] **Step 4: Run the tests.** Run: `.venv/bin/python -m pytest -q tests/test_chp_site_wazuh.py`, then the whole suite. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add appliance/chp-site/chp_site/wazuh.py tests/test_chp_site_wazuh.py
git commit -m "Wazuh settings for YARA: syscheck on the risky folders only, the YARA log, one scan-only active response"
```

---

### Task 5: `chp-security` 0.2.0 and `security enable`

**Files:**
- Create: `appliance/rpm/chp-security/chp-yara-scan`
- Create: `appliance/rpm/chp-security/chp-yara-fullscan.service`, `chp-yara-fullscan.timer`
- Create: `appliance/rpm/chp-security/monitor.d/73-yara-scan.sh`
- Modify: `appliance/rpm/chp-security/chp-security.spec`, `build-rpm.sh`
- Modify: `appliance/chp-site/chp_site/security.py`, `appliance/chp-site/chp-site.spec` (0.10.0)
- Test: `tests/test_chp_security_static.py`, `tests/test_chp_security_monitor.py`, `tests/test_chp_site_security.py`

**Interfaces:**
- Consumes: `wazuh.YARA_RULES` (Task 4), `chp-site yara-scan` (Task 3), `chp-yara-rules` (Task 2).
- Produces: `security.enable` installs `yara chp-yara-rules` with the Wazuh package and `chp-security`; on the server writes `/var/ossec/etc/rules/chp_yara_rules.xml` (0640, group wazuh); adds `chp-yara-fullscan.timer` to the units it enables, on both roles. Re-running `enable` on an enabled host adds these without making new agent keys.

- [ ] **Step 1: Write the failing tests**

In `tests/test_chp_security_static.py`:

```python
def test_yara_pieces_are_packaged():
    assert "Version:        0.2.0" in SPEC
    assert "Requires:       chp-site >= 0.10.0, chp-base, yara, chp-yara-rules" in SPEC
    for f in ("chp-yara-scan", "chp-yara-fullscan.service", "chp-yara-fullscan.timer", "73-yara-scan.sh"):
        assert f in SPEC, f
    assert "%attr(0750,root,root) /var/ossec/active-response/bin/chp-yara-scan" in SPEC


def test_active_response_wrapper_only_calls_the_scan():
    t = (D / "chp-yara-scan").read_text()
    assert t.startswith("#!/bin/sh") and "exec /usr/bin/chp-site yara-scan --wazuh" in t


def test_weekly_scan_runs_at_low_priority():
    s = (D / "chp-yara-fullscan.service").read_text(); t = (D / "chp-yara-fullscan.timer").read_text()
    assert "ExecStart=/usr/bin/chp-site yara-scan --full" in s
    assert "Nice=19" in s and "IOSchedulingClass=idle" in s
    assert "OnCalendar=Sun *-*-* 03:30:00" in t and "Persistent=true" in t
```

In `tests/test_chp_security_monitor.py` (reuse its `run` helper; the check reads `CHP_YARA_STATE` and `CHP_SECURITY_CONF`):

```python
def run_yara(tmp_path, last_full=None, conf_age_days=0, now=1_000_000_000):
    st = tmp_path / "yara"; st.mkdir(exist_ok=True)
    if last_full is not None:
        (st / "last-full").write_text(f"{last_full}\n")
    c = tmp_path / "security.conf"; c.write_text("ROLE=client\n")
    os.utime(c, (now - conf_age_days * 86400,) * 2)
    env = dict(os.environ, CHP_SECURITY_CONF=str(c), CHP_YARA_STATE=str(st), CHP_NOW=str(now))
    r = subprocess.run(["bash", str(M / "73-yara-scan.sh")], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_yara_recent_full_scan_is_ok(tmp_path):
    assert run_yara(tmp_path, last_full=1_000_000_000 - 3 * 86400).startswith("OK")


def test_yara_full_scan_overdue_alerts(tmp_path):
    assert "ALERT" in run_yara(tmp_path, last_full=1_000_000_000 - 9 * 86400)


def test_yara_never_scanned_is_ok_in_the_first_week_then_alerts(tmp_path):
    assert run_yara(tmp_path, conf_age_days=2).startswith("OK")
    assert "ALERT" in run_yara(tmp_path, conf_age_days=9)


def test_yara_not_enabled_is_silent_ok(tmp_path):
    env = dict(os.environ, CHP_SECURITY_CONF=str(tmp_path / "none"))
    out = subprocess.run(["bash", str(M / "73-yara-scan.sh")], env=env, capture_output=True, text=True).stdout
    assert out.startswith("OK")
```

In `tests/test_chp_site_security.py` (it already has the `Run`, `hosts`, `root` and `enable` helpers used below):

```python
def test_enable_installs_yara_and_starts_the_weekly_scan(tmp_path):
    r, s, run, done = enable(tmp_path, "server")
    assert ["dnf", "--enablerepo=chp", "install", "-y", "wazuh-manager", "chp-security", "yara",
            "chp-yara-rules"] in run.calls
    en = [c for c in run.calls if c[:3] == ["systemctl", "enable", "--now"]][0]
    assert "chp-yara-fullscan.timer" in en
    rules = r / "var/ossec/etc/rules/chp_yara_rules.xml"
    assert rules.read_text() == w.YARA_RULES and oct(rules.stat().st_mode & 0o777) == "0o640"


def test_client_enable_starts_the_weekly_scan_but_writes_no_rules(tmp_path):
    s = tmp_path / "stick"; (s / "wazuh").mkdir(parents=True)
    (s / "wazuh/ws1.key").write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    r, _, run, _ = enable(tmp_path, "client", stick=s)
    en = [c for c in run.calls if c[:3] == ["systemctl", "enable", "--now"]][0]
    assert en[3:] == ["wazuh-agent", "chp-yara-fullscan.timer"]
    assert not (r / "var/ossec/etc/rules/chp_yara_rules.xml").exists()


def test_enable_rerun_on_an_enabled_server_keeps_keys_and_adds_yara(tmp_path):
    r, s, _, _ = enable(tmp_path, "server")
    (r / "var/ossec/etc/rules/chp_yara_rules.xml").unlink()                  # as on a host enabled before update1
    keys1 = (r / "var/ossec/etc/client.keys").read_text()
    r, s, run2, _ = enable(tmp_path, "server", run=Run(rules=w.rich_rules(hosts())[0] + "\n"), stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == keys1
    assert (r / "var/ossec/etc/rules/chp_yara_rules.xml").read_text() == w.YARA_RULES
```

The existing `test_server_enable_writes_hardened_config_keys_and_firewall` asserts the old `dnf install` list; change it to the new list (ledger it as a ruling: YARA spec §2 adds the two packages).

- [ ] **Step 2: Run them.** Run: `.venv/bin/python -m pytest -q tests/test_chp_security_static.py tests/test_chp_security_monitor.py tests/test_chp_site_security.py`. Expected: FAIL on the new tests.

- [ ] **Step 3: Write the package files.**

`chp-yara-scan` (the Wazuh active-response wrapper; RPM-owned, so fapolicyd trusts it):

```sh
#!/bin/sh
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# Wazuh active response (YARA spec §3): scan the one file in the event. Scan only; never moves or deletes anything.
exec /usr/bin/chp-site yara-scan --wazuh
```

`chp-yara-fullscan.service`:

```ini
[Unit]
Description=CHP weekly YARA scan of every local file system (alert only)
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/chp-site yara-scan --full
Nice=19
IOSchedulingClass=idle
```

`chp-yara-fullscan.timer`:

```ini
[Unit]
Description=CHP weekly YARA scan

[Timer]
OnCalendar=Sun *-*-* 03:30:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

`monitor.d/73-yara-scan.sh`:

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 73-yara-scan (YARA spec §5): the weekly full scan has completed within the last 8 days.
C=${CHP_SECURITY_CONF:-/etc/chp/security.conf}; S=${CHP_YARA_STATE:-/var/lib/chp/yara}; now=${CHP_NOW:-$(date +%s)}
[ -f "$C" ] || { echo "OK security add-on not enabled on this host"; exit 0; }
limit=$((8 * 86400))
if [ -f "$S/last-full" ]; then
  last=$(tr -dc '0-9' < "$S/last-full")
  if [ -n "$last" ] && [ $((now - last)) -le $limit ]; then echo "OK weekly YARA scan completed $(( (now - last) / 86400 )) days ago"
  else echo "ALERT the weekly YARA scan has not completed in 8 days (systemctl status chp-yara-fullscan)"; fi
else
  since=$(stat -c %Y "$C")
  if [ $((now - since)) -le $limit ]; then echo "OK first weekly YARA scan not due yet"
  else echo "ALERT the weekly YARA scan has never completed (systemctl status chp-yara-fullscan)"; fi
fi
exit 0
```

In `chp-security.spec`: `Version: 0.2.0`, `Requires: chp-site >= 0.10.0, chp-base, yara, chp-yara-rules`, new `Source10..13` for the four files, install lines (`install -Dm0750 %{SOURCE10} %{buildroot}/var/ossec/active-response/bin/chp-yara-scan`, the two units under `%{_unitdir}`, the monitor check beside the others), `%files` entries (`%attr(0750,root,root) /var/ossec/active-response/bin/chp-yara-scan`, the units, `73-yara-scan.sh`), and a changelog entry. Add the four files to `build-rpm.sh`'s copy list.

- [ ] **Step 4: Change `security._enable`.** Install YARA with the rest:

```python
    run(["dnf", "--enablerepo=chp", "install", "-y", pkg, "chp-security", "yara", "chp-yara-rules"], check=True)
    done.append(f"{pkg}, YARA and its rules installed")
```

In the server branch, after `api.yaml` is written:

```python
        _p(root, f"{OSSEC}/etc/rules").mkdir(parents=True, exist_ok=True)
        _write(_p(root, f"{OSSEC}/etc/rules/chp_yara_rules.xml"), w.YARA_RULES, 0o640, group_wazuh)
```

and set `units = ["wazuh-manager", "chp-wazuh-alerts", "chp-wazuh-retention.timer", "chp-yara-fullscan.timer"]` (server) and `units = ["wazuh-agent", "chp-yara-fullscan.timer"]` (client). Bump `chp-site.spec` to `Version: 0.10.0`, `Release: 1.chp%{?dist}` with a changelog entry, and `__version__` if `chp_site/__init__.py` carries one.

- [ ] **Step 5: Run the tests.** Run: `.venv/bin/python -m pytest -q`. Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add appliance/rpm/chp-security appliance/chp-site tests
git commit -m "chp-security 0.2.0 + chp-site 0.10.0: YARA active-response wrapper, weekly scan, monitor check; enable installs YARA"
```

---

### Task 6: Build, sign repo 0.8.0, prove on the lab

**Files:**
- Modify: `lab/iso5/prove.sh` (stages `yara-on`, `yaracatch`, `yarafull`)
- Create: `lab/security/PROOF-RECORD-Y1.md`

**Interfaces:**
- Consumes: everything above; PR #38's `chp-identity-server` 0.1.2-2 (merge #38 first, or merge `origin/update-0.3.0-1` into this branch and ledger it).
- Produces: signed repo 0.8.0 at `aero:/data/chp-release/0.8.0/repo`; the lab proofs.

- [ ] **Step 1: Build the packages and assemble repo 0.8.0.** Run the existing build scripts for chp-site, chp-security, chp-identity-server and chp-yara-rules (as in the W2 rebuilds: `bash appliance/chp-site/build.sh; bash appliance/chp-site/build-rpm.sh; bash appliance/rpm/chp-security/build-rpm.sh; bash appliance/rpm/chp-identity-server/build-rpm.sh; bash appliance/rpm/chp-yara-rules/build-rpm.sh`), copy the YARA RPMs into `/data/lab-inputs/rpms`, push the tools (`bash appliance/release/push.sh`), then on aero: `bash /data/chp-release/tools/assemble-repo.sh /data/chp-release/0.8.0/stage /data/chp-release/built /data/lab-inputs/rpms`. Expected: the stage lists `chp-site-0.10.0`, `chp-security-0.2.0`, `chp-identity-server-0.1.2-2`, `chp-yara-rules`, `yara` (EPEL).

- [ ] **Step 2: Sign it (owner "go").** Restart gpg-agent, ask the owner for "go", cue "click inside the PIN box, type the PIN, touch the key", then:

```bash
export SSH_CONFIG=lab/iso5/ssh_config; bash appliance/release/sign-session.sh 'bash /data/chp-release/tools/sign-repo.sh /data/chp-release/0.8.0/stage /data/chp-release/0.8.0/repo 2DE0D71BF37D8F5E4201A590521276F43C908F8E /data/chp-release/tools'
```

Expected: `REPO OK: <N> packages, all signed by pinned keys`.

- [ ] **Step 3: Add the prove.sh stages.** `yara-on` upgrades each iso5 host from repo 0.8.0 (unpack the tarball into `/var/lib/chp/repo`, `dnf --enablerepo=chp upgrade -y`), runs `chp-site security enable` (server first, then each client, with the stick attached as in the W1 `enable` stage), then checks on every host:
  - `rpm -q yara chp-yara-rules chp-security` → all installed, chp-security 0.2.0;
  - `systemctl is-enabled chp-yara-fullscan.timer` → `enabled`;
  - `/var/ossec/active-response/bin/chp-yara-scan` exists, mode 750, owner root;
  - 0 "No such tag" lines in `ossec.log` since the restart; 0 fapolicyd denials; 0 YARA or Wazuh AVCs;
  - server: `/var/ossec/etc/rules/chp_yara_rules.xml` present; `agent_control -l` still shows both agents Active; `client.keys` unchanged from before the stage (compare sha256).
  `yaracatch` writes the EICAR string (Task 1 Step 4) to `/home/lab01/eicar-<ts>.txt` and `/tmp/eicar-<ts>.txt` on iso5-cli2, waits up to 3 minutes, and checks: two `chp_yara` match lines in `/var/log/chp-yara.json` on iso5-cli2; two rule-100501 alerts for iso5-cli2 in the server's `alerts.json`; two forwarder lines in `/var/log/lab-hook.log` on the server; both files still present with their original sha256. Then it deletes the two test files.
  `yarafull` starts `systemctl start chp-yara-fullscan` on iso5-cli2 after writing one EICAR file to `/var/tmp`, waits for the service to finish, and checks: a summary line with `files` > 1000, `matches` = 1, `errors` = 0; `/var/lib/chp/yara/last-full` updated; the monitor's 73 check says OK. It records the summary's `seconds`.

- [ ] **Step 4: Run the proofs.** Run, in order: `bash lab/iso5/reset.sh`, then `bash lab/iso5/prove.sh yara-on`, `yaracatch`, `yarafull`. Expected: ALL PASS for each. Record the results in `lab/security/PROOF-RECORD-Y1.md` (proofs 1 catch, 2 weekly scan), with the full scan's time and file count.

- [ ] **Step 5: The quiet day.** Leave the hosts running for 24 hours after `yara-on` (no resets). Then check: no rule-100501 alert other than the EICAR tests; the daily AIDE check reports only the files the update is expected to change (record that list for the update notes); `chp-site alerts --since 24h` reviewed. Record it as proof 3.

- [ ] **Step 6: Commit**

```bash
git add lab/iso5/prove.sh lab/security/PROOF-RECORD-Y1.md
git commit -m "Y1: repo 0.8.0 lab proofs (YARA on, catch, weekly scan, quiet day)"
```

---

### Task 7: Gates on the upgraded lab

**Files:**
- Create: `lab/iso5/regression-<date>.md` (written by the engine)
- Modify: `lab/security/PROOF-RECORD-Y1.md`, `lab/iso5/scan-results/*.xml.xz`

- [ ] **Step 1: Re-take golden with YARA on.** On the upgraded hosts, in the documented order: `bash lab/iso5/prove.sh adapter`, `nvram`, then `IDM_PROFILE=appliance .venv/bin/python lab/iso5/fixtures.py` (expect `FIXTURES OK`), then `bash lab/iso5/prove.sh golden` (expect ALL PASS, 0 findings).

- [ ] **Step 2: Gate 2.** Run: `IDM_PROFILE=appliance IDM_TEST_APPROVE=1 .venv/bin/python -m engine regress --runs 3 --out lab/iso5/regression-<date>.md`, then `bash lab/iso5/prove.sh row36`. Expected: 33/33 GREEN and 3/3.

- [ ] **Step 3: Gate 3.** Run: `bash lab/iso5/prove.sh scan`, then `python3 lab/iso5/deviations.py --decisions lab/iso5/decisions.tsv lab/iso5/scan-results/iso5-{srv,cli1,cli2}.xml`. Expected: 108 pass / 2 fail on every host, Gate 3 met. Compress the results with `xz -9 -f`.

- [ ] **Step 4: Commit**

```bash
git add lab/iso5/regression-*.md lab/iso5/scan-results lab/security/PROOF-RECORD-Y1.md
git commit -m "Y1: gates on repo 0.8.0 (regression, row 36, CUI scan)"
```

---

### Task 8: Release `0.3.0-update1`

**Files:**
- Create: `appliance/release/UPDATE-0.3.0-update1.md.in`
- Create: `appliance/release/RELEASE-RECORD-0.8.0.md`
- Create: `appliance/release/RULES-UPDATE.md`
- Modify: `appliance/site-stick-kit/SITE-STICK.md`
- Modify: `appliance/release/release-kit.sh` (README row for `0.3.0-update1/`)
- Test: `tests/test_release_iso_static.py` (or the file that checks update notes)

- [ ] **Step 1: Write the failing test**

```python
def test_update_0_3_0_update1_notes():
    t = (R / "UPDATE-0.3.0-update1.md.in").read_text()
    for s in ("@REPO@", "chp-site security enable", "alert only", "/var/log/chp-yara.json", "chp-site aide-accept",
              "Detection Rule License", "monthly"):
        assert s in t, s
```

Run: `.venv/bin/python -m pytest -q tests/test_release_iso_static.py -k update1`. Expected: FAIL (file missing).

- [ ] **Step 2: Write `UPDATE-0.3.0-update1.md.in`**, following `UPDATE-0.2.0-update4.md.in`'s structure:
  - **What it adds:** YARA malware scanning (signature-base, Detection Rule License 1.1); real-time scans of new or changed files in `/home`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/srv`, `/data`; a weekly full scan (Sunday 03:30); alert only, matches at level 12 to `ALERT_HOOK`; results in `/var/log/chp-yara.json`; rules updated monthly by signed updates; plus the `chp-identity-server` login-script fix.
  - **Apply it:** verify the folder; unpack `chp-repo-@REPO@.tar.gz` over `/var/lib/chp/repo` on every host; `dnf --enablerepo=chp upgrade`; then, with the site stick, `chp-site security enable` on the server first, then each client.
  - **Expect one AIDE alert, then accept it:** the list measured in Task 6 Step 5, then `chp-site aide-accept --approver "Your Name" --reason "@VERSION@: YARA scanning added"`.
  - **Test it:** the EICAR test string, where it should appear, and that the file is not moved.
  - **Known limits:** anything Task 1 recorded (FIPS, skipped rules count), the scan time measured, and that hosts with `SECURITY_ADDONS=no` are unchanged.

- [ ] **Step 3: Write `RULES-UPDATE.md`** (the monthly procedure): update `SIG_COMMIT`/`SIG_SHA256` in `lab/inputs/fetch-signature-base.sh`; fetch; build `chp-yara-rules`; on the lab, install it on iso5-cli2 and run `prove.sh yarafull` (no new false alarms; add any to `exclude.txt` with the reason); assemble and sign a repo with only `chp-yara-rules` changed; release as `0.3.0-rules-<YYYY-MM>` with `release-repo.sh` and a short `UPDATE` note naming the commit and the skip count.

- [ ] **Step 4: Kit guide.** Add to `SITE-STICK.md`, above "From 0.3.0 on", a section "From 0.3.0 update 1 on: malware scanning (YARA)" (3–5 lines: what it does, alert only, where results go, monthly rules updates).

- [ ] **Step 5: Run the tests and commit.** Run: `.venv/bin/python -m pytest -q`. Expected: all pass. Commit:

```bash
git add appliance/release appliance/site-stick-kit tests
git commit -m "0.3.0-update1 notes, monthly rules procedure, kit guide section"
```

- [ ] **Step 6: Final whole-branch review** (executing-plans' Final Review), fix pass, ledger.

- [ ] **Step 7: Release (owner "go").** Copy the rendered notes to the Desktop as `Update 0.3.0-update1 - REVIEW.md`, ask for "go", restart gpg-agent, cue the owner, then: `V=0.3.0-update1 REPO_V=0.8.0 NOTE=UPDATE-0.3.0-update1.md.in bash appliance/release/release-repo.sh`. Expected: `RELEASED: /Volumes/For Jeff/cyberhygiene-lab-installer/0.3.0-update1` and Good signature. Write `RELEASE-RECORD-0.8.0.md` with the hashes (as `RELEASE-RECORD-0.7.8.md` does) and commit.

- [ ] **Step 8: chp-templates text.** In `~/chp-templates` on a new branch, update `rev2/templates/ssp/controls/3.14.2.md`, `3.14.4.md` and `3.14.5.md`: the implementation text says that with the security add-on (`SECURITY_ADDONS=yes`) YARA scans new and changed files in the user and temporary folders in real time and every local file system weekly, alerting the ISSO and changing nothing; that rules are updated monthly through signed updates (3.14.4); evidence `lab/security/PROOF-RECORD-Y1.md`. Run chp-templates' tests; open a PR there (released with the next templates version; tell the owner and the diwai session before any release, because Automated_Compliance pins chp-templates).

- [ ] **Step 9: PR.** Pre-publication scan of `git diff origin/main`, push, open a PR to main with the rulings and deferred minors from the ledger. The owner merges.
