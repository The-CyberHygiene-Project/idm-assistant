# chp-templates Plan C3: installer integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A site renders its own SSP and POA&M on the appliance server with one command, from the signed chp-templates
release and its own `profile.ini` on the site stick. It ships to 0.2.0 sites as a package update, with no reinstall.

**Architecture:**
- **A new noarch package, `chp-templates`,** is built from the **signed `templates-1.2.0` tarball**, with its sha256
  pinned and its signature checked at build time. It installs the library to `/usr/share/chp-templates/`.
- **`chp-site` 0.7.2 gains `docs`.** The command reads `profile.ini` from the site stick, using the same temporary
  USBGuard authorization `aide-pin` uses. It runs the installed renderer as a subprocess (`python3 …/chpfill.py`), so
  fapolicyd trusts it as an RPM-installed file. It writes `/var/lib/chp/docs/<UTC timestamp>/`.
- **`chp-site validate`** checks a `profile.ini` on the stick against the chp-templates vocabulary when chp-templates is
  available.
- **No kickstart or ISO change.** It is released as signed repo 0.7.6 in a `0.2.0-update2/` folder, through
  `release-repo.sh`.

**Tech Stack:** Python 3.9 stdlib (`chp_site`), bash, rpmbuild on aero, the signed repo tools, pytest on the Mac,
the iso5 rc2 golden lab hosts.

**Spec:** `docs/superpowers/specs/2026-10-24-chp-templates-design.md` §5.2 (APPROVED 2026-10-24). Owner rulings since:
- the per-system and per-contract forms (chp-templates 1.1.0 and 1.2.0);
- `profile.ini` at the stick's top level (agreed with Automated_Compliance, 2026-10-25).

## Facts established while planning (2026-10-25)

- **AIDE on the server:**
  - `/var/lib/chp/docs` has **no matching rule** (`aide --path-check` on iso5-srv), so rendered documents and the site's
    later edits raise no alerts.
  - `/usr/share/chp-templates` falls under `/usr` (content-checked). A package install there is "explained by signed
    package updates".
- **The kickstart copies only `site.conf`, `hosts` and `client.conf` to `/etc/chp`** (`chp.ks.in` lines 92–96). A
  `profile.ini` on the stick is therefore read from the stick at `docs` time, not copied at install. This keeps
  document values, which include names and addresses, off the server's `/etc`.
- **`site_stick(stick=None)`** (`chp_site/usbstick.py`) authorizes only the pinned stick through USBGuard, temporarily,
  mounts it, yields the path, and always blocks it again. With `--stick DIR` (tests, lab) it simply yields `DIR`.
- **The `templates-1.2.0` release:** `For Jeff/chp-templates/1.2.0/`, tarball
  sha256 `ca40b7ff4cfa95040f3dc5155fc8c238d71e3f1feade89380e5072381c75b389`, `SHA256SUMS.asc` signed by
  `2DE0D71BF37D8F5E4201A590521276F43C908F8E`. Automated_Compliance pins the same release.
- **The renderer's interface** (chp-templates 1.2.0) is
  `python3 render/chpfill.py fill --lib DIR --profile P [--site-conf S] [--public] --out OUT --templates-version V`.
  - Exit codes: 0 on success, 2 on a `FillError`, with the message on stderr.
  - It refuses an existing `--out`.
  - `rev2/MANIFEST.json` carries `content_version`.

## Global Constraints

- **File header:** new `idm-assistant` files carry the installer header (the three Rocky Linux lines).
- **`chp_site`:** Python 3.9, standard library only. **It never imports chp-templates code into the zipapp.** It calls
  the installed renderer as a subprocess, or loads it by path for `validate`.
- **Versions:** `chp-site` **0.7.2-1.chp**; `chp-templates` **1.2.0-1.chp** (the package version equals the templates
  release); signed repo **0.7.6**. Released 0.1.0, 0.2.0 and update1 are never touched.
- **Secrets:** the stick's escrow is never read by `docs`; `profile.ini` is never copied to `/etc`; rendered documents
  are root-only (dir 0700, files 0600).
- **Signing:** cue the owner per memory: "reply go, finger ready; touch when it flashes; a PIN window only if not cached".
- **Ledger:** `.superpowers/sdd/2026-10-25-chp-templates-plan-c3-installer/progress.md`.

## Review Focus

1. **The stick is not plugged in when `docs` runs.** Expect the same clear refusal `aide-pin` gives (no OEMDRV stick),
   not a traceback, and no `/var/lib/chp/docs/<ts>` created. → Task 2 test `test_docs_without_a_stick_refuses`.
2. **No `profile.ini` on the stick.** Expect a render anyway, with every document value left as a visible placeholder
   and listed in the report (the documents still come out with `site.conf`'s mapped values), plus a one-line note
   saying so. → Task 2 test `test_docs_without_a_profile_renders_with_placeholders`.
3. **The renderer fails** (exit 2: a bad profile key, a secret-shaped value, a non-UTF-8 file). Expect `docs` to pass
   the renderer's message through, exit non-zero, and leave no partial `<ts>` folder. → Task 2 test
   `test_renderer_error_is_passed_through_and_nothing_is_left`.
4. **chp-templates is not installed**, for example after a partial update. Expect "install chp-templates" as the
   message, not a missing-file traceback. → Task 2 test `test_docs_without_chp_templates_installed`.
5. **`--rev rev3` is asked for before the Rev 3 library exists.** Expect "rev3 is not in this chp-templates release". →
   Task 2 test `test_unknown_revision_is_refused`.

---

### Task 1: The `chp-templates` package (built from the signed release)

**Files:** Create `appliance/rpm/chp-templates/{chp-templates.spec,build-rpm.sh}`, `tests/test_chp_templates_rpm_static.py`.
Modify `appliance/release/PACKAGES.txt` (add `chp-templates ours`).

- [ ] **Step 1: Failing static test.**
  - The spec has `Version: 1.2.0`, `BuildArch: noarch` and `Requires: python3`.
  - It installs `/usr/share/chp-templates/{rev2,render,vocabulary.md,site-conf-mapping.csv,README.md}` and the licence,
    and nothing under `tests/` or `tools/`.
  - `build-rpm.sh` pins the tarball sha256 above.
  - `build-rpm.sh` runs `gpg --verify SHA256SUMS.asc SHA256SUMS` and `shasum -a 256 -c` **before** copying the tarball
    to aero, and refuses on any mismatch.
  - `PACKAGES.txt` has `chp-templates ours`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3: Write the files.**
  - The spec's `%install` unpacks `chp-templates-1.2.0/` and copies only the shipped paths (modes 0644; directories
    0755).
  - `%files` lists them.
  - The changelog entry reads "First release: chp-templates 1.2.0 (signed tarball sha256 ca40b7ff…)".
  - `build-rpm.sh` follows the `chp-integrity/build-rpm.sh` pattern. It reads the tarball from
    `${CHP_TEMPLATES_RELEASE:?}` (a folder holding the tarball, `SHA256SUMS` and `SHA256SUMS.asc`; on the Mac,
    `/Volumes/For Jeff/chp-templates/1.2.0`). It verifies, scps to aero, and runs rpmbuild.
- [ ] **Step 4:** Run the test (PASS) and the full suite. Then run `CHP_TEMPLATES_RELEASE=… bash
  appliance/rpm/chp-templates/build-rpm.sh`. Expected: the RPM file list printed, with `/usr/share/chp-templates/…`.
- [ ] **Step 5: Commit** `chp-templates RPM 1.2.0, built from the signed release (sha256 + signature checked)`.

### Task 2: `chp-site docs`

**Files:** Create `appliance/chp-site/chp_site/docs.py`, `tests/test_chp_site_docs.py`. Modify
`appliance/chp-site/chp_site/cli.py` (the subcommand) and `__init__.py` (VERSION 0.7.2).

**Interfaces:** `docs.render(stick_dir: Path|None, site_conf: Path, templates: Path, out_root: Path, rev: str, now:
callable) -> Path`. It returns the new output dir and raises `SiteError` with a person-readable message.

**CLI:** `chp-site docs [--stick DIR] [--site /etc/chp/site.conf] [--templates /usr/share/chp-templates] [--out-root
/var/lib/chp/docs] [--rev rev2]`.

- [ ] **Step 1: Failing tests**, using a tmp templates dir with a **stub** `render/chpfill.py`. The stub writes its
  arguments to a file and creates the three output files; for the error test it exits 2 with a message.
  - The arguments include `fill --lib <templates>/rev2 --profile <stick>/profile.ini --site-conf <site.conf> --out
    <out_root>/<UTC ts> --templates-version <MANIFEST content_version>`.
  - The out dir is mode 0700, its files 0600, and it is named `YYYYmmddTHHMMSSZ`.
  - A second run in the same second gets a `-2` suffix and never overwrites.
  - The five Review Focus tests (above).
  - `docs` never touches `<stick>/escrow`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - `docs.py` runs `subprocess.run([sys.executable or "python3", chpfill, "fill", …], capture_output=True,
    text=True)`.
  - On exit code ≠ 0: remove any created dir, then raise `SiteError(stderr)`.
  - Read the version with `json.load(MANIFEST)["content_version"]`.
  - The CLI wraps it in `site_stick(a.stick)`, so the stick is authorized only while the profile is read and rendered,
    and always blocked again afterwards.
  - Print the output path, the number of unfilled placeholders (from the renderer's stdout), and a pointer to
    `fill-report.md`.
  - Then `logger -t chp-site "docs rendered <path>"`.
- [ ] **Step 4:** Run the tests (PASS) and the full suite. Then commit `chp-site docs: render the site's SSP and
  POA&M from the stick's profile.ini (0.7.2)`.

### Task 3: `chp-site validate` checks `profile.ini`

**Files:** Modify `appliance/chp-site/chp_site/cli.py` (`_validate`). Create `appliance/chp-site/chp_site/profilecheck.py`,
`tests/test_chp_site_profilecheck.py`.

**Interfaces:** `profilecheck.check(site_dir: Path, templates: Path|None) -> str`. It returns a one-line result, raises
`SiteError` on a bad profile, and returns `"profile.ini not checked: chp-templates not found (set CHP_TEMPLATES)"`
when the renderer can't be found.

- [ ] **Step 1: Failing tests.**
  - The renderer is found in `$CHP_TEMPLATES`, then `/usr/share/chp-templates`, then `<site_dir>/../chp-templates`.
  - The renderer module is loaded by path with `importlib.util.spec_from_file_location`, never imported into the
    zipapp.
  - It calls `load_values(profile, site.conf, None, mapping)` and `check_values(values, facts,
    load_vocabulary(vocab), public=False)`, and converts the renderer's `FillError` into `SiteError` with the same
    text.
  - Without a `profile.ini`, it returns `""`, and `validate` prints nothing extra.
  - A stub renderer module stands in for unit tests. One integration test uses the real `~/chp-templates`, skipped when
    absent.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. `_validate` appends the result to its OK line when non-empty.
- [ ] **Step 4:** Run the tests (PASS) and the full suite. Then commit `chp-site validate: check profile.ini against
  the chp-templates vocabulary when available`.

### Task 4: Kit — `profile.ini.template` and the guide

**Files:** Create `appliance/site-stick-kit/profile.ini.template`, `tests/test_kit_profile_template.py`. Modify
`appliance/site-stick-kit/SITE-STICK.md` (a new section, "From 0.2.0 update 2 on: your SSP and POA&M").

- [ ] **Step 1: Failing test.**
  - Every key in the template (commented examples included) is in chp-templates 1.2.0's vocabulary. The test is
    skipped when `~/chp-templates` is absent.
  - Every example value uses `example.test`, `192.0.2.x` or "Example …".
  - The guide names `chp-site docs`, `/var/lib/chp/docs`, `fill-report.md`, the stick's top level, and "never put
    passwords in profile.ini".
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3: Write the files.**
  - The template follows Automated_Compliance's form: `[organization]`, `[roles]`, `[system.<name>]`,
    `[contract.<n>]`, `[scope]`, `[document]`, `[decision]` and `[facts]`. Each has a one-line comment, and the
    decision values the appliance enforces are marked.
  - The guide section is short: what `profile.ini` is, where it goes, the command, where output goes, and that the
    report lists what is still to fill.
- [ ] **Step 4:** Run the test (PASS) and the full suite. Then commit `Kit: profile.ini.template and the SSP/POA&M
  section of the site-stick guide`.

### Task 5: Repo 0.7.6, lab proof, update note

**Files:** Create `appliance/release/UPDATE-0.2.0-update2.md.in`, `appliance/release/RELEASE-RECORD-0.7.6.md`. Modify
`appliance/release/release-repo.sh` (`NOTE=` selects the update note; the default stays `UPDATE.md.in`, so update1
behaviour is unchanged) and its static test.

- [ ] **Step 1: release-repo.sh test first.**
  - `NOTE` is honoured.
  - The default note is unchanged.
  - The note file must exist, or the script refuses.
- [ ] **Step 2: Build and assemble.**
  - Build `chp-site` 0.7.2 and `chp-templates` 1.2.0.
  - Run `assemble-repo.sh` to `/data/chp-release/0.7.6/stage`. Expected: 14 lines, including `chp-templates ←
    chp-templates-1.2.0-1…`.
- [ ] **Step 3: Owner signing** (cue as in Global Constraints). Then run `verify-repo.sh` (expected `REPO OK: 14
  packages`) and copy to `/data/lab-inputs/chp/0.7.6`.
- [ ] **Step 4: Lab proof** on iso5-srv (rc2 golden, adapter):
  1. Unpack 0.7.6.
  2. `dnf --enablerepo=chp upgrade chp-site && dnf --enablerepo=chp install chp-templates`.
  3. Write a lab `profile.ini` (fictional values) to the stick image.
  4. Attach the stick.
  5. Run `sudo chp-site docs`.

  Expected:
  - a new `/var/lib/chp/docs/<ts>/` holding `ssp.md`, `poam.md` and `fill-report.md` (dir 0700, files 0600);
  - the boundary and contract lists rendered;
  - USBGuard blocks the stick again afterwards;
  - `aide --path-check d:/var/lib/chp/docs` reports no rule.

  Run `chp-site validate --site <stick>` on the Mac copy of the stick. Revert to golden. Record everything in
  `RELEASE-RECORD-0.7.6.md`.
- [ ] **Step 5: The update note** (`UPDATE-0.2.0-update2.md.in`):
  - what is new;
  - how to apply it (unpack the tarball; `dnf … upgrade chp-site`; `dnf … install chp-templates`);
  - how to use it (`profile.ini` on the stick, from `profile.ini.template`; `chp-site docs`);
  - that `/usr/share/chp-templates` is AIDE-checked and the install shows as "explained by signed package updates",
    to accept with `aide-accept`.
- [ ] **Step 6: Commit** `Repo 0.7.6 (chp-site 0.7.2 + chp-templates 1.2.0): lab-proved; update note`.

### Task 6: Release `0.2.0-update2` (owner's YubiKey) and the kit

- [ ] **Step 1:** Run the pre-publication scan over the files bound for the share.
- [ ] **Step 2: Release.** Run `V=0.2.0-update2 REPO_V=0.7.6 NOTE=UPDATE-0.2.0-update2.md.in bash
  appliance/release/release-repo.sh` (owner signing). Expected: `Good signature`, all OK.
- [ ] **Step 3: Kit.** The kit gains `profile.ini.template` and the new guide section, so republish it as
  `site-stick-kit-0.2.0-update2/` with `release-kit.sh`. Add `profile.ini.template` to its file list (test first) and
  take `chp-site.pyz` from repo 0.7.6. A second owner signature.
- [ ] **Step 4:** Update the share's README rows. Commit `Released 0.2.0-update2 and its kit`.

### Task 7: Finish

- [ ] **Whole-branch review:** a fresh reviewer, most capable model, with this plan's Review Focus. Fix Important
  findings RED→GREEN.
- [ ] **Publish:** run the pre-publication scan, push `plan-c3-templates`, and open a PR (attribution). The merge is
  the owner's.
- [ ] **Wrap up:** update the memory notes, and tell the diwai session that appliance-side rendering exists (same
  release, same names).
