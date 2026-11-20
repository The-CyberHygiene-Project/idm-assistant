# Repo 0.13.0: unsigned stage and dry-run (ISO 0.7.0 Plan 3, Task 11b)

**Date:** 2026-11-19 · **Stage:** `aero:/data/chp-release/0.13.0/stage` (UNSIGNED, 72 RPMs + `modules.yaml`, 1.2 GB)
· **Not signed:** the owner signs it (YubiKey) with `sign-repo.sh`. Logs: `stage-0.13.0-logs/`. `0.12.0/` was not touched
(its stage and its signed repo pass `sha256sum -c`, and the repo's timestamp is unchanged).

> **OPEN (blocks signing):** the stage carries **chp-templates 1.3.1**, not 1.4.0. `chp-templates/build-rpm.sh` builds
> only from a release folder whose `SHA256SUMS.asc` is signed by the project key. templates-1.4.0 is a local tag
> that has not been released, and the Plan 3 release gate says it must not be signed until after Task 11's lab proof.
> chp-site 0.14.0-7 (`doc.py`, `TEMPLATES_PKG = "chp-templates 1.4.0"`) needs the 1.4.0 `doc/cui/` templates. The
> controller decides; see task-11b-report.md. `~/go.sh` refuses to sign until the stage holds chp-templates 1.4.0.

## What is in it

Repo 0.13.0 = the 0.12.0 stage (61) with 7 of our packages replaced and 11 added (`stage-diff.log`, `stage-sha256.txt`):

| | Package | sha256 |
|---|---|---|
| Replaced | chp-site 0.14.0-4 → **0.14.0-7** | `d99796a5e43a30be786f5be7ea43f5b03fa05a3c907aad04d1e8f98b48670325` |
| Replaced | chp-base 0.1.0-12 → **0.1.0-13** (M7) | `e757657cd770cc012ed8ac1c7faa6fe35bf9521de44f1346c2e08f2ae3fd93d2` |
| Replaced | chp-integrity 0.1.7-1 → **0.1.7-2** (D15) | `453c1cdc7ce321c15b8a694e964ea6a81f6f04d028e2738a3c700e1cb30025ff` |
| Replaced | chp-identity-client 0.2.4-1 → **0.2.4-2** | `bb4a532b2e454eae6ff81408c72fab5e1088a151083e4c08c94eedf7afe27264` |
| Replaced | chp-documents 0.1.0-6 → **0.1.0-8** | `ec2ce84bed8c229526c4f6bb0de2dae9ef51a5b39aa72e323e075625228f151e` |
| Replaced | nextcloud-chp 35.0.3-5 → **35.0.3-6** (chp-build; chp_ledger 1.0.1 + chp_foldertag) | `25da563b84697820ffb4fb84b72649c66533f19bcfe12b30f97a28c4d0dd6705` |
| Added (ours) | chp-onlyoffice 0.1.0-3 | `2dad97f1b52aa9d82c47e4628ae64961ff9170ea7c7d40cd4f844a23c880a9a6` |
| Added (vendor, re-signed at signing) | onlyoffice-desktopeditors 10.0.0-169.el7 (unsigned copy; header `64189290…dc785`) | `872e4aef467490cf6d21e8020941650e0e543c3158b80a094f0a14f7ce0cdb05` |
| Added (Rocky 9.8 DVD, key `350d275d`) | boost-filesystem, boost-system, libXScrnSaver, liberation-narrow-fonts, xcb-util-image, -keysyms, -renderutil, -wm, poppler-utils | `dvdcopy.log` |
| Unchanged | the other 54, including chp-templates **1.3.1** (see OPEN) | |

- **The build.** nextcloud-chp was built on the build VM chp-build, which was started for the build and then shut down
  again. The other packages were built with each package's `build-rpm.sh` on aero (rpmbuild).
- **The old nextcloud-chp-35.0.3-6.** An earlier build with the same version (from before chp_ledger 1.0.1) was in
  `built/`. It was moved to `built/superseded/…pre-ledger-1.0.1`.
- **chp-base and chp-integrity.** Their sources changed in Task 1 (M7, D15), but their releases had not been bumped
  (carry: "Task 11 must bump and rebuild both"). This task bumped them (specs + changelog; `test_chp_base_fapolicyd_fsmark`
  release assertion → 13).
- **Requires pins.** Every pin resolves within the stage: chp-documents → chp-base ≥ 0.1.0-12, chp-site ≥ 0.14.0-7,
  nextcloud-chp ≥ 35.0.3-6, poppler-utils. chp-onlyoffice → onlyoffice-desktopeditors = 10.0.0, chp-site ≥ 0.14.0-7,
  poppler-utils, chp-base. chp-identity-client → chp-site ≥ 0.14.0-5. chp-integrity → chp-site ≥ 0.7.1.
- **The vendor RPM.** The cached file was `~/idm-lab-inputs/onlyoffice/repo-copy.rpm` on the Mac (sha256 `2e634456…2df9`,
  the VENDOR.txt pin). It was copied to `aero:/data/lab-inputs/onlyoffice-vendor/`. Nothing was downloaded.
  `stage-vendor.sh` verified the vendor signature (E09C…2DE8E5), the name, version-release and header, then stripped
  the signature. The unsigned copy was installed into the third-party dir (`/data/lab-inputs/rpms`, root-owned:
  `sudo install`).
- **The Rocky extras.** The closure was resolved by dnf in scratch installroots on aero (`closure.sh`, `unshare -rm`).
  It ran against **copies** of iso5-cli1's and iso5-srv's rpm databases, with the candidate repo + the DVD's BaseOS and
  AppStream, without weak deps. On the workstation, `chp-onlyoffice` pulls exactly the **8** extras in PACKAGES.txt
  (+ onlyoffice + a chp-site upgrade). **poppler-utils** (21.01.0-24.el9) and its dependencies (poppler, poppler-data,
  poppler-glib, poppler-cpp) are already on every 0.6.0 install, so its closure adds nothing; the DVD copy is in the
  repo for the Requires. All 9 files pass `rpm -K` with the Rocky key alone and are byte-identical (`cmp`) to the DVD.
- **modules.yaml** `6b0eb335…cff012c`, unchanged (no new modular package).

## Dry-run on the three hosts (owner-signed 0.12.0 r4 applied)

Run as `chpadmin`, with no sudo, as uid 0 of `unshare -rm`. The repo was a temp copy of the stage with repodata from
`make-repodata.sh` (sign-repo's path, unsigned; modules record present), used alone (`--repo=s013 --nogpgcheck`). The
host's module state was copied into a namespace tmpfs; dnf history, cache and log were tmpfs too. Every transaction ran
`--assumeno`. `rpm -U --test` ran against a **copy** of each host's rpm database. Scripts: `push-dry.sh`, `outer.sh`,
`dry-run.sh`. Logs: `dry-srv.log`, `dry-cli1.log`, `dry-cli2.log`.

| Host (role) | `upgrade` | Editor / documents | `rpm -U --test` |
|---|---|---|---|
| iso5-srv (server; php 8.3 [e], postgresql 16 [e]) | **Upgrade 6**: chp-base 0.1.0-13, chp-documents 0.1.0-8, chp-identity-client 0.2.4-2, chp-integrity 0.1.7-2, chp-site 0.14.0-7, nextcloud-chp 35.0.3-6 (212 MB); nothing else | `install nextcloud-chp chp-documents` = upgrade 3; `install chp-templates` = 1.3.1 (OPEN) | rc 0 (6) |
| iso5-cli1 (workstation) | **Upgrade 4**: chp-base, chp-identity-client, chp-integrity, chp-site | `install chp-onlyoffice` = **Install 10** (chp-onlyoffice, onlyoffice-desktopeditors, 8 extras) + upgrade chp-site, 278 MB; with upgrade = Install 10, Upgrade 4. The editor does not pull chp-documents. | rc 0 (14): no conflicts, no unmet deps |
| iso5-cli2 (workstation) | same as cli1 | same as cli1 | rc 0 (14) |

Afterwards, on each host: rpmdb.sqlite, history.sqlite and modules.d were unchanged (stat), the installed versions were
unchanged, and `/var/tmp/s013` was removed. Nothing was installed on any lab VM. aero's fapolicyd was not changed.

**Not proven here:** signatures (`--nogpgcheck`), and the real transactions (scriptlets, SELinux, fapolicyd, the editor
on a desktop). Those are Task 11c.

## Signing tools

- `push.sh` now also copies `VENDOR.txt` and `vendor-keys/`. sign-repo.sh reads `VENDOR.txt` next to itself, and
  without it the onlyoffice RPM would be refused at signing.
- aero `tools/` == repo `appliance/release/` by sha256, for all 22 files that push.sh copies. aero also holds
  `RPM-GPG-KEY-Rocky-9`. It is not in git; it is byte-identical to the DVD's copy, as in 0.12.0.
- **`test_sign_repo.sh`** (aero tools dir, throwaway keys): **59 PASS, 0 FAIL**, exit 0 (`test_sign_repo.log`).
- **Rehearsal** (`rehearse.sh` / `rehearse.log`): `sign-repo.sh` ran on the real stage with a throwaway software key
  (temp GNUPGHOME; no YubiKey, no project key) and a keys dir where that key takes the cyberhygiene slot. Result:
  `REPO OK: 72 packages`. onlyoffice was re-signed by the rehearsal key with header `64189290…` unchanged, and the
  Rocky signatures were kept (`702d426d350d275d`). The output was deleted; the stage was unchanged (`sha256sum -c`).

## For the owner (after the chp-templates decision)

`~/go.sh` = `sign-session.sh "sign-repo.sh /data/chp-release/0.13.0/stage /data/chp-release/0.13.0/repo 2DE0…8F8E
/data/chp-release/tools"`. It holds while the stage has no chp-templates 1.4.0. Expect `REPO OK: 72 packages` (chp-templates
1.4.0 replaces 1.3.1: the count stays the same). verify-repo also checks the modules record.
