# Repo 0.14.0: unsigned stage and dry-run (ISO 0.7.0 Plan 3, Task 13b)

**Date:** 2026-11-21 · **Stage:** `aero:/data/chp-release/0.14.0/stage` (UNSIGNED, 72 RPMs + `modules.yaml`, 1.2 GB) ·
**Not signed:** the owner signs it (YubiKey) with `~/go.sh` → `sign-session.sh` → `sign-repo.sh`. Logs:
`stage-0.14.0-logs/`. Same procedure as 0.13.0 (`stage-0.13.0.md`, Task 11b + option A). **0.13.0 untouched:** its signed
repo and its stage hash the same before and after (`rehearse.log`), and the repo's mtime is still 11-20 09:34.
Built from idm-assistant `iso-0.7.0-owner-batch` (cbc7df1 + 7c63348).

> **chp-templates 1.4.0-2 is a PRE-RELEASE LAB CANDIDATE** (owner decision 2026-11-20, option A; 13b ruling). It was built
> with `CHP_TEMPLATES_TAG=~/chp-templates` from `git archive` of the **unsigned local tag** templates-1.4.0, which was
> re-tagged in this task from 0a18aca to **1d7b682** (chp-templates `iso-0.7.0-docs`: release notes state content
> 1.2.7; 3.4.3 and 3.8.4 cite `PROOF-RECORD-PLAN3.md`). Archive sha256 `3bf9d127…0032601e` = the build-rpm.sh pin; that
> pin is the only input check, with no signature provenance (`templates-build.log`). The tag is not pushed. The signed
> templates release (release.sh) moves to Plan 4. The spec's %changelog no longer carries a lab-candidate bullet (the
> same spec builds the signed release); this note is the record.

## What changed vs 0.13.0 (`stage-diff.log`; `stage-sha256.txt`)

| Package | 0.13.0 → 0.14.0 | sha256 | Built on |
|---|---|---|---|
| chp-site | 0.14.0-7 → **0.14.0-10** | `2fc465b0ac924e3b80b62bc362d88ef4d94cf44dbf3ae37509dd0e71feef4b1d` | aero |
| chp-base | 0.1.0-13 → **0.1.0-14** | `3df8800a873c5f5bdea121d6e02854a81b3b8ae0c6907e2a4c853296dbcb296d` | aero |
| chp-documents | 0.1.0-8 → **0.1.0-10** | `8478f2c60a4f76ce58e6cdeebe18ec8684d4244200991e6e95174664fef5872c` | aero |
| chp-identity-client | 0.2.4-2 → **0.2.4-4** | `e848ec031e100120d1fe975998c8da774e8236f8b492d6c89571aea39ac965ac` | aero |
| chp-identity-server | 0.1.2-3 → **0.1.2-6** | `879391850e4be4e2cb7c74ddbe9a5afea0c6190b73676445c68c619d40e95002` | aero |
| chp-onlyoffice | 0.1.0-3 → **0.1.0-5** | `4d873405fb0c1b72747cd3f68111390d494758679968b9cda6941303595ed1bf` | aero |
| chp-templates | 1.4.0-1 → **1.4.0-2** (lab candidate, above) | `c1f011fd28464c2b89571039630b2fb3b469c34538c85e891cae6bc09c656a08` | aero |
| nextcloud-chp | 35.0.3-6 → **35.0.3-7** (222,168,923 B, 33,915 files) | `16c7e815903d4de289a84271cec51c285c24718678d666d57571fbea3ac18ab8` | chp-build (started, then shut down) |
| the other 64 | unchanged (incl. chp-integrity 0.1.7-2, onlyoffice-desktopeditors, the 9 Rocky DVD packages) | | |

- Every spec whose Version/Release changed since 1819c9b (the 0.13.0 staging commit) is in the table: 8 packages. Every
  source dir with changes has its spec bumped. No Requires on a new third-party package.
- **Requires pins** (all resolve within the stage): chp-documents → nextcloud-chp ≥ 35.0.3-7, chp-site ≥ 0.14.0-10,
  chp-base ≥ 0.1.0-12, poppler-utils; chp-identity-client → chp-base ≥ 0.1.0-14, chp-site ≥ 0.14.0-10;
  chp-identity-server → chp-identity-client ≥ 0.2.4-4, chp-site ≥ 0.14.0-10; chp-onlyoffice → chp-templates ≥ 1.4.0-2,
  chp-site ≥ 0.14.0-10, onlyoffice-desktopeditors = 10.0.0, poppler-utils; chp-integrity → chp-site ≥ 0.7.1.
- **The DVD packages** (`dvdcopy.sh`/`.log`): the 9 files in the third-party dir pass `rpm -K` with the Rocky key alone
  (Rocky header signature 702d426d350d275d) and are byte-identical to the DVD (`cmp`). The `(none)` column is the
  SIGPGP tag, empty on these RPMs as in 0.13.0's log; the RSA header signature is the one checked.
- **The vendor RPM**: the same unsigned copy as 0.13.0 (header `64189290…dc785`), re-signed through VENDOR.txt at signing.
- **Closure** (`closure.sh`/`.log`, scratch installroots on aero against COPIES of all three hosts' rpm databases, candidate +
  DVD BaseOS/AppStream, no weak deps): nothing comes from the DVD. cli1/cli2 upgrade 5 (chp-base, chp-identity-client,
  chp-onlyoffice, chp-site, chp-templates); srv upgrade 6, and `install chp-templates` = install 1.
- modules.yaml: php:8.3, postgresql:16 (18 modular RPMs), unchanged.

## Dry-run on the three hosts (current lab state after 11c; `push-dry.sh`, `outer.sh`, `dry-run.sh`)

As 11b: chpadmin, no sudo, uid 0 of `unshare -rm`; a temp copy of the stage with `make-repodata.sh` repodata (unsigned)
used alone (`--repo=s014 --nogpgcheck`); module state, dnf history/cache/log in namespace tmpfs; every transaction
`--assumeno`; `rpm -U --test` against a COPY of each host's rpm database. The upgrade set for `rpm -U --test` is now taken
from check-update (the lab already holds the editor and chp-templates on the workstations).

| Host | Installed before | `upgrade` | Extra | `rpm -U --test` |
|---|---|---|---|---|
| iso5-srv (php 8.3 [e], postgresql 16 [e]) | 0.13.0 set | **Upgrade 6**: chp-base 0.1.0-14, chp-documents 0.1.0-10, chp-identity-client 0.2.4-4, chp-identity-server 0.1.2-6, chp-site 0.14.0-10, nextcloud-chp 35.0.3-7 (212 MB) | `install nextcloud-chp chp-documents` = upgrade 3; `install chp-templates` = install **1.4.0-2** | rc 0 (6) |
| iso5-cli1 | 0.13.0 set + chp-onlyoffice 0.1.0-3, onlyoffice 10.0.0, chp-templates 1.4.0-1 | **Upgrade 5**: chp-base, chp-identity-client, chp-onlyoffice 0.1.0-5, chp-site, chp-templates 1.4.0-2 (365 k) | `install chp-onlyoffice` = upgrade 3 (+chp-site, chp-templates); requires resolve to chp-base, chp-site, chp-templates, onlyoffice, poppler-utils | rc 0 (5) |
| iso5-cli2 | same as cli1 | same as cli1 | same | rc 0 (5) |

On every host the rpmdb, dnf history and modules.d stat lines and the installed versions are identical before and after;
`/var/tmp/s014` was removed. The `cp: failed to preserve ownership` lines are the namespace copy, as in 0.13.0.
Not proven here: signatures, scriptlets, SELinux, fapolicyd, AIDE (Task 13c).

## Signing tools

- `push.sh` re-run (nothing changed in `appliance/release/` since 1819c9b). aero `tools/` == repo by sha256 for all 22
  files (`tools-sha-check.log`); aero also holds `RPM-GPG-KEY-Rocky-9`, byte-identical to the DVD's, as before.
- **`test_sign_repo.sh`**: 59 PASS, 0 FAIL, exit 0 (`test_sign_repo.log`).
- **Rehearsal** (`rehearse.sh`/`.log`): sign-repo.sh on the real 0.14.0 stage with a throwaway software key (temp
  GNUPGHOME, no YubiKey, no project key): `REPO OK: 72 packages`; verify-repo rc 0; onlyoffice re-signed with header
  `64189290…` kept; Rocky signatures kept (702d426d350d275d). Output deleted; stage unchanged vs `stage-sha256.txt`.

## For the owner

`~/go.sh` refuses unless the stage holds chp-templates-1.4.0-2 and chp-onlyoffice-0.1.0-5, exactly 72 RPMs, and its
`sha256sum *` list hashes to `c7c1e333…65efdb` (= sha256 of `stage-sha256.txt`), and unless `0.14.0/repo` does not exist
yet. Then `sign-session.sh "sign-repo.sh /data/chp-release/0.14.0/stage /data/chp-release/0.14.0/repo 2DE0…8F8E
/data/chp-release/tools"`. Expect `REPO OK: 72 packages` and `sign EXIT=0`. The guard passes on 0.14.0 and refuses
on 0.13.0's stage.
