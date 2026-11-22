# Repo 0.14.1: unsigned stage and dry-run (ISO 0.7.0 Plan 3, Task 13e)

**Date:** 2026-11-22 · **Stage:** `aero:/data/chp-release/0.14.1/stage` (UNSIGNED, 72 RPMs + `modules.yaml`, 1.2 GB) ·
**Not signed:** the owner signs it (YubiKey) with `~/go.sh` → `sign-session.sh` → `sign-repo.sh`. Logs:
`stage-0.14.1-logs/`. Same procedure as 0.14.0 (`stage-0.14.0.md`, Task 13b), except the dry-run (below: no live VMs).
**0.13.0 and 0.14.0 untouched:** their signed repos and stages hash the same before and after, and the repos' mtimes are
still 11-20 09:34 and 11-21 05:32 (`stage.log`). Built from idm-assistant `iso-0.7.0-owner-batch` (affcd1a + 6034056).

> **chp-templates 1.4.0-3 is a PRE-RELEASE LAB CANDIDATE** (owner decision 2026-11-20, option A). It was built with
> `CHP_TEMPLATES_TAG=~/chp-templates` from `git archive` of the **unsigned local tag** templates-1.4.0, re-tagged in this
> task from 1d7b682 to **d015ba5** (chp-templates `iso-0.7.0-docs`, Rev 2 content 1.2.8: the SSP 3.4.3/3.1.3 alert
> conditions, the 3.1.3 wording, the proof-record citations). Archive sha256 `9af9dda9…d656c8` = the build-rpm.sh pin;
> that pin is the only input check, with no signature provenance (`templates-build.log`). The tag is not pushed. The
> signed templates release (Plan 4) must be Release ≥ 1.4.0-4.

## What changed vs 0.14.0 (`stage.log`; `stage-sha256.txt`, `built-sha256.txt`)

| Package | 0.14.0 → 0.14.1 | sha256 | Built on |
|---|---|---|---|
| chp-site | 0.14.0-10 → **0.14.0-12** | `b7c56ab9dec38f3d8b7b27b7f36e784a2767a5cd4c9cb564cf8e8d0a48e13783` | aero |
| chp-documents | 0.1.0-10 → **0.1.0-13** | `437b862bdd96d0cde8219847c65c8d457ba900e6a9896ce898241bbd907891f5` | aero |
| chp-identity-client | 0.2.4-4 → **0.2.4-6** | `f4141a0236fda6be0cc570d795bda770765fcefac75db1fb5099bec0f0d57bb6` | aero |
| chp-identity-server | 0.1.2-6 → **0.1.2-8** | `dd4ebbd7f5b52ba534427fbc633277d75254527ce7265beff50b5f5c1f6ed2ba` | aero |
| chp-onlyoffice | 0.1.0-5 → **0.1.0-7** | `eefe9c42ede64407e16c64735dd9c1f425a214e7655eca882560949b1fb404ff` | aero |
| chp-templates | 1.4.0-2 → **1.4.0-3** (lab candidate, above) | `bec4cb2a3745d0887419ac65551ec934a2c33562e4f1a6d2ba94b61b3c5987f1` | aero |
| nextcloud-chp | 35.0.3-7 → **35.0.3-8** (chp_ledger 1.0.3; 222,153,868 B, 33,915 files) | `84a31a9995d49c26884f9087434882b84ff6049f5df90f052077fcfdf7af6439` | chp-build (started, then shut down) |
| the other 65 + modules.yaml | **byte-identical** to the signed 0.14.0 stage: 66 of 66 names hash the same, 0 differ | | |

- Every spec's Version/Release was compared with the 0.14.0 stage: exactly these 7 differ (chp-base stays 0.1.0-14,
  chp-integrity 0.1.7-2). Every changed source dir since ff241dc (the 0.14.0 staging commit) has its spec bumped;
  `site-stick-kit/` ships in no RPM.
- The 0.14.0 stage list on aero is byte-identical to `stage-0.14.0-logs/stage-sha256.txt` (digest `c7c1e333…`).
- **Requires pins** (all resolve within the stage): chp-documents → nextcloud-chp ≥ 35.0.3-8, chp-site ≥ 0.14.0-12,
  chp-base ≥ 0.1.0-12, poppler-utils; chp-identity-client → chp-base ≥ 0.1.0-14, chp-site ≥ 0.14.0-12;
  chp-identity-server → chp-identity-client ≥ 0.2.4-6, chp-site ≥ 0.14.0-12; chp-onlyoffice → chp-site ≥ 0.14.0-12,
  chp-templates ≥ 1.4.0-2 (unchanged; met by 1.4.0-3), onlyoffice-desktopeditors = 10.0.0, poppler-utils.
- Vendor RPM, 9 Rocky DVD packages, modules.yaml: the same files as 0.14.0 (in the 66 identical).

## Dry-run (no live VM touched: a lab worker runs the regression gate on the iso5 VMs)

No saved rpm database of the current (0.14.0) lab exists on aero, so the dry-run is built from **fresh install-roots of
the 0.14.0 repo's package set** (`dryroot.sh`/`dry-run.log`): per host, `dnf --installroot` with `tsflags=justdb`
(database only; no files, no scriptlets) of the host's packages from the **signed 0.14.0 repo** + the DVD, no weak deps,
in `unshare -rm`. Host sets from the 13c logs (191, 215): srv = chp-site, chp-base, chp-integrity, chp-identity-server,
chp-identity-client, chp-documents, nextcloud-chp, chp-templates, chp-security (php 8.3, postgresql 16 enabled);
cli1 = cli2 = chp-site, chp-base, chp-integrity, chp-identity-client, chp-onlyoffice, chp-templates, chp-security.

| Host (rebuilt 0.14.0 db) | `upgrade`, candidate ONLY | role set from candidate + DVD | `rpm -U --test` (db copy) |
|---|---|---|---|
| srv (301 packages) | **Upgrade 6**: chp-documents 0.1.0-13, chp-identity-client 0.2.4-6, chp-identity-server 0.1.2-8, chp-site 0.14.0-12, chp-templates 1.4.0-3, nextcloud-chp 35.0.3-8 (212 MB) | the same 6, nothing from the DVD | rc 0 (6) |
| cli1 (306 packages) | **Upgrade 4**: chp-identity-client, chp-onlyoffice 0.1.0-7, chp-site, chp-templates 1.4.0-3 (346 k) | the same 4, nothing from the DVD | rc 0 (4) |
| cli2 (306 packages) | same as cli1 | same | rc 0 (4) |
| fresh server (empty root) | install 301 from candidate + DVD: every chp/kanidm/step/nextcloud package from the candidate; no unresolved Requires | | |
| fresh workstation (empty root) | install 306: likewise, the editor and its 8 extras from the candidate | | |

If srv does not hold chp-templates (13c kept it; not re-checked on the live VM), its upgrade is 5 and `install
chp-templates` adds 1.4.0-3.

**Supplementary** (`olddb.sh`/`olddb.log`): the only saved REAL lab rpm databases, srv's and cli1's of 2026-11-19 21:52
(the 0.12.0 state, two repos behind; copies from the Mac scratchpad, not from the VMs), with the candidate ALONE:
srv `install chp-documents nextcloud-chp chp-templates` + `upgrade` = 8 packages, rpm -U --test rc 0; cli1 `install
chp-onlyoffice chp-templates` (+ the vendor RPM and 8 extras, all from the candidate) + `upgrade` = 15 packages,
rpm -U --test rc 0.

Not proven here: scriptlets, signatures, SELinux, fapolicyd, AIDE, and the live hosts' exact package sets (the lab
apply after signing).

**Method note:** dnf's `--repo=` does not filter repos added with `--repofrompath` (seen in this task's first run: the
"0.14.0" build pulled the candidate). `dryroot.sh` therefore defines only the repos each call may use. 13b's
`closure.sh` "cand ONLY" calls had baseos/appstream defined too, so they did not prove "candidate alone" (its host
dry-run did: one repo only).

## Signing tools

- `appliance/release/` unchanged since ff241dc; not re-pushed. aero `tools/` == repo by sha256 for all 22 files
  (`tools-sha-check.log`); aero also holds `RPM-GPG-KEY-Rocky-9`, byte-identical to the DVD's (702D426D350D275D).
- **`test_sign_repo.sh`**: 59 PASS, 0 FAIL, exit 0 (`test_sign_repo.log`).
- **Rehearsal** (`rehearse.sh`/`.log`): sign-repo.sh on the real 0.14.1 stage with a throwaway software key: `REPO OK:
  72 packages`; verify-repo rc 0; onlyoffice re-signed with header `64189290…dc785` kept; Rocky signatures kept
  (702d426d350d275d). Output deleted; stage unchanged vs `stage-sha256.txt`.

## For the owner

`~/go.sh` (copy: `stage-0.14.1-logs/go.sh`) refuses unless the stage holds chp-templates-1.4.0-3 and
chp-onlyoffice-0.1.0-7, exactly 72 RPMs, and its `sha256sum *` list hashes to `789e1455…58009b8a` (= sha256 of
`stage-sha256.txt`), and unless `0.14.1/repo` does not exist yet. Then `sign-session.sh "sign-repo.sh
/data/chp-release/0.14.1/stage /data/chp-release/0.14.1/repo 2DE0…8F8E /data/chp-release/tools"`. Expect `REPO OK: 72
packages` and `sign EXIT=0`. The guard passes on 0.14.1, refuses on 0.14.0's stage, and refuses on an existing repo dir.
