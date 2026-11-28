# Proof record: package update 0.7.0-update1 (candidate repo 0.15.0)

**Date:** 2026-11-28 · **Lab:** the 0.7.0 ISO proof VMs (iso5-srv and cli2), upgraded in place with `rpm -U` from the
UNSIGNED packages (signature checking by dnf is not covered by this proof). **VMs only.**

## Packages

Stage `aero:/data/chp-release/0.15.0/stage`: 72 RPMs + `modules.yaml`; 71 of the 73 files are byte-identical to the
0.14.1 stage. `sha256sum *` list digest `31d0f8ce76965f5e747809592424459112157815b91c8e3f3655aafd1d5d2024`.

| Package | sha256 |
|---|---|
| chp-site-0.14.0-14.chp.el9.noarch | `6bc12f9b69bf37830dfc511714845ab42cdad17d9a4c4ca5e78df242d73d72b5` |
| chp-templates-1.4.0-4.chp.el9.noarch | `e52ef7b23f040a453ea740e60f69f6725efe0ddc1c64b5ff582b964fb7cb4e52` |

`chp-templates` was built from the signed templates 1.4.0 release (Good signature; tarball sha256
`9798631987063dabd68cd766ee69e132e7313664a7647fafe7428ad8b9535df9`). Test suite: 2622 passed.

## Results

| Proof | Result |
|---|---|
| `rpm -U --test`, srv and cli2 | rc 0 |
| P3-D16 before (chp-site 0.14.0-12), 2000-byte override reason | **reproduced**: rule 100643 level 12 with raw `$(dstuser)`, `$(path)` |
| P3-D16 after (0.14.0-13), 2000 and 12 bytes | **PASS**: user and path expanded; long reason ends `…[truncated; full text in the ledger]` |
| `config.php` false alert before | **found**: `chp-documents-check.service` failed 11-25 to 11-28 on this fresh install |
| Cause | enable pins `config.php` (2463 bytes); the nightly backup's `maintenance:mode` leaves `'maintenance' => false` (2489 bytes). Removing that line gives the pinned sha256 exactly. fapolicyd `integrity = none`, so NextCloud kept working |
| After (0.14.0-14): real backup, then real nightly check | **PASS**: check rc 0, OK, no trust alert; no failed units (DEGRADED MD5 is the known T-08) |
| Other changes to `config.php` still alert | unit tests only (maintenance `true`, an extra key, a doubled line) |
| AIDE after the upgrade | new entries: chp-site files and three RPM-GPG keys (both hosts); `/usr/share/chp-templates/` and its licence (cli2). The update note lists these |

The ledger journal line for P3-D16 was sent as a synthetic override record through the installed `journal()`; no ledger
entry was written. The alert test's records (paths `PROOF-D16-*`) remain in the lab's Wazuh alerts. The P3-D16 proof
ran on 0.14.0-13; 0.14.0-14 does not change that code.

Not run: a fresh install, the regression gate, `dnf upgrade` from the signed repo.
