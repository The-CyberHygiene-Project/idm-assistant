# Release record: signed repo 0.10.0 = package update 0.5.0-update1 (security bundle part 4: the ISSO's daily security review)

**Date:** 2026-11-09 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.5.0-update1/` and
`…/site-stick-kit-0.5.0-update1/` (earlier folders untouched; the share's `README.md` keeps the 0.5.0 rows and gains
rows for both) · **Audience:** CyberHygiene Project development team. Not an official Rocky Linux product.

**What's new** (spec `docs/superpowers/specs/2026-11-07-security-bundle-review-design.md`, plan
`docs/superpowers/plans/2026-11-07-security-bundle-plan-r1-review.md`): a nightly security review built on the server
for the previous day (intrusions grouped by source address, inside/outside `SUBNET`; security status of every host;
sysstat resources), kept one year and never rebuilt; ISSO sign-off (`chp-site review sign`) into a hash-chained ledger
kept forever, with the ledger head recorded on the site stick at each `review export`; monitor check 75 alerts (review
not built, sign-off overdue > 2 days, ledger check failed, items needing attention, long-lived cert/key within 7 days).
New optional, additive site key **`REVIEW_DELEGATES`**. No new listener or port: status records travel through the
existing Wazuh agent. Also: the deferred YARA alert-grouping fix (two different rules on one host within 15 minutes
both reach `ALERT_HOOK`).

## Packages (28, all signed by pinned keys)

New or changed: `chp-site-0.12.0-3`, `chp-security-0.4.0-2` (monitor 75), `sysstat`, `pcp-libs`, `pcp-conf`,
`lm_sensors-libs` (Rocky 9 AppStream/BaseOS, Rocky key). Unchanged otherwise from 0.9.2.

The repo was signed three times; only the final signing is published. The superseded chp-site 0.12.0-2 signed copy
is kept, never published, at `aero:/data/chp-release/0.10.0/repo-superseded-chp-site-0.12.0-2/`.

## Bytes

| File | sha256 |
|---|---|
| `0.5.0-update1/chp-repo-0.10.0.tar.gz` | `256bd3b1a539d47a6c167017717e0dc89e39438a816e4741e3f814a2796491c8` |
| `0.5.0-update1/UPDATE.md` | `73b0b16e5b1d3362bb53f696390079419b87d7c367863840d86d5d4590275740` |
| `0.5.0-update1/RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.5.0-update1/NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |

**Kit** (`site-stick-kit-0.5.0-update1/`): `SITE-STICK.md` `8de72baa7a442373…` · `site.conf.template` `527963d7824b9939…` ·
`hosts.template` `c20a3d8702ca417e…` · `profile.ini.template` `3a00f51ea489cf78…` · `chp-site.pyz` `6c8f399820c7c90f…`
(reports `chp-site 0.12.0`).

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey;
signature counter 787 → 789) and verified with `gpg --verify` → Good signature.

## Evidence (`lab/security/PROOF-RECORD-R1.md`)

- Proofs on the final packages: `repo`, `enable`, `on`, `build`, `sign`, `tamper`, `export`, `soon`, `reboot`, `res`:
  ALL PASS. Status record ~2 KB per 10 minutes, < 0.1 % CPU.
- Quiet day (2026-11-07 13:22 → 11-08 14:00 MST): the real 00:20 build; the real Sunday weekly YARA scan with 0
  matches; no false monitor 75 alerts; every AIDE change explained. Two report display faults found and fixed
  (chp-site 0.12.0-3).
- Gates: regression **33/33**, row 36 **3/3**, CUI scan **108 pass / 2 fail on every host** (the two accepted AIDE
  rules), Gate 3 met.
- Final whole-branch review: 1 Critical (deleted ledger passed verify) and 12 Important, all fixed TDD. I10 by owner
  option C (server strict at day end; clients "last seen HH:MM").

## Release-day note

`~/go.sh` passed `REPO_V` to `release-repo.sh` only; `release-kit.sh` stopped at its argument check before doing
anything and was re-run with `REPO_V=0.10.0` under the same owner go.

## Known limits (from `UPDATE.md`)

The newest sign-off is protected by the stick only after the next export; root on the server can rewrite the ledger
and its head (the stick's copy catches it); first 10 minutes after enable show disk use only; proved on VMs only.
