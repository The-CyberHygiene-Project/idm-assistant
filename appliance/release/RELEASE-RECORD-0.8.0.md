# Release record: signed repo 0.8.0 = package update 0.3.0-update1 (security bundle part 2: YARA)

**Date:** 2026-11-04 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.3.0-update1/` and
`…/site-stick-kit-0.3.0-update1/` (earlier folders untouched; the share's `README.md` gained rows for both) ·
**Audience:** CyberHygiene Project development team. Not an official Rocky Linux product.

**What's new** (spec `docs/superpowers/specs/2026-11-01-security-bundle-yara-design.md`, with the owner's amendments
§10 and §10.1): YARA malware scanning on every host with the security add-on: changed files in the watched folders
every 5 minutes, every local file system weekly, alert only (level-12 Wazuh alert → `ALERT_HOOK`), rules updated by a
monthly signed update (`RULES-UPDATE.md`). Wazuh file monitoring and active response stay off.

## Packages (19, all signed by pinned keys)

New or changed: `chp-site-0.10.0-2`, `chp-security-0.2.0-2`, `chp-yara-rules-2026.10.29-1` (Neo23x0 signature-base
`36ab70428fc5b52701b7ee6107c853ff019ed759`, 748 rule files compiled, 0 skipped; DRL 1.1), `yara-4.5.2-1.el9` (Rocky
AppStream, Rocky key), `chp-identity-server-0.1.2-2`. Unchanged from 0.7.9: aide, chp-base, chp-identity-client 0.2.4,
chp-integrity 0.1.7, chp-templates 1.2.0, google-authenticator, idm-collect, kanidm 1.11.2, step-ca, step-cli, Wazuh
4.14.9 manager and agent.

## Bytes

| File | sha256 |
|---|---|
| `0.3.0-update1/chp-repo-0.8.0.tar.gz` | `0c8edbbbc64ad9fefd1211cdf6a5a41123dc5aba89ed45dae40c2230a3025d67` |
| `0.3.0-update1/UPDATE.md` | `6dab186426e652adf0427c35780448a1c13ea2fba491de2a55518f6d63b6d02d` |
| `0.3.0-update1/RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.3.0-update1/NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |

**Kit** (`site-stick-kit-0.3.0-update1/`): `SITE-STICK.md` `ad6eafa5cdb259ea…` · `site.conf.template` `0d2e3700e92640f1…` ·
`hosts.template` `c20a3d8702ca417e…` · `profile.ini.template` `3a00f51ea489cf78…` · `chp-site.pyz` `c934e931ef9fd7ba…`
(reports `chp-site 0.10.0`).

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey) and
verified with `gpg --verify` → Good signature.

## Evidence (`lab/security/PROOF-RECORD-Y1.md`, `lab/security/SPIKE-YARA.md`)

- Spike: YARA under FIPS (system OpenSSL), 748/748 rule files compile, full scan ~1 min, 0 false alarms.
- Proofs 1–3 (enable, catch incl. odd file names, weekly scan): ALL PASS on the final packages; proof 4 quiet day: no
  false alarms, AIDE changes all explained.
- Gates on repo 0.8.0: regression 33/33, row 36 3/3, CUI scan 108/2 (the two accepted AIDE rules).
- Final review (fresh reviewer): 2 Critical and 4 Important findings fixed before release (file names that are not
  UTF-8 or contain a line break, failed runs recorded as success, no monitor for the 5-minute scan, `/run/user`, unit
  time limits).

## Known limits

- A new file waits up to 5 minutes before it is scanned (Wazuh's file-triggered response did not work on the lab).
- Proved on VMs only; a fresh install with YARA at install time is ISO 0.4.0's job.
- Deferred minors: see the PR.
