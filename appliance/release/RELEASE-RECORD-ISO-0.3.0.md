# Release record: CyberHygiene Project Lab Installer ISO 0.3.0

**Date:** 2026-11-01 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.3.0/` and `…/site-stick-kit-0.3.0/`
(earlier folders untouched; the share's `README.md` gained rows for both) · **Audience:** CyberHygiene Project
development team. Not an official Rocky Linux product.

**What's new:** the optional security add-on at install time: Wazuh 4.14.9 (spec
`docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md`, plan W2, requirement row 51):
- site keys `SECURITY_ADDONS` (yes/no, default no) and `SECURITY_ALERT_LEVEL` (3–15, default 10);
- the server installs the manager at first boot and writes one agent key per client; `export-client` moves them to the
  site stick;
- each client installs its agent from the ISO's repo at first boot, with its pre-made key, and waits for its first sync;
- with `SECURITY_ADDONS=no`, 0.3.0 installs exactly as 0.2.0 did.

A 0.2.0 site does not reinstall: `0.2.0-update4/` already gives it Wazuh. A 0.1.0 site: `0.3.0/UPGRADE-FROM-0.1.0.md`.

## Bytes

| File | sha256 |
|---|---|
| `cyberhygiene-lab-installer-el9.iso` (= **0.3.0-rc3**, the tested bytes) | `de69d364cf26f91e01977dc0cad0992319a87a90b331c10179d8c3c21f05c393` |
| `chp-repo-0.7.9.tar.gz` | `0017170b9fa406f6048f17b6de011ea43e9605f06f28c87bcd02af2684d1fd35` |
| `RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |
| `VERIFY.md` | `dc1913f0eef800facc1dfe9e0d8b7711ce74617f45451506c17452689f5ccf7d` |
| `UPGRADE-FROM-0.1.0.md` | `0933e09f1bd3fe2c361328d1450b71d5f748088509f160e1e39134b002fe324a` |

**Kit** (`site-stick-kit-0.3.0/`): `SITE-STICK.md` `ef113df1afe02296…` · `site.conf.template` `0d2e3700e92640f1…` ·
`hosts.template` `c20a3d8702ca417e…` · `profile.ini.template` `3a00f51ea489cf78…` · `chp-site.pyz` `82e8ad3ead426885…`
(reports `chp-site 0.9.0`).

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey) and
verified with `gpg --verify` → Good signature. Repo 0.7.9: 17 packages, including `chp-site-0.9.0-3`,
`chp-identity-server-0.1.2`, `chp-identity-client-0.2.4`, `chp-integrity-0.1.7`, `chp-security-0.1.0` and Wazuh 4.14.9
manager and agent (Wazuh's own signed packages, key pinned).

## Gates (evidence in `lab/security/PROOF-RECORD-W2.md`)

1. **Install from nothing:** rc3 on all three hosts with `SECURITY_ADDONS=yes`: 120/120 install checks, 28/28 Wazuh
   checks. The off case (`SECURITY_ADDONS=no`) was proved on rc1. Resources over 24 h on rc2: manager about 560 MB, agents
   under 50 MB, no restarts.
2. **Regression:** 33/33 with Wazuh running (`lab/iso5/regression-2026-10-31.md`), plus row 36 ×3.
3. **CUI scan:** 108 pass and 2 fail on every host, the same 2 AIDE deviations accepted for 0.2.0
   (`lab/iso5/DEVIATIONS.md`).

rc1 failed the first daily AIDE check (Wazuh's shared files arrive after the baseline): fixed in chp-integrity 0.1.7 and
chp-site 0.9.0-2 (rc2). The final review's I1 (a failed client step could not be retried) was fixed in chp-site 0.9.0-3
(rc3).

## Known limits

- **POA&M:** Wazuh's bundled OpenSSL 3.5.1 is outside the FIPS-validated module; Wazuh runs unconfined.
- **Proved on VMs only.**
- **Clients added after the server's first boot** need the manual `security enable` path (W1).
- **`kanidm-login.exp`** (chp-identity-server) can lose the password to a prompt race; it runs only at server first
  boot inside a five-try retry. The fix ships in the next update (owner decision, 2026-11-01).
