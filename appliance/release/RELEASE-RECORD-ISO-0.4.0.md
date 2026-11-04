# Release record: CyberHygiene Project Lab Installer ISO 0.4.0

**Date:** 2026-11-04 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.4.0/` and `…/site-stick-kit-0.4.0/`
(earlier folders untouched; the share's `README.md` gained rows for both) · **Audience:** CyberHygiene Project
development team. Not an official Rocky Linux product.

**What's new:** YARA malware scanning at install time. With `SECURITY_ADDONS=yes`, first boot's `security enable`
installs Wazuh, YARA and the signature-base rules and starts the 5-minute and weekly scan timers on every host (spec
`docs/superpowers/specs/2026-11-01-security-bundle-yara-design.md`, §10–§10.1). Same packages as 0.3.0-update1 (repo
0.8.0; `RELEASE-RECORD-0.8.0.md`); a 0.3.0 site applies update 1 instead of reinstalling.

## Bytes

| File | sha256 |
|---|---|
| `cyberhygiene-lab-installer-el9.iso` (= **0.4.0-rc1**, the tested bytes) | `8ca0b90ab9185cf1f37ab4a02d069a3c410e5bc558a11553fc320de64f4bd52d` |
| `chp-repo-0.8.0.tar.gz` | `0c8edbbbc64ad9fefd1211cdf6a5a41123dc5aba89ed45dae40c2230a3025d67` |
| `RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |
| `VERIFY.md` | `b04aa3f6c92cf38c2c3798ca1ca6ed8e8fd4ec619af86a955ef174bf31904764` |
| `UPGRADE-FROM-0.1.0.md` | `b819466d87d644d2cf6913bd9f8d74864eaa16ff98fcac669f17b50ca720ce3c` |

**Kit** (`site-stick-kit-0.4.0/`): `SITE-STICK.md` `9cdc26f72568257b…` · `site.conf.template` `0d2e3700e92640f1…` ·
`hosts.template` `c20a3d8702ca417e…` · `profile.ini.template` `3a00f51ea489cf78…` · `chp-site.pyz` `c934e931ef9fd7ba…`
(reports `chp-site 0.10.0`).

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey) and
verified with `gpg --verify` → Good signature.

## Gates (evidence in `lab/security/PROOF-RECORD-ISO-0.4.0.md`)

1. **Install from nothing:** rc1 on all three hosts with `SECURITY_ADDONS=yes`: every stage passed; YARA up at first
   boot, test files caught (including odd file names), weekly scan 111,931 files in 67 s.
2. **Regression:** 33/33 with Wazuh and YARA running (`lab/iso5/regression-2026-11-04.md`), plus row 36 ×3.
3. **CUI scan:** 108 pass and 2 fail on every host, the two accepted AIDE deviations (`lab/iso5/DEVIATIONS.md`).

## Known limits

- POA&M: Wazuh's bundled OpenSSL is outside the FIPS-validated module; Wazuh runs unconfined.
- A new file waits up to 5 minutes before it is scanned.
- Clients added after the server's first boot need the manual `security enable` path.
- Proved on VMs only; the real-hardware test is dc2.
