# Release record: ISO 0.5.0 (Suricata at install) and site-stick kit 0.5.0

**Date:** 2026-11-07 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.5.0/` and `…/site-stick-kit-0.5.0/`
(earlier folders untouched; the share's `README.md` gained rows for both) · **Audience:** CyberHygiene Project
development team. Not an official Rocky Linux product.

**What's new:** with `SECURITY_ADDONS=yes`, a 0.5.0 install turns on the whole security add-on at first boot: Wazuh,
YARA malware scanning and **Suricata network intrusion detection** (IDS only, each host on its own interface). The ISO's
signed repo **0.9.2** also carries `chp-templates` 1.3.1 (Rev 2 narratives for YARA and Suricata, for `chp-site docs`)
and `chp-site` 0.11.0-4, which stops the weekly YARA scan from reporting the Suricata rules file.

**Known issue for 0.4.0-update1 sites (owner ruling, option B: no separate update):** the weekly YARA scan reports
`/usr/share/chp-suricata-rules/chp-suricata.rules` (a false alarm, level 12) every Sunday on hosts with both add-ons.
Dismiss it, or upgrade `chp-site` from the 0.5.0 repo tarball (`VERIFY.md` §5). Stated in the kit guide and the share
README.

## Packages (repo 0.9.2, 24, all signed by pinned keys)

Changed from 0.9.0 (0.4.0-update1): `chp-site-0.11.0-4` (weekly YARA scan skips `/usr/share/chp-suricata-rules`),
`chp-templates-1.3.1-1` (from the signed templates-1.3.1 tarball, sha256 `73682cfc…f5a5df`; Rev 2 content 1.2.3).
Everything else as 0.9.0 (`RELEASE-RECORD-0.9.0.md`).

## Bytes

| File | sha256 |
|---|---|
| `0.5.0/cyberhygiene-lab-installer-el9.iso` (= tested 0.5.0-rc2) | `32b6d4b61b8c7a48084401c855a23b9a62361a7fa9e39716f50c2b958c3aba21` |
| `0.5.0/chp-repo-0.9.2.tar.gz` | `b39595e9a094b0ae816e074d369d18de76f3a35cfd6358ac991251fcf61a7925` |
| `0.5.0/VERIFY.md` | `fee563df67f066bf79a07074c79ca0246161bf0db983c6a8de0dcf7833b92d6e` |
| `0.5.0/UPGRADE-FROM-0.1.0.md` | `9d32760a59531e7d9ba7f8500b26dace51c83b611c28024e6d2d424adabb3b53` |
| `0.5.0/RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.5.0/NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |

**Kit** (`site-stick-kit-0.5.0/`): `SITE-STICK.md` `17ed109c1fe43baf…` · `chp-site.pyz` `ff627adc343554e7…` (reports
`chp-site 0.11.0`); the three templates as 0.4.0-update1.

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey) and
verified with `gpg --verify` → Good signature.

## Evidence (`lab/security/PROOF-RECORD-ISO-0.5.0.md`)

- rc2 fresh install of all three hosts with the add-on on: install, Wazuh, YARA (`fresh`, `catch`, weekly scan: the test
  file is the only match), Suricata (`fresh` with all 36 `on` checks, `catch` → level 12 → hook, cold `reboot`, `res`):
  ALL PASS.
- Gates: CUI scan **108/2** on every host (Gate 3 met); regression **33/33**; row 36 **3/3**.
- rc1 found the Suricata-rules false alarm in YARA's weekly scan; fixed and proved before rc2.
