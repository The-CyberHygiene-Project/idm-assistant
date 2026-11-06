# Release record: signed repo 0.9.0 = package update 0.4.0-update1 (security bundle part 3: Suricata)

**Date:** 2026-11-06 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.4.0-update1/` and
`…/site-stick-kit-0.4.0-update1/` (earlier folders untouched; the share's `README.md` keeps the 0.4.0 rows and gains
rows for both) · **Audience:** CyberHygiene Project development team. Not an official Rocky Linux product.

**What's new** (spec `docs/superpowers/specs/2026-11-04-security-bundle-suricata-design.md`, plan
`docs/superpowers/plans/2026-11-04-security-bundle-plan-s1-suricata.md`): Suricata network intrusion detection on every
host with the security add-on: each host watches its own site interface, HOME_NET = `SUBNET`, **IDS only (nothing is
blocked)**, alerts to `/var/log/suricata/eve.json` and the Wazuh manager; severity 1 → level 12 (`ALERT_HOOK`),
severity 2 → level 7 (daily summary). ET Open rules in a signed package, updated monthly (`RULES-UPDATE.md`). Monitor
check 74. Logs kept for `RETENTION_DAYS`.

## Packages (24, all signed by pinned keys)

New or changed: `chp-site-0.11.0-3` (ships the pinned EPEL 9 key; `security enable` installs and configures Suricata;
per-signature alert grouping), `chp-security-0.3.0-3` (monitor 74), `chp-suricata-rules-2026.11.04-1` (ET Open
2026.11.04, sha256 `1fa39a90…f0eabb`, 52,859 rules, 0 disabled; GPLv2 and BSD), `suricata-7.0.17-1.el9`, `hiredis-1.0.2-2.el9`,
`hyperscan-5.4.1-2.el9` (EPEL 9, EPEL key), `libnetfilter_queue-1.0.5-1.el9` (Rocky 9.8 AppStream, Rocky key).
Unchanged from 0.8.0: aide, chp-base, chp-identity-client 0.2.4, chp-identity-server 0.1.2-2, chp-integrity 0.1.7,
chp-templates 1.2.0, chp-yara-rules 2026.10.29, google-authenticator, idm-collect, kanidm 1.11.2, step-ca, step-cli,
yara 4.5.2, Wazuh 4.14.9 manager and agent.

`chp-security` deliberately does not require `suricata`: `dnf upgrade` would pull the EPEL-signed package before
`security enable` has imported the EPEL key (found on the lab, fixed before release).

## Bytes

| File | sha256 |
|---|---|
| `0.4.0-update1/chp-repo-0.9.0.tar.gz` | `949b6b51009aa90a0ea6fb37b9a488aa40a598942055af12dbdc6a58d3747f2b` |
| `0.4.0-update1/UPDATE.md` | `66135cbe6191fc84b535a9851db4150220d816e19a93b555a553fa627c356ab4` |
| `0.4.0-update1/RPM-GPG-KEY-cyberhygiene` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.4.0-update1/NOTICE.txt` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |

**Kit** (`site-stick-kit-0.4.0-update1/`): `SITE-STICK.md` `e8f75fb9b0a05129…` · `site.conf.template` `0d2e3700e92640f1…` ·
`hosts.template` `c20a3d8702ca417e…` · `profile.ini.template` `3a00f51ea489cf78…` · `chp-site.pyz` `4c818b6cd48bf2f1…`
(reports `chp-site 0.11.0`).

**Signatures:** both `SHA256SUMS.asc` were made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (the YubiKey) and
verified with `gpg --verify` → Good signature.

## Evidence (`lab/security/PROOF-RECORD-S1.md`, `lab/security/SPIKE-SURICATA.md`)

- Spike: Suricata under FIPS, SELinux enforcing and fapolicyd: no crypto library linked, 0 AVCs, 0 denials; 52,859 ET
  Open rules load; ~16 h clean day with 0 alerts.
- Proofs on the final packages: upgrade + `enable` re-run, `on` (36 checks), `catch` (SID 2017025 → level 12 on both
  hosts → hook), `reboot` (cold reboot of both hosts), `res`: ALL PASS. Quiet day (24 h 23 min): 0 alerts, RSS flat at
  ~500 MB, < 1 % CPU, 0 drops; AIDE changes all explained.
- Gates: regression **33/33**, row 36 **3/3**, CUI scan **108 pass / 2 fail on every host** (the two accepted AIDE
  rules), Gate 3 met.
- Final whole-branch review: 0 Critical; 3 Important fixed or proved (monitor 74 false drop alerts after a restart;
  per-signature alert grouping; the reboot proof); minor fixes folded in. Ruling M-4: Suricata's default memcaps and
  threads kept (memory flat over 24 h).

## Known limits (from `UPDATE.md`)

Each host sees only its own traffic; encrypted payloads are not inspected; ~500 MB memory per host; Suricata runs
`unconfined_service_t` (no EPEL policy); proved on VMs only.
