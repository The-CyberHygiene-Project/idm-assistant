# Release record: package repository 0.7.2 (lab candidate for core 0.2.0; not released)

**Date:** 2026-10-16 · **Location:** `aero:/data/chp-release/0.7.2/repo` (lab copy `aero:/data/lab-inputs/chp/0.7.2`) ·
**Audience:** CyberHygiene Project development team only. Released 0.1.0 (repo 0.6.3) and the For Jeff share are unchanged.

**Why 0.7.2 (core 0.2.0 Plan A Task 13, quiet check 2026-10-16; owner decisions in gate form):**
- `chp-site-0.7.1-1.chp`: `chp-site stick-pin-hash` pins the plugged-in, still blocked site stick's USBGuard hash
  (read from `usbguard list-devices`; the stick is never allowed).
- `chp-integrity-0.1.2-1.chp`: `aide-baseline` runs `stick-pin-hash` before `aide --init` (the first stick use no
  longer adds `/etc/chp/site-stick.hash` after the baseline); `!/var/log/audit/audit\.log\.[0-9]+$` (rotated audit
  logs; the live `audit.log` and the directory stay checked). Requires `chp-site >= 0.7.1`.
- Every other package is the same build as in 0.7.1 (re-signed, so sha256 differs); `aide` keeps Rocky's signature.

**Signer:** `2DE0D71BF37D8F5E4201A590521276F43C908F8E` (dedicated YubiKey). Third-party signatures kept: EPEL, Rocky.

## Packages

| Package | Signed by (key ID) | sha256 |
|---|---|---|
| aide-0.19.2-5.el9.x86_64 | 702d426d350d275d | `0788202dd6e95f5c67e34c14e80e24c82f2e95ef1614b371fc7c362811e0e08e` |
| chp-base-0.1.0-3.chp.el9.noarch | 521276f43c908f8e | `748cf47f93ffe56177a78ce05356ad25963dc2a61569ca8786a4dd1fcdb6e8b5` |
| chp-identity-client-0.2.2-1.chp.el9.noarch | 521276f43c908f8e | `bedd994b1b9694bd526a6adcc3b72399b2edc9ec01badffe3229a94a88a7ba71` |
| chp-identity-server-0.1.1-1.chp.el9.noarch | 521276f43c908f8e | `ca984f076393e396be0fc761873841faf5395bfb063964bca1ba8f4780cec5cd` |
| chp-integrity-0.1.2-1.chp.el9.noarch | 521276f43c908f8e | `3e744f17ed37e143beae1d98a394c348b518c3add0921e2b84c7a387ecfd4df0` |
| chp-site-0.7.1-1.chp.el9.noarch | 521276f43c908f8e | `0ebbebfa14a946ccfa902fe9a1101dc0281821b87e5d32062d356a35319728bb` |
| google-authenticator-1.09-5.el9.x86_64 | 8a3872bf3228467c | `0afb54b80b21911bbb645e0a9df49d0544bc7702070c37dc5e6d6ecac3190f14` |
| idm-collect-0.1.0-11.chp.el9.noarch | 521276f43c908f8e | `e4ef4631042fd3b00257b6dc810223ce1be465f60ab56e7094b7cddbec89932f` |
| kanidm-clients-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `53cc1a9ba815d95be2e840dca7a83fd2ad3efcf24c0d97f378f8f438ab7c10e6` |
| kanidm-server-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `e16ba6dfee4df5bae91cc7b712c4dba30c586b0533630eef1be762328da0f76c` |
| kanidm-unixd-1.11.2-2.chp.el9.x86_64 | 521276f43c908f8e | `c26f64eff9b289ce7fddf26b1400f6b25d4f65f1c995ab3604b6839836b85951` |
| step-ca-0.30.2-3.chp.el9.x86_64 | 521276f43c908f8e | `6daaac71fd0dbd3cae2fbfe6ef99930e1bac18f6603e9de436a57dae9441f176` |
| step-cli-0.31.0-2.chp.el9.x86_64 | 521276f43c908f8e | `15727de3e133b616f4be23965620685c842eaf9dab5037aa6b604dafacbb3002` |

Repository metadata: `repomd.xml` `099cf49a4d1467684af7f1e336c4a1e52a1517d0eeb28f80d68084b1e328dffc`, `repomd.xml.asc` `622a9dc48ecf09dc76e17c8207a73ed5dd06b08ffeee5e840ddc6a1ffb1a96e4`.

`verify-repo.sh`: `REPO OK: 13 packages, all signed by pinned keys; repomd.xml signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E`
