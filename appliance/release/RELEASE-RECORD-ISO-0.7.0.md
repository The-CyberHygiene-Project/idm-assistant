# Release record: ISO 0.7.0 with signed repo 0.14.1

**Date:** 2026-11-25 · **Published to:** `For Jeff/cyberhygiene-lab-installer/0.7.0/` and `…/site-stick-kit-0.7.0/`
(earlier folders untouched; the share's `README.md` gains rows for both) · **Audience:** CyberHygiene Project
development team. Not an official Rocky Linux product.

**What's new:**
- **Controlled-document workflow.** Check out, approve and publish documents through NextCloud and ONLYOFFICE
  Desktop, with sign-in through Kanidm. Every step is a record in a hash-chained ledger watched by Wazuh (rules
  100633 to 100656, monitor checks 81, 82, 83 and 20). Undo and unfinished-step records, quarantine, and
  idempotent requests are included. Workstations use `chp-site doc`.
- **Marking checks** for CUI and FCI documents (docx, xlsx, md, pdf): required banner, name rule, citations.
  FCI templates ship in `chp-templates` (a pre-release lab build; see known issues).
- **Time sync from the server only.** Workstations take time from the site server; the server serves its subnet.
  Monitor check 20.
- **ISSO daily review** shows document-workflow overrides under "Needs attention".
- **Nightly NextCloud backup** with bounded runtime and a clear FAILED record; restore failure handling.
- **Server OpenSCAP tailoring file** ships in `chp-identity-server` (not yet wired into the kickstart).

## Packages

Repo 0.14.1: 72 packages, all signed by pinned keys. Changed from the 0.14.0 signed repo: seven packages (final-review
fixes, the lockdown-recovery alert, the backup and restore hang fix, `chp-templates` 1.4.0-3).

## Bytes

| File | sha256 |
|---|---|
| `0.7.0/cyberhygiene-lab-installer-el9.iso` (rc1, tested bytes) | `eed5f77eeec452b9723f1017996355900afa08ee83a8d922405db2b808aa9f17` |
| `0.7.0//Volumes/For` | `7c0b4ae6a2ffec548a365dfa6703e87c795d8f72c7acc3365f454669f8d3be82` |
| `0.7.0//Volumes/For` | `87081ccd47855109ec284bd0ddadf4efc3804cd994d9981de01818df069625c1` |
| `0.7.0//Volumes/For` | `f2c24c9b248a5aae3bad4f257128087212e05a7a23ddcf5f0406521b98dd3d3f` |
| `0.7.0//Volumes/For` | `dafb2da89c3a9dcb8ef2b8597b6cb07b6529d776fd9af128814ae05d364eb7b6` |

**Signatures:** both `SHA256SUMS.asc` (ISO folder and kit folder) made with `2DE0D71BF37D8F5E4201A590521276F43C908F8E`
(the YubiKey) and verified → Good signature. The ISO was copied from aero and its hash checked against the tested rc1
before signing.

## Evidence

`lab/docs-proof/PROOF-RECORD-PLAN3.md` (rounds 1 to 3 on the repo) and `lab/security/PROOF-RECORD-ISO-0.7.0.md`
(rc1): fresh install of server and both workstations from the ISO; first-ever documents enable on a server that never
had NextCloud (D1) passed in one run with 0 fapolicyd denials; CUI and FCI documents end to end (new, approve, publish,
then checkout, approve, publish); CUI scan server 107/3 and workstations 108/2 (server row accepted by the owner);
row 36 3/3; regression 33/33; golden restore.

## Known issues (carried to 0.7.1)

- `chp-templates` 1.4.0-3 is a lab candidate: pinned by sha256, no signed source release. A signed release (1.4.0-4 or
  higher) follows.
- The server OpenSCAP tailoring file is not yet applied by the kickstart.
- P3-D16: an ISSO override reason of about 2,000 bytes leaves the level-12 alert text unexpanded (alert still fires).
- P3-D6: the web server's body-size limit on the ledger route is not enforced; the app's 64 MiB check is the control.
- POA&M seed rows T-08 to T-16 carry NIST requirement numbers marked pending owner confirmation.
- Full list: `docs/release/0.7.0-known-issues.md`.
