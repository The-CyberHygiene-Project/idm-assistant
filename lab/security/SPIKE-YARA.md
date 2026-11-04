# Spike: YARA under FIPS, signature-base compile count, full-scan time (Plan Y1 Task 1, 2026-11-01)

Lab: iso5-srv and iso5-cli2 at the 0.3.0-rc3 golden snapshots (FIPS, SELinux enforcing, fapolicyd, USBGuard, Wazuh on).
Reverted to golden afterwards.

## Package source

- **EPEL 9 has no `yara` package** (checked 2026-11-01). **Rocky 9 AppStream does:** `yara-4.5.2-1.el9.x86_64`,
  signed by the Rocky key that the repo already pins (`702d426d350d275d`), and present on the Rocky 9.8 DVD. It is the
  same YARA version RS#2 runs.
- Dependencies (`libyara.so.10` is in the package; `protobuf-c`, `jansson`, `file-libs`) are already installed on the
  appliance hosts.

## Under FIPS (iso5-cli2, `fips_enabled=1`)

| Check | Result |
|---|---|
| `yara --version` | 4.5.2 |
| EICAR test rule | matches |
| `hash` module md5 / sha1 / sha256 | all work (rule matching only; nothing is protected by these hashes) |
| Crypto library | the system `libcrypto.so.3` (the FIPS-validated OpenSSL), `readelf -d` NEEDED |
| fapolicyd denials / YARA AVCs | 0 / 0 |
| `--define`, `--scan-list`, `--timeout` | present |
| `wazuh-execd` user | root (so a `root:root 0750` active-response script can run) |

`ldd` itself is blocked by fapolicyd on a hardened host (it executes the dynamic loader directly); expected.

## signature-base

- Pinned commit `36ab70428fc5b52701b7ee6107c853ff019ed759` (2026-10-29), tarball sha256
  `f63f2184ba3608876d695b4003b6e198ba129438dbd5aa9cb4b51ff0a86ebbe4` (`lab/inputs/fetch-signature-base.sh`).
- **748 of 748 rule files compile** with plain `yarac` once the externals `filename`, `filepath`, `extension`,
  `filetype` and `owner` are defined (empty). Compiled together: no clashes, 16 MB `rules.yarc`.

## Full scan (every local file system, skipping /proc /sys /dev /run, Wazuh data, the repo; files under 256 MB)

| Host | Files | Time | False alarms | Errors |
|---|---|---|---|---|
| iso5-cli2 | 111,921 | 63 s | **0** | 0 |
| iso5-srv | 112,195 | 64 s | **0** | 1 (a temporary file under `/var/cache/man` gone before it was read) |

Two findings for the design:
1. **The compiled rules file matches about 1,420 of its own rules**, so the full scan must skip
   `/usr/share/chp-yara-rules`.
2. **`yara --timeout` limits the whole run, not each file**: with `--timeout=60` the full scan stopped at 60 s. Single
   file scans keep 60 s; the full scan uses a separate, long limit (6 h).

Settings carried into the plan: `MAX_BYTES` 256 MiB, `TIMEOUT` 60 s (one file), `FULL_TIMEOUT` 21600 s, an empty
`exclude.txt` (no false alarms on a clean appliance), and full-scan errors for files that no longer exist are ignored.
