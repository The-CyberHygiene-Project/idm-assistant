# step-ca 0.30.2-2.chp / step-cli 0.31.0-2.chp build record (ISO Plan 1 Task 7)

**Date:** 2026-09-29 · **Builder:** build1 (Rocky 9.8, FIPS mode, SELinux enforcing), VM on aero, lab bridge only.
fapolicyd was **permissive** for this build (ISSO-approved 2026-09-29), then **reverted** (`permissive = 0`, restart and
reboot) and build1 was shut down.

## Inputs (pinned in `appliance/inputs/MANIFEST.txt`, re-verified on build1: 5 × OK)
- `step-ca-0.30.2.tar.gz`, `step-cli-0.31.0.tar.gz`: GitHub tag archives, sha256 pinned on first fetch
- `step-ca-0.30.2-vendor.tar.gz`, `step-cli-0.31.0-vendor.tar.gz`: `go mod verify` (go.sum) and then `go mod vendor`
- `go1.26.8.linux-amd64.tar.gz`: sha256 equals go.dev's published value. The go.mod files ask for Go >= 1.26.0.

## Toolchain and flags
- `go1.26.8`, `GOTOOLCHAIN=local`, `GOFLAGS=-mod=vendor`, `GOPROXY=off`, `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w -X main.Version -X main.BuildTime"`
- `GOFIPS140=v1.0.0`. The toolchain's `lib/fips140` holds `v1.0.0-c2097c7c.zip`, `v1.0.0.txt` and `v1.26.0.zip`; `v1.0.0`
  resolves to the frozen **Go Cryptographic Module v1.0.0** snapshot.
- `go version -m step-ca` shows `GOFIPS140=v1.0.0-c2097c7c` and
  `DefaultGODEBUG=cryptocustomrand=1,fips140=on,tlssecpmlkem=0,urlstrictcolons=0`, so FIPS 140-3 mode is the binary's
  default, and the unit also sets `GODEBUG=fips140=on` explicitly (row 13). The frozen module also turns off the hybrid
  ML-KEM TLS key exchange by default (`tlssecpmlkem=0`).

## Smoke test (`smoke.sh`, before packaging)
A throwaway CA was initialised on loopback, started with `GODEBUG=fips140=on`, passed its health check, and issued one
certificate through the JWK provisioner: **SMOKE OK**. (The first run failed only because the test CA's certificate had
no `127.0.0.1` SAN; `smoke.sh` now adds it.)

## Binaries
```
06027c20fe70e7b3b4e246227771570553f940e62844dd4cc604f2f3ac86b7c3  step-ca
80a65b305f7f1cadd25c6da144e5309b5cca5444d65f453305117c849ff9b308  step-cli
```

## Packages (unsigned here; signed in Task 8)
| RPM | sha256 |
|---|---|
| step-ca-0.30.2-2.chp.el9.x86_64.rpm | `4def74b769165e2fb3f1f6b269cdef8a9d14fe7900117a2d42818a304069dc1c` |
| step-cli-0.31.0-2.chp.el9.x86_64.rpm | `c4a1e1ca9b7bf43cbb7f06ce08d9bfe12dcd64d6b796738b2ae61051521918e9` |

`check-step.sh`: all 11 checks OK (`STEP RPMS OK`). They cover the Go version and frozen FIPS module in the build info,
the reported versions, the `step → step-cli` symlink, `GODEBUG=fips140=on` in the unit (and never `fips140=only` in
an `Environment=` line), the sysusers entry for `step`, the licence files, and that nothing lab-specific is inside. The
paths match the upstream RPMs the lab used (`/usr/bin/step-ca`, `/usr/bin/step-cli`, `/usr/bin/step`). The unit ships
**disabled**; the identity-server role enables it.

Not established here: CMVP status of the Go Cryptographic Module v1.0.0 (see `appliance/release/CMVP-STATUS.md`).
