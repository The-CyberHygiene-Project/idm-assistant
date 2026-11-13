# chp-build: the dedicated RPM build VM (ISO 0.7.0, owner decision 4)

A Rocky 9.8 minimal VM on the lab hypervisor aero, used only to build RPMs that contain PHP/JS content (NextCloud).
Why: aero's fapolicyd denies reading untrusted PHP/JS, so rpmbuild's `%install` cannot run on aero, and the Mac's
Homebrew rpmbuild is not an EL9 toolchain. aero's own fapolicyd is NOT changed. The VM has no fapolicyd, SELinux enforcing.

- Name `chp-build`; 4 GiB, 2 vCPU, 60 GB sparse qcow2 `/data/libvirt/images/chp-build.qcow2`; autostart.
- Not a lab host: not `iso5-*`, not in any site hosts table. Static 192.168.100.60 on `br-lab`, which has no route out
  (ip_forward=0): the VM cannot reach the internet. Packages come from the DVD; sources are copied in from the Mac after
  `lab/docs-spike/fetch-inputs.sh`-style verification (sha256 vs MANIFEST checked before copy).
- Packages: rpm-build, rpmdevtools, tar, bzip2, gzip.
- It NEVER holds signing keys. Built RPMs are copied back to aero and signed there with `appliance/release/sign-session.sh`.

## Use
`ssh -F lab/build-vm/ssh_config chp-build` (user `builder`, key `~/idm-lab-secrets/chp_build_ed25519`, via aero; passwordless
sudo). Copy sources to `~/rpmbuild/SOURCES`, spec to `SPECS`, run `rpmbuild -bb --define "dist .el9" ...`, fetch from
`~/rpmbuild/RPMS/noarch/`.

## Rebuild
1. Mac: `ssh-keygen -t ed25519 -N '' -f ~/idm-lab-secrets/chp_build_ed25519` (once).
2. Mac: `sed "s|@PUBKEY@|$(cat ~/idm-lab-secrets/chp_build_ed25519.pub)|" lab/build-vm/ks.cfg > /tmp/ks.cfg`; scp it and `create.sh` to aero.
3. aero: `sudo bash create.sh /tmp/ks.cfg` (installs from `/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso`, ~10 min, detaches the DVD, starts).

## Proof (2026-11-13)
Built `lab/docs-spike/nextcloud.spec` (spike5) on chp-build with native rpm 4.16.1.3 and `--define "dist .el9"`:
`nextcloud-chp-35.0.3-0.spike5.el9.noarch.rpm`, 33,896 files, Size 832,339,150, `linux noarch zstd`, Build Host chp-build,
sha256 bb99c2f1a38bf7a7e088c9622191db33972926cd6092f9e9d334965a3cee3955 (unsigned). EL9-compatible (native EL9 rpm; rpm 4.16 format).
