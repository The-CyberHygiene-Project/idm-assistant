# chp-build: the dedicated RPM build VM (ISO 0.7.0, owner decision 4)

A Rocky 9.8 minimal VM on the lab hypervisor aero, used only to build RPMs that contain PHP/JS content (NextCloud).
Why: aero's fapolicyd denies reading untrusted PHP/JS, so rpmbuild's `%install` cannot run on aero, and the Mac's
Homebrew rpmbuild is not an EL9 toolchain. aero's own fapolicyd is NOT changed. The VM has no fapolicyd, SELinux enforcing.

- Name `chp-build`; 4 GiB, 2 vCPU, 60 GB sparse qcow2 `/data/libvirt/images/chp-build.qcow2`; autostart.
- Not a lab host: not `iso5-*`, intentionally outside every site hosts table. Static 192.168.100.60 on `br-lab`.
  Isolation: the PRIMARY control is that `ks.cfg` configures no gateway and no DNS, so the VM has no route off
  192.168.100.0/24. Backstop (host state, not set by this change): aero `net.ipv4.ip_forward = 0`. Packages come from the DVD; sources are copied in from the Mac after
  `lab/docs-spike/fetch-inputs.sh`-style verification (sha256 vs MANIFEST checked before copy), e.g.
  `scp -F lab/build-vm/ssh_config FILE chp-build:rpmbuild/SOURCES/` (mkdir `~/rpmbuild/{SOURCES,SPECS}` first).
- Packages: rpm-build, rpmdevtools, tar, bzip2, gzip.
- It NEVER holds signing keys. Built RPMs are copied back to aero and signed there with `appliance/release/sign-session.sh`.

- RAM: 4 GiB for the VM against about 5 GB free on aero with all five iso5 lab VMs up; stop the VM (`virsh shutdown chp-build`) when not building.
- Time: no time source (chronyd has nothing to sync to; aero lists no NTP sources either), so build timestamps come from the host clock via libvirt/RTC and may drift.

## Use
`ssh -F lab/build-vm/ssh_config chp-build` (user `builder`, key `~/idm-lab-secrets/chp_build_ed25519`, via aero; passwordless
sudo). Copy sources to `~/rpmbuild/SOURCES`, spec to `SPECS`, run `rpmbuild -bb --define "dist .el9" ...`, fetch from
`~/rpmbuild/RPMS/noarch/`.

## Rebuild
1. Mac: `ssh-keygen -t ed25519 -N '' -f ~/idm-lab-secrets/chp_build_ed25519` (once).
2. Mac: `sed "s|@PUBKEY@|$(cat ~/idm-lab-secrets/chp_build_ed25519.pub)|" lab/build-vm/ks.cfg > /tmp/ks.cfg`; scp it and `create.sh` to aero.
3. aero: `sudo bash create.sh /tmp/ks.cfg` (refuses if chp-build or its disk exists; add `--force` to delete it and rebuild from scratch) (installs from `/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso`, ~10 min, detaches the DVD, starts).

## Isolation check (run 2026-11-13, read-only)
- aero: `sysctl net.ipv4.ip_forward` -> `net.ipv4.ip_forward = 0`
- VM: `ip route` -> only `192.168.100.0/24 dev enp1s0 ... src 192.168.100.60` (no default route)
- VM: `bash -c 'echo > /dev/tcp/1.1.1.1/443'` -> `Network is unreachable` (outbound connect failed)
- VM: `timedatectl` -> `System clock synchronized: no`

## Proof (2026-11-13)
Built `lab/docs-spike/nextcloud.spec` (spike5) on chp-build with native rpm 4.16.1.3 and `--define "dist .el9"`:
`nextcloud-chp-35.0.3-0.spike5.el9.noarch.rpm`, 33,896 files, Size 832,339,150, `linux noarch zstd`, Build Host chp-build,
sha256 bb99c2f1a38bf7a7e088c9622191db33972926cd6092f9e9d334965a3cee3955 (unsigned). EL9-compatible (native EL9 rpm; rpm 4.16 format).
