# Spike: 2 TB sparse install, size guard, mount options, auditd (ISO 0.6.0 plan, Task 1)

Run 2026-11-09 on `aero` with the released 0.5.0 ISO (rc2, sha256 `32b6d4b6...aba21`, checked on aero), server
install through the existing `lab/iso5/prove.sh server` stage, one disk of `DISK_GB=1863` (about 2.0 TB virtual,
sparse qcow2), `size-guard.sh` at the 50 GB owner limit. iso5-cli1 and iso5-cli2 were not touched.

## Result in one line

A 2 TB sparse disk installs and runs in about 10 GB of real space on aero. The guard never tripped.

## Size of the image file on aero (actual allocation, `du -B1M`)

| Point | Site add-ons off | Site add-ons on (Wazuh + Suricata + YARA) |
|---|---|---|
| Installed, first boot unlocked | 8,681 MB | 9,316 MB |
| First boot finished (`firstboot` stage ALL PASS) | 8,727 MB | 10,529 MB |
| After `security enable` | n/a (no-op when off) | `security enable` ran inside first boot: 10,529 MB; 10,531 MB after a reboot |

Limit 50 GB, so the largest figure is about 21 percent of the limit. Virtual size 2 TB, apparent file size is small
because qcow2 is sparse. With add-ons on, `/var/ossec` was 1.2 GB. No internal snapshots exist on the new image
(`qemu-img snapshot -l` is empty), so the old golden snapshots are gone as warned.

Layout seen on the server: `/` (root) grew into the whole disk (1.76 TB, 18-19 GB used); home 10 GB, tmp 4 GB,
var 20 GB, var_log 8 GB, var_log_audit 8 GB, var_tmp 4 GB, swap 8 GB.

## Size guard

`lab/iso5/size-guard.sh NAME LIMIT_GB`, started by `install-iso.sh` as `systemd-run --unit=size-guard-NAME` when
`DISK_GB` is above 120 (limit `GUARD_GB`, default 50). `install-iso.sh` refuses to install when the unit is not
active, and refuses `DISK_GB` above 120 with more than one disk. Self-test on a scratch image
(`iso5-guardtest-1.qcow2`, 2 TB virtual, limit 1 GB, 2.5 GB written with `qemu-io`): the guard stopped the VM name and
printed `SIZE-GUARD STOP iso5-guardtest 3 GB (limit 1 GB)` within 8 s of the write. The image was deleted afterwards.
(`qemu-io` refuses one write above 2 GiB, so the test wrote 1500M + 1000M. The first attempt, a single 2G write,
was rejected by qemu-io and the guard correctly did nothing.) The guard unit stays running until
`systemctl stop size-guard-NAME`; it was stopped at the end of this spike.

## Mount options (`findmnt -s`, the fstab)

| Mount | Options |
|---|---|
| `/`, `/home`, `/tmp`, `/var`, `/var/log`, `/var/tmp` | `defaults` only |
| `/var/log/audit` | `defaults,nodev,noexec,nosuid` |
| `/boot` | `defaults` |
| `/boot/efi` | `defaults,uid=0,gid=0,umask=077,shortname=winnt` |

Live mounts match (`/dev/shm` has nosuid,nodev from systemd). Source: the kickstart (`render.py`, `logvol` lines)
passes **no** `--fsoptions`; the options on `/var/log/audit` come from the Anaconda OpenSCAP add-on running the CUI
profile (`xccdf_org.ssgproject.content_profile_cui`) at install time. That profile did not add nodev/nosuid/noexec
to `/home`, `/tmp`, `/var/tmp` or `/var` on this build. If the 0.6.0 layout wants those, the kickstart must set
them with `--fsoptions`.

## auditd (`/etc/audit/auditd.conf`)

```
space_left = 75                  (MB free)
space_left_action = SYSLOG
admin_space_left = 50            (MB free)
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
max_log_file = 8, num_logs = 5, max_log_file_action = ROTATE
```

In plain words: auditd keeps five 8 MB log files and rotates them. When the audit volume is down to 75 MB free it
writes a warning to syslog. At 50 MB free, or when the volume is full or errors, it **suspends**: it stops writing
audit records but the machine keeps running (it does not halt). The audit trail therefore has a gap rather than the
host stopping. These figures were read from the config; the volume was not filled in this spike.

## TPM unlock and volume group

- vTPM present (`/dev/tpm0`, `/dev/tpmrm0`). LUKS2 on `/dev/vda3` has a clevis token
  `tpm2 {"hash":"sha256","key":"ecc","pcr_bank":"sha256","pcr_ids":"7"}` (PCR 7, Secure Boot state), plus a
  passphrase slot.
- After `systemctl reboot` the server came back with no passphrase sent by us (checked on both installs: uptime
  moved forward and the LUKS root was open). TPM unlock works on a 2 TB disk.
- `vgs chp`: VFree 0 (VSize under 1.82t), as expected, because `/` took the free space.

## Files changed in this task

`lab/iso5/size-guard.sh` (new), `lab/iso5/install-iso.sh` (`DISK_GB`, guard start), `lab/security/SPIKE-DISK.md`,
and one line in `lab/iso5/prove.sh` that passes `DISK_GB` through to `install-iso.sh` (needed so the unchanged
`server` stage can use it; default stays 120).
