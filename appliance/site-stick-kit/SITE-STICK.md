# Making the site stick — CyberHygiene Project Lab Installer 0.1.0 to 0.4.0

Internal test image for the CyberHygiene Project development team. Not an official Rocky Linux product.

The installer ISO is the same for every site. Everything that belongs to **your** site (domain, addresses, which
machine is the server) is on a second USB stick, the **site stick**: a FAT drive labelled `OEMDRV` with two files you
write, `site.conf` and `hosts`. The installer reads it, checks it, and refuses to touch any disk if something is wrong.
There are no questions at the console.

Files in this kit:

| File | What it is |
|---|---|
| `SITE-STICK.md` | this guide |
| `site.conf.template` | every setting, with what it means and an example |
| `hosts.template` | the machine table, with the format and an example |
| `chp-site.pyz` | the same checker the installer runs (Python 3; works on macOS and Linux) |
| `SHA256SUMS`, `SHA256SUMS.asc` | checksums, signed with the project release key (check them as in your release's `VERIFY.md`) |

## 1. Before you start (checklist)

- [ ] **A USB stick for this site only**, any size, good brand. It will hold every machine's recovery passwords, and
      each installed machine remembers this exact stick (its USB ID and serial number). Use the **same physical stick**
      for every install at the site and for the server step in §5. A different stick is refused.
- [ ] **The domain** (e.g. `cyberappliance.tech`). It cannot be changed after the server is installed.
- [ ] **The address plan**: subnet, gateway, one fixed IP per machine, time source, upstream DNS.
- [ ] **Each machine's MAC address** — of the network port that will be cabled to the site network (§3).
- [ ] **Every client machine known now.** List them all before the server install (see §7).
- [ ] **An ECDSA SSH key** on the admin workstation (§3). ed25519 keys are refused (FIPS).
- [ ] **Firmware on every machine:** UEFI boot, **Secure Boot on**, **TPM 2.0 enabled**. Without Secure Boot or a TPM
      the install still works, but the disk passphrase must be typed at **every** boot.
- [ ] **One internal disk per machine** — or note which disk to erase (§3, `disk` column). Recommended: a 2 TB SSD for
      the server, 240 GB or more for a workstation (see "From 0.6.0 on" in §6).
- [ ] **A monitor and keyboard** on each machine for its install and first boot.
- [ ] The ISO checked and written to its own USB stick (`0.1.0/VERIFY.md`).

## 2. Make the stick

**macOS** (find the stick's `/dev/diskN` with `diskutil list`; check it twice — this erases it):

    diskutil eraseDisk FAT32 OEMDRV MBRFormat /dev/diskN

**Linux** (find the stick with `lsblk`; check it twice):

    sudo parted -s /dev/sdX mklabel msdos mkpart primary fat32 1MiB 100%
    sudo mkfs.vfat -n OEMDRV /dev/sdX1

The label must be exactly `OEMDRV`.

## 3. Fill in the two files

Copy `site.conf.template` to the stick as **`site.conf`** and `hosts.template` as **`hosts`** (no `.template`), then
edit them with a plain-text editor. Save as plain UTF-8 text (TextEdit: *Format → Make Plain Text*).

- **site.conf** — fill every line the comments call required. Comments go on their own line, never after a value.
- **MAC addresses** — Linux: `ip -br link`; macOS: `ifconfig en0 | grep ether`; or the firmware/iLO screen, or the
  label on the machine. Use the port that will actually be cabled.
- **Admin key** — on the admin workstation:

      ssh-keygen -t ecdsa -b 384 -f ~/.ssh/chp_admin
      cat ~/.ssh/chp_admin.pub

  Paste that whole line after `ADMIN_SSH_PUBKEY=`. Keep the private key (`~/.ssh/chp_admin`) safe: it is the
  break-glass login (`chpadmin`) to every machine.
- **disk** — only for a machine with two or more internal disks. Prefer the `/dev/disk/by-id/...` name.

## 4. Check it — at your desk, not at the console

With the stick mounted (macOS: `/Volumes/OEMDRV`):

    python3 chp-site.pyz validate --site /Volumes/OEMDRV
    python3 chp-site.pyz validate --site /Volumes/OEMDRV --mac 3c:ec:ef:12:34:56 --role server

The first checks the files; the second also checks that this MAC is in `hosts` with that role. It must print
`OK: <domain>, <n> hosts, server <name>`. Any other answer names the line and the problem — fix it and run it again.
The installer runs the same check and stops, before any disk is touched, if it fails.

## 5. Install the server

1. Plug in **the ISO stick and the site stick**. Boot the ISO (UEFI). Choose **Install identity server**.
   Nothing installs on a timeout. The install erases that machine's disk and runs unattended.
2. While it runs, the installer writes `escrow/<hostname>.txt` to the site stick: that machine's disk passphrase
   (`LUKS_PASSPHRASE`), root console password (`ROOT_CONSOLE_PASSWORD`) and boot-loader password (`GRUB_PASSWORD`).
   A line `INSTALL COMPLETED <time>` is added at the end; without it the file is not valid.
3. **First boot asks once for the disk passphrase.** Read `LUKS_PASSPHRASE` from `escrow/<server>.txt` (on the stick, on
   another computer) and type it. First boot then binds the disk to the TPM, so later boots unlock by themselves.
4. Wait for first boot to finish (several minutes; it sets up Kanidm, the certificate authority and DNS). From the
   admin workstation: `ssh -i ~/.ssh/chp_admin chpadmin@<server IP> systemctl status chp-server-firstboot` —
   - `inactive (dead)` = **not started yet** (a common step runs first) — wait and ask again;
   - `activating (start)` = still running — wait;
   - `active (exited)` with `status=0/SUCCESS` = **finished**;
   - `failed` = stop and send the output of `journalctl -u chp-server-firstboot` (as root, see step 5).
5. **Move the server's secrets onto the stick.** Plug the **same** site stick into the server, then from the admin
   workstation:

       ssh -i ~/.ssh/chp_admin chpadmin@<server IP>
       su -                       # password: ROOT_CONSOLE_PASSWORD from escrow/<server>.txt
       chp-site export-client

   It moves the Kanidm admin recovery passwords, the root CA key and the CA password to the stick
   (`escrow/<server>-server.txt`), writes `client.conf`, copies one enrolment token per client listed in `hosts`
   (`tokens/`), and prints fingerprints. **Write the fingerprints down** and compare them with what clients report later.
   Until this step is done the server's monitor keeps alerting that recovery secrets are still on the server.

## 6. Install the clients — one at a time

For each client: plug in the ISO stick and the site stick, boot, choose **Install client workstation**, then at first
boot type that client's `LUKS_PASSPHRASE` from `escrow/<client>.txt`. Wait until
`systemctl status chp-client-firstboot` on the client shows it finished (as in §5 step 4). Finish one client before
starting the next (one stick, one writer). To check the stick before a client install:

    python3 chp-site.pyz validate --site /Volumes/OEMDRV --mac <client MAC> --role client

### From 0.2.0 on: file integrity (AIDE)

Core 0.2.0 adds a daily file-integrity check (AIDE). Nothing below applies to 0.1.0.

- **Leave the site stick plugged in until first boot has finished** on each host. The host records the stick's
  identity just before it takes its file-integrity baseline. If the stick is already out, the first later use of the
  stick raises one alert, and the ISSO accepts it with `chp-site aide-accept`.
- **Server:** `export-client` (§5) also pins the server's baseline to the stick (`aide/<server>.txt`).
- **Each client:** after first boot has finished, plug in the site stick and run `sudo chp-site aide-pin`. It writes
  `aide/<client>.txt` to the stick. The monitor keeps alerting "AIDE baseline not pinned" until you do.
- **Who may accept file changes:** the ISSO (`ISSO_NAME`), plus anyone listed in `BASELINE_DELEGATES` in `site.conf`
  (names separated by commas; it may be left empty). This list is separate from `UNEXPIRE_DELEGATES` on purpose.

### From 0.6.0 on: disks, the layout, and the backup drive

**What is new in 0.6.0.** The installer now sizes the volumes by the size of the disk. Before 0.6.0 every machine got
the same small volumes and `/` took the rest. On a big server that left `/var` and the logs (where Wazuh, Suricata,
YARA, the Kanidm database and the daily reviews write) in 20 GB and 8 GB volumes that could not be grown. Also new:
a low-disk-space alert on every host (monitor check 76), logrotate for the YARA log (chp-security 0.4.1), and fixes to
the daily-review sign-off (chp-site 0.13.0): signing needs a terminal (piped input no longer counts as consent),
`--date` must be `YYYY-MM-DD`, and `--notes` is at most 1000 characters with no control characters.

**Recommended disks.**

- **Server: one 2 TB SSD.** The data of the site lives on the server. Add a second drive in the spare bay for backups
  (see below).
- **Workstation: any disk of 240 GB or more.** Workstations keep their working data on the server, not locally.
- **Smaller disks still work.** The minimum is still 100 GB. A server under 900 GB and a workstation under 240 GB get
  the same layout as before 0.6.0 (this is what lab VMs get). Then `/data` and `/backup` are plain folders on `/`.
- A server disk under 1.9 TB works, and the installer says so: the escrow file has a `DISK_NOTE` line, and the
  install-complete screen shows it. It is a note, not a stop.

**The layout** (sizes in GiB, rounded down; the volumes are in the encrypted volume group `chp`).

| Volume | Server 2 TB | Server 1 TB | Workstation 512 GB |
|---|---|---|---|
| `/` | 90 | 90 | 40 |
| `/var` | 100 | 100 | 20 |
| `/var/log` | 50 | 50 | 20 |
| `/var/log/audit` | 30 | 30 | 8 |
| `/var/tmp` | 15 | 15 | 4 |
| `/tmp` | 15 | 15 | 4 |
| swap | 29 | 29 | 8 |
| `/home` | 238 | 93 | 92 |
| `/data` | 350 | 137 | none |
| `/backup` | 599 | 234 | none |
| **left free in the volume group** | **343** | **135** | **277** |

How other disk sizes are worked out: on a server the `/`, `/var`, `/var/log`, `/var/log/audit`, `/var/tmp`, `/tmp` and swap
volumes are fixed; what is left is split 15.6 % `/home`, 22.9 % `/data`, 39.2 % `/backup`, and the rest stays free.
On a workstation the fixed volumes are as above, `/home` is a quarter of what is left (at least 10 GiB), and
the rest stays free. `/boot/efi` (1 GiB) and `/boot` (2 GiB) are outside the encrypted group, as before.

**The free space is the point.** XFS can grow but never shrink, so space left unassigned is space you can give to any
volume later, online, with one command: see `runbooks/grow-a-volume.md` in this kit. The monitor (check 76) alerts at
85 % full on any volume and tells you how much is free in `chp`.

**Mount options.** `/data` is `nodev,nosuid`. `/backup` is `nodev,nosuid,noexec`. `/var/log/audit` is
`nodev,nosuid,noexec` (set by the CUI profile at install). Other volumes use the defaults.

**The backup drive.** `/backup` starts on the server's own disk, so it is not yet a backup against the loss of that disk.
Add a separate drive in the spare bay, then move `/backup` to it with `runbooks/move-backup-to-a-second-drive.md`
(it encrypts the drive, binds it to the TPM, puts its recovery passphrase on this stick, and returns the space to the
volume group). Do this soon after the install. The project does not install backup software or set a schedule.

If the second drive is already in the machine **at install time**, the installer will not guess which disk to erase.
Put the install disk in the **fifth column of `hosts`** (`disk`, see §3) by its `/dev/disk/by-id/...` name. The other
drive is left alone and is added with the runbook afterwards.

**What happens when the audit volume fills.** These are the installed settings (`/etc/audit/auditd.conf`, set by the CUI
profile). They were read from the configuration; a full volume was not tested. auditd logs a warning to syslog at 75 MB
free (`space_left`). At 50 MB free (`admin_space_left`) it suspends. If the volume is full or has an error
(`disk_full_action` and `disk_error_action`), auditd **suspends auditing** and the machine keeps running. So the audit
trail gets a gap, but the host does not halt. Avoid the gap: the earlier warning is monitor check 76, which alerts at
85 % full, long before 50 MB is left. Act on it; grow the volume with the runbook.

**Existing installs keep their layout.** An install made with an earlier ISO is not repartitioned: its volume group has
no free space, because `/` took it. The new layout reaches a site only by reinstalling. Check 76 does apply to
existing hosts once they have the update. If you are planning a new server (for example a second site), install
0.6.0 or later.

**Sync clients and `/home` on workstations.** A workstation's `/home` is modest on purpose. If a site runs a sync
client that keeps a **full local copy** of the user's files (for example the Nextcloud desktop client), those files land
in `/home` and its size matters. Either grow `/home` (`runbooks/grow-a-volume.md`) or set the client to on-demand
files. A file service on the CHP server itself is not part of 0.6.0; `/data` is where one would live.

### From 0.5.0 update 1 on: the daily security review

With the security add-on on, the server builds a review of the previous day every night: intrusions by source address
(inside or outside your `SUBNET`), every host's security status (certificates, keys, scans, sysstat, repo), and resource
use. The ISSO reads it with `chp-site review`, signs it with `chp-site review sign --approver "Name" --notes "..."`, and
exports the evidence to this stick with `chp-site review export` (it also records the sign-off ledger's head here, in
`review/heads.txt`, so later changes show). To let others sign, list them in **`REVIEW_DELEGATES`** in `site.conf`
(comma separated; may be empty; separate from the AIDE and unexpire delegates). The administrator is alerted if a review
waits more than 2 days for a sign-off. See `0.5.0-update1/UPDATE.md`.

### From 0.5.0 on: network intrusion detection at install

With `SECURITY_ADDONS=yes`, a 0.5.0 install also turns on Suricata at each host's first boot (the same intrusion
detection that 0.4.0 update 1 adds to existing hosts): nothing more to set on the stick. The ISO's repo also carries
`chp-templates` 1.3.1 for `chp-site docs` (Rev 2 narratives for YARA and Suricata).

### From 0.4.0 update 1 on: network intrusion detection (Suricata)

With the security add-on on, every host runs Suricata on its own network interface, with the ET Open rules and your
`SUBNET` as the home network. It is **IDS only: nothing is blocked**. A high-severity match is reported to `ALERT_HOOK`
straight away; medium ones go into the daily summary. Alerts are kept in `/var/log/suricata/eve.json` for
`RETENTION_DAYS`. Each host sees only its own traffic, and Suricata needs about 500 MB of memory per host. New rules
arrive as a small signed update each month. See `0.4.0-update1/UPDATE.md`.

**Known issue in 0.4.0 update 1 (fixed in 0.5.0):** on hosts with both YARA and Suricata, the weekly YARA scan (Sunday
03:30) reports `/usr/share/chp-suricata-rules/chp-suricata.rules` as a match, because ET Open's rules quote the attack
patterns YARA looks for. It is a false alarm: the file is the signed rules package. Dismiss it. Installing 0.5.0, or its
repo's `chp-site` 0.11.0-4, stops it.

### From 0.4.0 on: malware scanning at install

With `SECURITY_ADDONS=yes`, a 0.4.0 install also turns on YARA malware scanning at each host's first boot (the same
scanning that 0.3.0 update 1 adds to existing hosts): nothing more to set on the stick.

### From 0.3.0 update 1 on: malware scanning (YARA)

With the security add-on on, every host scans new or changed files in the user and temporary folders every 5 minutes,
and every local file system weekly, with YARA and the signature-base rules. It is **alert only**: a match is reported to
`ALERT_HOOK` and left in place for a person to decide. Results are kept in `/var/log/chp-yara.json`. New rules arrive as
a small signed update each month. See `0.3.0-update1/UPDATE.md`.

### From 0.3.0 on: the security add-on at install (optional)

Set `SECURITY_ADDONS=yes` in `site.conf` before you install, and the installer sets up Wazuh at each host's first boot.
Keep the usual order, because the agent keys travel on the stick like the client tokens:

1. **Install the server first.** Its first boot makes one Wazuh agent key per client.
2. **Plug the stick into the server and run `chp-site export-client`.** It copies the client tokens *and* the agent
   keys (`wazuh/<host>.key`) to the stick, checks them, and removes them from the server.
3. **Install each client** with the stick. The installer copies that client's own key to the client, and the client's
   first boot connects its agent to the server.

A client installed before step 2 stops at the start of the install ("no Wazuh agent key"), before any disk is touched.
The packages come from the ISO's own repo, which the installer copies to each host. **Installing over the network
instead of from the ISO?** Then no repo is copied: before first boot reaches its security step, unpack the release's
`chp-repo-<version>.tar.gz` into `/var/lib/chp/repo` (as in the update notes). If the step has already failed, unpack it
and reboot; the step runs again.
With `SECURITY_ADDONS=no` (the default) nothing changes from 0.2.0. `SECURITY_ALERT_LEVEL` (default 10) sets which
Wazuh alerts go to `ALERT_HOOK` straight away; the rest go into a daily summary. It is read once, at the first enable:
to change it later, edit `ALERT_LEVEL` in `/etc/chp/security.conf` on the server and run
`systemctl restart chp-wazuh-alerts`.

### From 0.2.0 update 4 on: the security add-on (optional)

`chp-site security enable` turns on Wazuh log monitoring and intrusion detection: the server first, then each
client, **with the site stick plugged in each time**. The server writes one agent key per client to the stick
(`wazuh/<host>.key`), and each client reads its own. Those keys are secrets, so the stick needs the same care as
always. Important alerts go to your `ALERT_HOOK` (set it in `site.conf`). See `0.2.0-update4/UPDATE.md`.

### From 0.2.0 update 2 on: your SSP and POA&M

The appliance can write a first draft of your **System Security Plan (SSP)** and **Plan of Action and Milestones
(POA&M)**. It uses the CyberHygiene Project's templates (`chp-templates`), filled with your own values.

1. Copy `profile.ini.template` from this kit to the site stick's top level, **next to `site.conf`**, as `profile.ini`.
   Replace every example value with your own. **Never put passwords, keys or tokens in it.**
2. Check it at your desk: `python3 chp-site.pyz validate --site /Volumes/OEMDRV`. Point `CHP_TEMPLATES` at a copy of
   chp-templates so `profile.ini` is checked too.
3. On the server, with the site stick plugged in, run as root: `chp-site docs`.

The documents go to a new folder under `/var/lib/chp/docs/`, readable by root only, and an earlier one is never
overwritten.
- `ssp.md` and `poam.md` are your editable starting point.
- `fill-report.md` lists every value still to fill. It shows each as `{{placeholder}}` in the documents, together with
  any default you have not yet confirmed.
- For a Word copy, run `pandoc ssp.md -o ssp.docx` on your workstation.

## 7. Limits in 0.1.0

- **Adding a client after the server is installed is not yet a supported procedure.** The server builds its DNS zone
  and its client tokens from the `hosts` table it was installed with. List every client before the server install. A
  supported "add a client later" path is planned for the next core release.
- The domain cannot be changed without reinstalling the server.

## 8. Known problem: "Waiting for multipath siblings of sdX"

An earlier CyberHygiene build hung on real hardware (HP ProLiant, Rocky 9.7, installing from USB) printing
`Waiting for multipath siblings of sdb` over and over. If you see this: at the ISO menu, highlight the install entry,
press **e**, add a space and **`rd.multipath=0`** at the end of the line that starts with `linuxefi`, then press
**Ctrl-X** to boot it. This workaround is **not yet tested with this ISO** — please report whether you needed it and
whether it worked.

## 9. Keep the stick safe

After the first install the stick holds every machine's disk, root and boot-loader passwords, and after §5 the
Kanidm admin recovery passwords and the root CA key. **Keep it offline and locked away.** Never copy it to a network
share (including the shared folder this kit came from), to cloud storage, or into email. Make one offline copy on a
second stick kept in a different safe place.
