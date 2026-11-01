# Making the site stick — CyberHygiene Project Lab Installer 0.1.0 and 0.2.0

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
- [ ] **One internal disk per machine** — or note which disk to erase (§3, `disk` column).
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
