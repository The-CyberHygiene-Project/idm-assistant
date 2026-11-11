# Runbook: move /backup to a second drive

For any server installed with 0.6.0 on a disk of 900 GB or more: it has `chp/backup`. On it, `/backup` is a volume (600 GB
on a 2 TB disk) on the system disk. This moves it to its own encrypted drive in the spare bay, then gives that space back to the volume
group `chp` so you can grow other volumes.

**Time:** about 30 minutes plus the copy time. **Reboot:** one, at the end, to prove the new mount survives.
**Who:** the administrator at the server, plus the ISSO for the last step (the AIDE accept).

**Why `nofail`, and why `chattr +i`:** a dead backup drive must not stop the identity server from booting, so the
mount is marked `nofail` and the server keeps running. Then `/backup` would be an empty folder on `/`, and backups could
silently fill the system disk. So the empty folder is made immutable (step 9): while the drive is absent, writes to
`/backup` fail loudly instead.

**What changes:** a new LUKS2 drive appears, mounted on `/backup`. `/etc/fstab`, `/etc/crypttab` and the LVM
records under `/etc/lvm` change (AIDE watches them, so it raises an alert until the ISSO accepts them). The logical volume `chp/backup` is removed.

**What you need:**
- the new drive, empty or one you are happy to erase, installed in the bay;
- the **site stick** (the one labelled `OEMDRV`) and another computer to write on it (the server blocks USB storage);
- the server's root login.

**The new drive is ERASED. Be sure of its name before step 3.** Name it by its serial number, never by `sdb`.

## Steps

All commands as root on the server (`su -`).

1. Check this is the right kind of server, stop whatever writes to `/backup`, and check what is there:

       findmnt -no SOURCE /backup     # must print /dev/mapper/chp-backup; anything else: STOP
       df -h /backup
       fuser -vm /backup

   If `findmnt` prints anything but `/dev/mapper/chp-backup`, stop: this server is a legacy install (its `/backup` is a
   folder on `/`) and this runbook does not apply. If `fuser` lists a process, stop that job first. Nothing of the
   project's own writes there.

2. Find the new drive and set a short name for it. `lsblk` shows every disk; the new one has no partitions and no mount:

       lsblk -d -o NAME,SIZE,MODEL,SERIAL
       ls -l /dev/disk/by-id/ | grep -v part

   Pick its `/dev/disk/by-id/...` name (not the `-part` ones) and set it:

       D=/dev/disk/by-id/PUT-THE-NAME-HERE
       [ "$(lsblk -no NAME "$D" | wc -l)" = 1 ] && [ -z "$(lsblk -no MOUNTPOINTS "$D" | tr -d '[:space:]')" ] \
         && echo "OK: empty, unmounted" || echo "REFUSE: has partitions or is mounted"

   If it prints `REFUSE`, stop. Do not go on with that drive: it holds partitions or something is mounted from it. Check
   you named the right disk (serial number); if the drive is meant to be wiped, wipe it deliberately (`wipefs -a`) and
   run this check again. Step 4 erases whatever it finds.

3. Make the recovery passphrase and show it. It is kept only on the site stick, never on this server:

       P=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40); echo "$P"

   Do not close this window. On the **other computer**, plug in the site stick and add the file
   `escrow/<hostname>-backup-drive.txt` (the same folder that holds `<hostname>.txt`) with these lines, typing the
   passphrase exactly:

       BACKUP_DRIVE_SERIAL=<the serial from step 2>
       BACKUP_DRIVE_LUKS_PASSPHRASE=<the passphrase>
       WRITTEN=<today, YYYY-MM-DD>

   Eject the stick safely, plug it in again, and read the file back. The passphrase on the stick must match the one on
   the server's screen character for character. **Do not go on until it does.** If the window is closed, start step 3
   again (nothing has been changed yet).

4. Write the passphrase to a temporary file in memory, then encrypt the drive (LUKS2, as the system disk is):

       install -m 0600 /dev/null /run/bk.key; printf '%s' "$P" > /run/bk.key
       cryptsetup luksFormat --type luks2 --key-file /run/bk.key $D
       DEV=$(readlink -f $D)

   `cryptsetup` asks you to type uppercase `YES`: that is the last chance to stop before the drive is erased.

5. Bind it to the TPM, the way first boot binds the system disk (PCR 7, so it needs Secure Boot on). This lets the
   drive unlock by itself at every boot:

       mokutil --sb-state             # must say "SecureBoot enabled"
       clevis luks bind -y -k /run/bk.key -d $DEV tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
       clevis luks list -d $DEV       # must show a tpm2 line

   Unlike first boot, **keep** the passphrase slot: it is the recovery passphrase you just put on the stick.
   If Secure Boot is off, stop and fix that first: without it the binding would open the drive on any boot chain.

6. Open it, make the file system, mount it somewhere temporary:

       cryptsetup open --key-file /run/bk.key $DEV backupdrive
       mkfs.xfs -L backup /dev/mapper/backupdrive
       mkdir -p /mnt/newbackup
       mount -o nodev,nosuid,noexec /dev/mapper/backupdrive /mnt/newbackup

7. Copy. `-aHAX` keeps permissions, owners, hard links, ACLs and extended attributes (SELinux labels):

       rsync -aHAX --info=stats2 /backup/ /mnt/newbackup/

   Run it a second time. The second run should copy nothing ("Number of regular files transferred: 0"). Then compare:

       diff -rq /backup /mnt/newbackup && echo SAME

   It must print `SAME`.

8. Switch the mount. Write the UUIDs into `/etc/crypttab` and `/etc/fstab` (UUIDs, never `sdX`; the LUKS UUID is the one
   of the drive itself, the XFS UUID the one of the file system inside):

       LUKS_UUID=$(cryptsetup luksUUID $DEV); XFS_UUID=$(blkid -s UUID -o value /dev/mapper/backupdrive)
       echo "backupdrive UUID=$LUKS_UUID none luks,nofail" >> /etc/crypttab
       sed -i.bak '\# /backup #d' /etc/fstab
       echo "UUID=$XFS_UUID /backup xfs nodev,nosuid,noexec,nofail,x-systemd.device-timeout=30 0 0" >> /etc/fstab
       cat /etc/crypttab /etc/fstab

   Check that `/etc/fstab` has exactly one `/backup` line and `/etc/crypttab` one `backupdrive` line. (`/etc/fstab.bak`
   is the old copy.) Both lines say `nofail`: if the drive is dead or missing, the server still boots (see the note at
   the top). The name `backupdrive` is deliberately not `chp-backup`: that is already the old volume's name.

9. Move the mount, set the SELinux labels, and check:

   First, with writers still stopped (step 1), copy once more and verify, so nothing written since step 7 is lost:

       rsync -aHAX --delete /backup/ /mnt/newbackup/
       diff -rq /backup /mnt/newbackup && echo SAME      # must print SAME

   Then switch. The `chattr +i` goes on the empty folder underneath, so it is done after the old volume is unmounted
   and before the new drive is mounted:

       umount /mnt/newbackup && rmdir /mnt/newbackup
       umount /backup
       chattr +i /backup              # nothing is mounted on it now; this is the empty folder on /
       lsattr -d /backup              # must show the i flag
       systemctl daemon-reload
       mount /backup
       restorecon -R /backup
       findmnt /backup                # SOURCE /dev/mapper/backupdrive, OPTIONS rw,nosuid,nodev,noexec,...
       ls -ldZ /backup                # the SELinux label must not be unlabeled_t
       touch /backup/.probe && rm /backup/.probe     # works: the drive is mounted

   `findmnt /backup` must show the `backupdrive` source. If it shows nothing, the new drive is not mounted: stop and
   read `journalctl -b -u systemd-cryptsetup@backupdrive`. (The `chattr +i` does not block writes to the mounted drive;
   it only protects the empty folder.)

10. Remove the old volume, which gives its space back to the volume group:

        lvremove chp/backup            # answer y
        vgs chp                        # VFree is now about 600 GB larger

    The old `/backup` copy is gone with it. Do this only after step 7 and step 9 both said `SAME`.

11. Shred the temporary key file and clear the variable:

        shred -u /run/bk.key; unset P

12. Reboot once to prove it:

        systemctl enable clevis-luks-askpass.path
        systemctl is-enabled clevis-luks-askpass.path     # must print: enabled
        systemctl reboot

    The `clevis-luks-askpass.path` unit is what lets the TPM unlock a drive that is not the root disk. Nothing in the
    installer enables it, so without the `enable` the reboot stops and asks for the passphrase. With it, nothing needs
    typing at the console (the TPM unlocks both disks). After the boot, log in and run
    `findmnt /backup`, then read the monitor output: the only new alert should be the AIDE change. The journal for
    `systemd-cryptsetup@backupdrive` shows one "Failed to activate with specified passphrase" line followed by
    "Finished Cryptography Setup": the first unlock attempt fails, then the TPM unlocks it. That is normal.

13. **ISSO: accept the AIDE change.** `/etc/fstab` and `/etc/crypttab` changed, so AIDE alerts. With the site stick
    plugged in, as the ISSO or a `BASELINE_DELEGATES` person:

        chp-site aide-accept --approver "Name" --reason "backup moved to second drive (runbook move-backup-to-a-second-drive)"

    It shows what changed. The move itself explains exactly these paths: `/etc/fstab`, `/etc/crypttab`,
    `/etc/fstab.bak` (the old copy from step 8; delete it first if you no longer need to undo), `/etc/lvm/backup/chp`
    and a new file under `/etc/lvm/archive/` (LVM records every volume change; `lvremove` in step 10 made them). Anything
    else on the list is not from this move: say **no** and investigate.

14. Put the site stick back in its safe. The new drive's recovery passphrase is only on it. Keep your offline second
    copy of the stick up to date (it needs the new `escrow/<hostname>-backup-drive.txt` too).

## If something goes wrong

- **Step 5 fails** ("TPM" errors): the drive is encrypted but not TPM-bound. Fix the cause (Secure Boot, TPM
  enabled) and run step 5 again; nothing else depends on it yet.
- **Step 7 copy differs**: do not go on. The old `/backup` is still in place and still the live one.
- **After the reboot `findmnt /backup` shows nothing** (the host still boots, because of `nofail`; writes to `/backup`
  now fail, by design): log in, read
  `journalctl -b -u systemd-cryptsetup@backupdrive`. If the TPM will not unlock it, type the recovery passphrase from
  the stick: `cryptsetup open /dev/disk/by-uuid/<LUKS_UUID> backupdrive`, then `mount /backup`, and fix the
  TPM binding: run step 5's `clevis luks bind`, but leave out `-k /run/bk.key` so that clevis asks for the existing
  passphrase, and type the one from the stick. (If you prefer a key file: `install -m 0600 /dev/null /run/bk.key;
  printf '%s' '<passphrase>' > /run/bk.key`, use `-k /run/bk.key`, then `shred -u /run/bk.key`. Never make it with
  `echo`: its trailing newline makes it the wrong key.)
- **To undo before step 10** (the old volume is untouched): restore the old lines (`mv /etc/fstab.bak /etc/fstab`,
  delete the `backupdrive` line in `/etc/crypttab`), then:

      umount /backup                 # the new drive, if step 9 mounted it
      chattr -i /backup              # remove the immutable flag, or the old volume cannot be used as before
      cryptsetup close backupdrive   # close the new drive's mapping
      systemctl daemon-reload
      mount /backup                  # the old chp/backup volume again

  Anyone who abandons the move after step 9 must run `chattr -i /backup` once the drive is unmounted.
