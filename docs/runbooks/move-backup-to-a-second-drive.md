# Runbook: move /backup to a second drive

For an ISO 0.6.0 or later server on the recommended 2 TB disk. On it, `/backup` is a volume (about 600 GB) on the
system disk. This moves it to its own encrypted drive in the spare bay, then gives the 600 GB back to the volume
group `chp` so you can grow other volumes.

**Time:** about 30 minutes plus the copy time. **Reboot:** one, at the end, to prove the new mount survives.
**Who:** the administrator at the server, plus the ISSO for the last step (the AIDE accept).

**What changes:** a new LUKS2 drive appears, mounted on `/backup`. `/etc/fstab` and `/etc/crypttab` change (AIDE
watches both, so it raises an alert until the ISSO accepts them). The logical volume `chp/backup` is removed.

**What you need:**
- the new drive, empty or one you are happy to erase, installed in the bay;
- the **site stick** (the one labelled `OEMDRV`) and another computer to write on it (the server blocks USB storage);
- the server's root login.

**The new drive is ERASED. Be sure of its name before step 3.** Name it by its serial number, never by `sdb`.

## Steps

All commands as root on the server (`su -`).

1. Stop whatever writes to `/backup`, and check what is there:

       df -h /backup
       lsof +D /backup 2>/dev/null | head

   If `lsof` lists anything, stop that job first. Nothing of the project's own writes there.

2. Find the new drive and set a short name for it. `lsblk` shows every disk; the new one has no partitions and no mount:

       lsblk -d -o NAME,SIZE,MODEL,SERIAL
       ls -l /dev/disk/by-id/ | grep -v part

   Pick its `/dev/disk/by-id/...` name (not the `-part` ones) and set it:

       D=/dev/disk/by-id/PUT-THE-NAME-HERE
       lsblk $D                       # must show NO partitions and NO mountpoints; if it does, stop

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
       cryptsetup luksFormat --type luks2 -q --key-file /run/bk.key $D
       DEV=$(readlink -f $D)

5. Bind it to the TPM, the way first boot binds the system disk (PCR 7, so it needs Secure Boot on). This lets the
   drive unlock by itself at every boot:

       mokutil --sb-state             # must say "SecureBoot enabled"
       clevis luks bind -y -k /run/bk.key -d $DEV tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
       clevis luks list -d $DEV       # must show a tpm2 line

   Unlike first boot, **keep** the passphrase slot: it is the recovery passphrase you just put on the stick.
   If Secure Boot is off, stop and fix that first: without it the binding would open the drive on any boot chain.

6. Open it, make the file system, mount it somewhere temporary:

       cryptsetup open --key-file /run/bk.key $DEV chp-backup
       mkfs.xfs -L backup /dev/mapper/chp-backup
       mkdir -p /mnt/newbackup
       mount -o nodev,nosuid,noexec /dev/mapper/chp-backup /mnt/newbackup

7. Copy. `-aHAX` keeps permissions, owners, hard links, ACLs and extended attributes (SELinux labels):

       rsync -aHAX --info=stats2 /backup/ /mnt/newbackup/

   Run it a second time. The second run should copy nothing ("Number of regular files transferred: 0"). Then compare:

       diff -rq /backup /mnt/newbackup && echo SAME

   It must print `SAME`.

8. Switch the mount. Write the UUIDs into `/etc/crypttab` and `/etc/fstab` (UUIDs, never `sdX`; the LUKS UUID is the one
   of the drive itself, the XFS UUID the one of the file system inside):

       LUKS_UUID=$(cryptsetup luksUUID $DEV); XFS_UUID=$(blkid -s UUID -o value /dev/mapper/chp-backup)
       echo "chp-backup UUID=$LUKS_UUID none luks" >> /etc/crypttab
       sed -i.bak '\# /backup #d' /etc/fstab
       echo "UUID=$XFS_UUID /backup xfs nodev,nosuid,noexec 0 0" >> /etc/fstab
       cat /etc/crypttab /etc/fstab

   Check that `/etc/fstab` has exactly one `/backup` line and `/etc/crypttab` one `chp-backup` line. (`/etc/fstab.bak`
   is the old copy.) There is deliberately no `nofail`: if the drive is missing the host stops in emergency mode and
   you notice, instead of backups landing silently on the system disk.

9. Move the mount, set the SELinux labels, and check:

       umount /mnt/newbackup && rmdir /mnt/newbackup
       umount /backup
       systemctl daemon-reload
       mount /backup
       restorecon -R /backup
       findmnt /backup                # SOURCE /dev/mapper/chp-backup, OPTIONS rw,nosuid,nodev,noexec
       ls -ldZ /backup                # the SELinux label must not be unlabeled_t

10. Remove the old volume, which gives its space back to the volume group:

        lvremove chp/backup            # answer y
        vgs chp                        # VFree is now about 600 GB larger

    The old `/backup` copy is gone with it. Do this only after step 7 said `SAME`.

11. Shred the temporary key file and clear the variable:

        shred -u /run/bk.key; unset P

12. Reboot once to prove it:

        systemctl reboot

    Nothing needs typing at the console (the TPM unlocks both disks). After the boot, log in and run
    `findmnt /backup`, then read the monitor output: the only new alert should be the AIDE change.

13. **ISSO: accept the AIDE change.** `/etc/fstab` and `/etc/crypttab` changed, so AIDE alerts. With the site stick
    plugged in, as the ISSO or a `BASELINE_DELEGATES` person:

        chp-site aide-accept --approver "Name" --reason "backup moved to second drive (runbook move-backup-to-a-second-drive)"

    It shows what changed. It must list only `/etc/fstab` and `/etc/crypttab`. If it lists anything else, say **no** and investigate.

14. Put the site stick back in its safe. The new drive's recovery passphrase is only on it. Keep your offline second
    copy of the stick up to date (it needs the new `escrow/<hostname>-backup-drive.txt` too).

## If something goes wrong

- **Step 5 fails** ("TPM" errors): the drive is encrypted but not TPM-bound. Fix the cause (Secure Boot, TPM
  enabled) and run step 5 again; nothing else depends on it yet.
- **Step 7 copy differs**: do not go on. The old `/backup` is still in place and still the live one.
- **After the reboot the host stops in emergency mode**: log in with the root console password, read
  `journalctl -b -u systemd-cryptsetup@chp-backup`. If the TPM will not unlock it, type the recovery passphrase from
  the stick: `cryptsetup open /dev/disk/by-uuid/<LUKS_UUID> chp-backup`, then `mount /backup`, and fix the
  TPM binding with step 5 again (use the passphrase from the stick as the key file).
- **To undo before step 10:** restore the old lines (`mv /etc/fstab.bak /etc/fstab`, delete the `chp-backup` line in
  `/etc/crypttab`), `systemctl daemon-reload`, `umount /backup`, `mount /backup`. The old volume is untouched.
