# Runbook: grow a volume

For ISO 0.6.0 or later servers and workstations, and for any host whose volume group `chp` has free space.
Takes about two minutes. The volume stays mounted and in use. Nothing is rebooted.

**When to use it:** monitor check 76 raised "volume X is N % full" (at 85 % or more), or you are about to put
something big on a volume (for example a sync client that keeps a full copy of the user's files in `/home`).

**What changes:** the size of one logical volume and the file system on it. No file is touched. AIDE does not watch
file system sizes, so no baseline change is needed.

**Before you start:** you need the root console or `chpadmin` and `su -`. XFS can grow but never shrink. Grow by what
you need plus some headroom, not by everything that is free.

## Steps

1. See which volume is full and how much room the volume group has:

       df -h -x tmpfs -x devtmpfs
       vgs chp

   The `VFree` column of `vgs chp` is what you can hand out. If it is `0`, stop: there is no room. Add a disk, or see
   the backup-drive runbook (`move-backup-to-a-second-drive.md`) to take back the space `/backup` is using.

2. Find the logical volume name for the mount (`/var/log` is `var_log`, `/var/log/audit` is `var_log_audit`, `/var/tmp`
   is `var_tmp`, `/` is `root`, `/home` is `home`, `/data` is `data`, `/backup` is `backup`):

       lvs chp

3. Grow it by N GiB and its file system with it (`-r` does both). Example: add 20 GiB to `/var`:

       lvextend -r -L +20G chp/var

   It prints the new size of the logical volume and of the file system. If it says "insufficient free space", use a
   smaller number.

4. Check:

       df -h /var
       vgs chp

   `df` shows the larger size. `vgs` shows `VFree` down by the amount you added.

5. Within 15 minutes (the monitor runs every 15 minutes) monitor check 76 clears by itself when the volume is back under 85 %. Nothing to acknowledge.

## If something goes wrong

- `lvextend` fails with a message and the sizes are unchanged: nothing was changed. Read the message; the usual cause
  is not enough free space.
- You grew the wrong volume: it cannot be shrunk. Leave it. The space is not lost; it is just in the wrong volume.
- Do not run `lvreduce` or `xfs_growfs` on its own. `lvextend -r` does both in the right order.
