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

### From 0.7.0 on: controlled documents

0.7.0 adds an optional **document server** (NextCloud, on the server, at `https://files.<your domain>:8443`) and a
way to change **controlled documents** (SSP, POA&M, policies, procedures, runbooks, change records, evidence) under
control. A controlled document is published only after someone else has approved the exact file.

Ordinary CUI work files (drawings, data, customer material) do not go through this. People put them in the CUI or
FCI folders with the browser. Everything in those folders is tagged and audited.

#### What you need

- **Site stick:** `DOCUMENTS=yes` and `SECURITY_ADDONS=yes` in `site.conf`, and the keys `DOC_ISSO_ACCOUNT`,
  `DOC_APPROVER_ACCOUNTS`, `CUI_CONTROLLED_BY`, `CUI_CATEGORY` and `CUI_POC` (the template has them). The ISSO's
  account is listed in `DOC_ISSO_ACCOUNT` only, never also in the approver list. Until at least one of the two is set,
  every approval is refused.
- **Server memory: at least 8 GiB.** The lab server that passed its proofs had 8 GiB. Nothing checks it when you turn
  the document server on, so do not install it on less.
- **Turn it on:** on the server, as an administrator, with the site stick plugged in and a Kanidm admin session:
  `chp-site documents enable`. Look at it any time with `chp-site documents status`.
- **Workstations:** client enrolment sets up the editor and the document commands when the site has `DOCUMENTS=yes`.
  The editor takes about 1.2 GB under `/opt/onlyoffice`.
- **Sign-in:** each person signs in with their own Kanidm account. A typed name is never enough.

#### The author's day

You work on a **working copy** in `~/Documents/CHP-Working`. That folder is yours (mode 0700) and must be on the
encrypted disk, or the commands refuse. Run `chp-site doc` as yourself, never as root.

1. Sign in: `chp-site doc login`. A browser opens at Kanidm. If it does not, open the address the command prints.
   The sign-in lives in memory only and ends when your last session ends, or when Kanidm ends it (about 8 hours).
2. Start from one of two places.
   - A new document: `chp-site doc new MyPolicy --cui`. Use `--non-cui` for a document with no CUI marks. Add
     `--type xlsx` or `--type md` for another format (the default is `docx`). The title has no spaces. You get
     `CUI_MyPolicy_v0.1-DRAFT.docx` with the CUI marks already in it.
   - A change to a published one: `chp-site doc checkout CUI_MyPolicy_v1.0.docx`. You get the next minor version,
     `CUI_MyPolicy_v1.1-DRAFT.docx`. Rename it by hand for a major change (for example `v2.0`).
3. Open the file in ONLYOFFICE, edit it, save it.
4. Ask what is missing: `chp-site doc check CUI_MyPolicy_v1.1-DRAFT.docx`. It changes nothing. It checks the name,
   the CUI marks, `-DRAFT`, and whether the published copy changed since your checkout. It prints `OK` or
   `NOT READY`.
5. If marks are missing, see what would be added: `chp-site doc mark CUI_MyPolicy_v1.1-DRAFT.docx`. To add them,
   run the same command with `--apply`. Marks are added only to a `-DRAFT` file with a `CUI_` or `FCI_` name.
6. Hand the draft to an approver (next part). Wait for the approval.
7. Rename the approved file, **changing nothing else**: remove `-DRAFT`:

       mv CUI_MyPolicy_v1.1-DRAFT.docx CUI_MyPolicy_v1.1.docx

   The approval covers the file's bytes (its sha256), not its name. Do not open the file
   in ONLYOFFICE again: saving changes the bytes and the approval no longer counts.
8. Publish: `chp-site doc publish CUI_MyPolicy_v1.1.docx`. It makes the reader PDF, checks the marks on both files,
   and sends them. The server then writes the new version and its PDF to the Compliance area, moves the old version
   to Superseded, tags the files, and gives the change a number (`CR-<year>-<number>`). `publish` never renames
   anything and refuses a `-DRAFT` name. It refuses a file larger than 64 MiB together with its PDF.
9. Clean up: `chp-site doc close CUI_MyPolicy_v1.1.docx`. It removes your working copy and ONLYOFFICE's recovery
   copies. It refuses while ONLYOFFICE is running, so quit ONLYOFFICE first.

Only an author can publish. You are an author of a change if you created it or checked it out since the last
publish. If the published copy changes after your checkout, `publish` refuses and you check it out again.

`chp-site doc logout` revokes the sign-in and removes the tokens.

#### Handing the draft to the approver

The approver needs to read your exact file. The way to hand it over:

1. You upload the `-DRAFT` file with the **browser** to an ordinary location: a folder in the CUI team folder (for a
   CUI document) or in Internal (for a non-CUI document). Not into Compliance, which only `publish` can write to.
2. The approver downloads it from there into their own `~/Documents/CHP-Working`. It is CUI, so it must stay on the
   encrypted disk. Move it from the browser's download folder.
3. The approver runs `chp-site doc approve CUI_MyPolicy_v1.1-DRAFT.docx`.

The approval is bound to the sha256 of the exact file, so the way it travelled needs no trust. If one byte differs,
the approval does not match and `publish` refuses.

The approver must **not** run `chp-site doc checkout` on it. That makes the approver an author of this change (see
the next part).

The upload is an ordinary work file, tagged and audited. The approver removes the downloaded copy afterwards with
`chp-site doc close <file>`. Deleting the shared upload raises a level-7 alert (Wazuh 100606).

#### The approver's rules

Approvers are the accounts in `DOC_APPROVER_ACCOUNTS`, and the ISSO's account in `DOC_ISSO_ACCOUNT`.

- Sign in as yourself (`chp-site doc login`), then `chp-site doc approve <file>`. Add `--notes "text"` if you want a
  note in the record.
- Your local marking check runs first. A file that fails it is not sent.
- **You cannot approve a change you are an author of.** The author is whoever created the document or checked it
  out since the last publish.
- **The trap of a reader checkout.** If you run `chp-site doc checkout` just to read a document, you become an author
  of that change for the whole cycle. Your approval is then refused, and an earlier approval of yours stops
  counting. To read a document, open it in the browser, download it, or read its PDF.
- **An approval counts only if it comes after the last checkout.** If anyone checks the document out after you
  approved, approve again.
- **An approval is for one file.** The author must publish the same bytes you approved.

#### The ISSO override

On a one-person site nobody else can approve. The ISSO may then approve a change they authored, with a reason:

`chp-site doc override CUI_MyPolicy_v1.1-DRAFT.docx --reason "sole administrator; no other approver"`

The override is refused when:

- you are not the account in `DOC_ISSO_ACCOUNT`;
- any approver account other than the authors of this change exists (ask one of them to approve instead);
- there is no `--reason`.

Every override raises a level-12 alert at once (Wazuh 100643, sent to `ALERT_HOOK`; this needs
`SECURITY_ALERT_LEVEL` of 12 or lower, see "Alerts you will see") and is listed under
"Needs attention" in the daily review until a signed review covers it.

#### Answers and exit codes

Every `chp-site doc` command ends with one of these:

| Exit | Meaning |
|---|---|
| 0 | Done. |
| 1 | The server said no (it tells you why), a local check refused (the marking check in `approve`, `publish` or `mark`), or `check` found problems. |
| 2 | Refused before anything was sent: not signed in, name rule, working folder, a missing file. A plain message. |
| 3 | **Pending.** The server has not answered. Wait a minute and run **the same command again**. |

A pending command is never sent twice. The second run asks about the same request. The request ids are kept when you
run `chp-site doc logout`. They are lost only when your last session ends and your runtime folder goes away.

If the sign-in ends, the command says so. Run `chp-site doc login` and then the same command again.

The 15-minute access token is refreshed 60 seconds before it ends (the sign-in itself lasts about 8 hours). That assumes the workstation clock is right. chrony keeps it
right, and it is the only program allowed to reach the time servers (`NTP_UPSTREAM`).

#### The ISSO's duties

On the server, as root:

1. Read the daily review (`chp-site review`) and sign it. Publications show as routine. Overrides show under
   "Needs attention" until the review that covers them is signed. A day whose ledger did not verify keeps every
   override listed: the review says it cannot list them.
2. Check the ledger: `chp-site doc-ledger verify` (exit 0 good, 1 a problem, 3 the appender was busy). With the
   site stick plugged in, `chp-site doc-ledger export` records the ledger's head on the stick, and
   `chp-site doc-ledger verify --stick` checks the ledger against the heads kept there (exit 2 if the stick is
   absent).
3. Look for unfinished publishes: `chp-site doc-ledger pending` (exit 0 none, 1 some, 2 cannot tell, 3 busy).
   A line is a publish that started and never finished, or whose undo was incomplete ("UNDO INCOMPLETE": parts may
   be in the area). Look at the document named, in its Compliance area and in Superseded. Put it right with an
   administrator. Then record what you checked and did:
   `chp-site doc-ledger resolve <request id> --reason "checked the area, nothing half-written"`.
   Until you resolve it, a re-sent publish with that request id is refused.
4. Look at the quarantine, which holds requests set aside as malformed (`/var/lib/chp-docs/quarantine`). Then clear
   it: `chp-site doc-ledger purge-quarantine`.

Monitor check 82 watches all of this: the ledger path unit is active, the chain verifies, the quarantine is empty,
and no publish is unfinished. If the appender holds the lock when the check runs, the check says "not checked this
run" and does not report all clear. After 4 runs in a row (about an hour) it alerts.

A publish that finished but whose record could not be removed (the journal says `unfinished-clear-failed`, level 7)
is not listed as pending: the ledger holds the publish.

#### When the database cannot do MD5

Under FIPS the database refuses the MD5 function that NextCloud uses for some moves. The server then runs in
**DEGRADED mode** (POA&M item T-08). `chp-site documents status` and the nightly check say "DEGRADED: database MD5
unavailable". The first refusal each day raises a level-7 alert. It ends by itself when the database can compute MD5.

What works:

- Uploading, downloading, editing, renaming and deleting **files**.
- Copying files.
- Making, renaming and deleting **empty** folders.
- Moving files from one folder to another inside the same team folder.
- Moving a file CUI to Archive, or Archive to CUI, when the file has no old versions.

What is refused:

- Moving, renaming or deleting a folder that has files in it.
- Moving a file that has old versions to another team folder.

Copying or moving out of CUI, FCI or Archive to any other place is refused in any case. The only exceptions are CUI
to Archive and Archive to CUI.

To change a folder with files in it, an administrator can do it one file at a time. **These steps are not yet
proven in the lab.** Read all of them first.

- Never use them on a Compliance or Superseded area, or on a team folder's root.
- Folder access rules (groupfolders advanced permissions) belong to the old folder. A new folder takes its parent's
  rules, not the old folder's. If the old folder has any rule of its own, copy the same rules to the new folder
  before you move a single file, or stop and ask the administrator.
- Every delete in CUI, FCI or Archive raises a level-7 alert (Wazuh 100606). Tell the ISSO first.

1. Check the old folder for access rules of its own, as above.
2. Make the new folder, then any folder that goes inside it, from the top down. Give them the old folder's rules.
3. Move the files into the new folders one by one. A single file moved inside its own team folder works.
4. Check that the old folders hold nothing any more.
5. Delete the empty old folders from the bottom up. A folder with files in it is refused.

**Not supported in 0.7.0:** moving a file that has old versions to another team folder. A copy is a new file and
the old versions are not carried. If they must be kept, leave the file where it is until DEGRADED ends.

If `publish` says the old version could not be moved to Superseded (DEGRADED), nothing was changed. The new copy was
removed. This happens only when the published file has old versions, which a normal publish never creates. Keep the
approved file. Tell the ISSO and an administrator. There is no way around it and nobody moves files on the disk by
hand. Run `publish` again once `chp-site documents status` no longer says DEGRADED.

#### Site rules

1. **Download then re-upload.** A person who can download a CUI file can upload it somewhere else. The server cannot
   stop that, and the owner accepted it as an insider risk. CUI taken from the document server is never uploaded
   outside the CUI folders. Every download and upload is logged (Wazuh 100607 and 100621, level 3). The ISSO reviews
   those records. This is also recorded in the SSP (3.1.3).
2. **No sharing.** Sharing is off in CUI, FCI and Archive. A share there raises a level-12 alert at once.
3. **Alert text carries CUI file names and paths.** Wazuh alerts go to `ALERT_HOOK`. The site delivers them only
   inside the CUI boundary, or to a channel that is authorised for CUI.
4. **The audit log and the Wazuh index are CUI-boundary records.** Keep them on the appliance. Backups under
   `/backup/nextcloud` hold the documents and are inside the boundary too.
5. **FCI marking.** As built, FCI documents carry the CUI banner. Whether FCI needs its own marking is under review.
   The names still use the `FCI_` prefix.

#### ONLYOFFICE on the workstation

- **Open it once first.** Before the first `chp-site doc publish` on a workstation, start ONLYOFFICE from the desktop
  and close it. That first run builds its font list (`AllFonts.js`), which the reader PDF needs. It is once per
  person on each workstation, not once per file. Until then `publish` refuses and says so.
- **AI and start-page features are off.** The AI Tools plugin is removed at install and again after every ONLYOFFICE
  upgrade. A settings file hides the AI entries on the start page, turns off update checks, plugins and cloud
  portals. The plugin removal is best effort and nothing watches it: after each ONLYOFFICE upgrade, check that the AI Tools
  plugin folder is gone. The egress table and the hosts block are the controls that hold either way.
- **Recovery copies are CUI.** ONLYOFFICE keeps autosave copies. `chp-site doc close` removes them. An hourly sweep
  removes the rest, but only for a person who has no process running at all, and only copies older than 12 hours.
- **The whole workstation is confined, Firefox included.** Outgoing connections go only to the site server
  (ports 22, 443, 8443, 1514 and 9000, and ping) and to the site resolver for DNS. Time comes only from chrony, to the
  `NTP_UPSTREAM` addresses when every entry is an address, otherwise to any address. The workstation has no
  internet. This is by design.
- **Sessions end at logout.** `KillUserProcesses=yes` (from the next boot) and an hourly `disable-linger` apply to **all** accounts, not
  only ordinary users (only root is left out of the kill). An administrator's `tmux` or `screen` session ends when
  the administrator logs out. A rule refuses `loginctl enable-linger` for everyone but root. If linger is on anyway,
  `chp-site doc login` refuses and says how to turn it off (`loginctl disable-linger <account>`).
- **Egress lock-down.** If the workstation's egress table cannot load at boot (a damaged site file and no earlier
  good one), the workstation falls to loopback only. Nothing leaves it, not even replies to ssh. The journal line is
  `EGRESS LOCKDOWN` (Wazuh 100628, level 12). It arrives only after the link is back. The first live sign is the
  server's "agent disconnected" check (71). Monitor check 83 on the workstation alerts every 15 minutes while it
  lasts, but that alert cannot leave the workstation either: it is seen at the console, or after recovery. To recover, at the console:
  1. Read `journalctl -u chp-workstation-egress` and fix the cause.
  2. Run `systemctl restart chp-workstation-egress`. A good load removes the lock-down.
  3. Check 83 turns to OK at its next run.

#### Alerts you will see

| Wazuh rule | Level | When |
|---|---|---|
| 100642 | 12 | An approval was recorded. |
| 100643 | 12 | An ISSO override was recorded. |
| 100644 | 7 | A document was published. |
| 100641, 100649, 100653, 100654 | 3 | Checkout, new, publish start, other ledger lines. |
| 100645 | 12 | A malformed request was set aside (quarantine). |
| 100646 | 12 | The ledger appender failed. |
| 100647 | 12 | A publish failed and its undo was incomplete. |
| 100648 | 12 | The ledger may end in a partial line. |
| 100655 | 12 | The record of an unfinished publish could not be written. |
| 100650, 100651, 100652 | 7 | A publish was undone, an unfinished publish was resolved, an appender problem. |
| 100629 | 12 | The Kanidm sign-in added an account to `admin` or `cui-users`. It pages once for each new CUI reader's first sign-in. |
| 100623 | 12 | An account or group was changed inside NextCloud. The **first** `documents enable` raises it twice. Tell the ISSO first. |
| 100609 | 12 | `chp-canary` was enabled outside 03:05-03:45. Running `chp-site documents check` by hand does this. |
| 100626 | 3 | The sweep removed a recovery copy. |
| 100631, 100632, 100627 | 7 | The sweep failed, the egress addresses did not render, a packet was refused. |
| 100628 | 12 | Egress lock-down. |

**Keep `SECURITY_ALERT_LEVEL` at 12 or lower while `DOCUMENTS=yes`.** Approvals and overrides are level 12. Above
that, they reach only the daily summary, and the detection that T-13 relies on is gone.

The ledger forgery residual (POA&M item T-13): anyone with a shell on the server can write false
`chp-docs-ledger` lines to the journal (`logger -t chp-docs-ledger`). That can raise a false level-12 alert. It never
hides a real event: check 82 and the daily review trust only the ledger and root's own journal lines.

After **any Wazuh upgrade**, prove the ledger rules again with `wazuh-logtest`. A `chp-docs-ledger` line must come
out as one of the 1006xx rules above. Its base rule (100640) is level 15 on purpose, so it is tried before Wazuh's own
syslog rules. A line that comes out as a stock rule means the family needs fixing.

#### Accounts outside Kanidm

Three NextCloud accounts are local and are not in Kanidm. Record all three in the SSP's account types and name an
owner for each (POA&M item T-15).

- **`chp-publisher`** is the ledger appender's account. It alone writes the Compliance and Superseded areas. It has
  no usable password: a random one is set at every `chp-site documents enable` and thrown away.
- **`chp-canary`** is the nightly share test. It is switched off between runs. The nightly check (03:10) switches it
  on for a few minutes inside 03:05-03:45.
- **`ncadmin`** is the break-glass NextCloud administrator, made by `chp-site documents enable`. It is the one of the
  three that has a usable password. It signs in at `/login?direct=1`, and every sign-in pages at level 12 (Wazuh
  100622). Its password is written to the site stick, in `escrow/` (a file named `<host>-nextcloud-admin.secret`),
  and shredded on the server. Keep the stick safe; use the account only in an emergency.

#### New installs, and the upgrade notes

**0.7.0 is for new installs only.** The disk layout and the place of NextCloud on `/data` do not fit older installs.
A site that has an earlier version moves by reinstalling. There is no upgrade path for the document server.

If you upgrade `chp-documents` anyway, know these two things:

- The NextCloud sign-in rewrite is live as soon as the package is installed, before `chp-site documents enable`
  runs. It sends `/login` straight to Kanidm, so Kanidm must be user_oidc provider number 1. `documents enable`
  refuses if it is not.
- `/etc/httpd/conf.d/chp-nextcloud.conf` is kept if you edited it. The new file arrives beside it as
  `chp-nextcloud.conf.rpmnew` and holds a new `Include` line. If you do not merge it, the login page shows **two
  buttons**. To merge: add the two lines below, inside the `<VirtualHost>`, right after `RewriteEngine On`. Then run
  `apachectl configtest` and `systemctl reload httpd`.

      # /login straight to Kanidm with two user_oidc providers (ISO 0.7.0 Plan 3)
      Include /etc/httpd/conf.d/chp-nextcloud-login-rewrite.inc

#### Open items

These are recorded for the SSP and the POA&M. The seed rows are in `poam-seeds-0.7.0.md` in this kit, and the
release's known issues are in `docs/release/0.7.0-known-issues.md` in the project repository.

| Id | Item |
|---|---|
| T-08 | MD5 degraded mode |
| T-09 | fapolicyd filesystem marks off, and the restart crash |
| T-10 | ONLYOFFICE: non-validated crypto and `--no-sandbox` |
| T-11 | Move off PHP 8.3 before NextCloud 37 |
| T-12 | The OIDC code in NextCloud's audit log |
| T-13 | Ledger forgery residual, with detection |
| T-14 | DNS tunnelling through the site resolver |
| T-15 | `chp-publisher` and `chp-canary` outside Kanidm |
| T-16 | The banner check reads text only |

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
- A server disk under 1.9 TB works, and the installer says so: the note is written to the install log
  (`/var/log/anaconda/program.log`) and as a `DISK_NOTE` line in the host's escrow file on the site stick. It is a
  note, not a stop. (The install-complete screen does not show it.)

**The layout** (sizes in GiB, rounded down; the volumes are in the encrypted volume group `chp`). The columns assume
real disk sizes in bytes: a 2 TB disk is 2,000,398,934,016 bytes, a 1 TB disk 1,000,204,886,016 and a 512 GB disk
512,110,190,592. Your disk's exact size moves the last three server rows and the free space by a few GiB.

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
| `/backup` | 600 | 234 | none |
| **left free in the volume group** | **342** | **135** | **277** |

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
The new mount is marked `nofail`, so a dead backup drive does not stop the server booting. The runbook also makes the
empty `/backup` folder immutable and enables `clevis-luks-askpass.path` (so the TPM unlocks the drive at boot). While the
drive is missing, writes to `/backup` then fail loudly instead of filling `/`.

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
From 0.6.0 on (chp-site 0.13.0) signing needs a terminal (piped input no longer counts as consent), `--date` must be
`YYYY-MM-DD`, `--notes` is at most 1000 characters with no control characters, and a second signer at the same moment
is refused.

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
