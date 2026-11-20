# chp-onlyoffice

The workstation side of the controlled-document workflow's editor (ISO 0.7.0 Plan 3 Task 8). It turns the editor
spike's gate items G2, G3 and G4 (`lab/docs-spike/SPIKE-NEXTCLOUD.md`, §Editor) and ruling F3 (linger) into a
package. ONLYOFFICE Desktop Editors 10.0.0 itself is the **vendor's RPM, re-signed with the project key**: the repo
carries the vendor's yum-repository file, its sha256 and header digest pinned in `appliance/release/VENDOR.txt`
(`stage-vendor.sh` checks the vendor signature, then strips it; `sign-repo.sh` signs only a pinned file).

Nothing runs until `chp-site onlyoffice enable` (root; client enrolment's `docs` step does it when the site has
`DOCUMENTS=yes`).

## What it does

| Gate | What | Where |
|---|---|---|
| G4 | removes the **AI Tools** plugin (`sdkjs-plugins/{9DC93CDB-…}`, agent tools `run_script`, `file_opener`) | `/usr/libexec/chp/onlyoffice-ai-off`: `%post`, `%posttrans`, trigger on every install/upgrade of `onlyoffice-desktopeditors`; `enable` refuses while it exists |
| G4 | system-wide defaults: no update check, portals locked, plugins off, start-page AI entries hidden | `/etc/xdg/onlyoffice/DesktopEditors.conf` |
| G4 | the vendor names lead to `0.0.0.0` (defence in depth, as the spike proved) | `/etc/hosts`, a marked block written by `enable` |
| G3 | the whole workstation may reach only the site server (22, 443, 8443, 1514, 9000, ping) and the site resolver (53 udp/tcp); DoT/DoQ 853 refused to anyone; DNS to anyone else refused over IPv4 and IPv6; DoH (443 elsewhere) refused by the default rule; NTP only from chronyd, to the upstream addresses; loopback-only lock-down when the table cannot load | `/etc/nftables/chp-workstation-{egress,lockdown}.nft`, `chp-workstation-egress{,-lockdown}.service` |
| G2 | hourly sweep of ONLYOFFICE's auto-recovery copies (`~/.local/share/onlyoffice/desktopeditors/data/recover/DE__*`) and their `recents.xml` entries | `chp-onlyoffice-sweep.timer` → `chp-site onlyoffice sweep` |
| F3 | logout ends the user's processes; linger off (and refused) | `/etc/systemd/logind.conf.d/50-chp-docs.conf`, `/etc/polkit-1/rules.d/50-chp-no-linger.rules`; `enable` and the sweep run `loginctl disable-linger` for anyone who has it |

### The sweep (G2)

- A user is swept only when **no process of that user runs at all**: not while ONLYOFFICE (`DesktopEditors`,
  `editors_helper`) runs, and not while the user is logged in. `recover/` is also the editor's crash recovery, so a
  live session's copies are never touched.
- Only recovery folders whose newest file is older than **12 h** go. A document that also has a younger copy keeps
  its `recents.xml` entry.
- The removal runs **as that user** (the root service forks a child that drops to the owner of the home folder), with
  `chp_site.doc.remove_editor_copies`, the same function as `chp-site doc close`. Symbolic links on the way are
  reported and skipped.
- Every removal is one line `removed <path> (user …, uid …; no live session; older than 12 h)` under the journal tag
  **`chp-doc-sweep`**. Wazuh rule 100626 stores it (level 3), and also `linger turned off for …`.

### The egress table (G3)

- It is a separate table, `inet chp_workstation_egress`, so firewalld's table and its reloads are left alone. A packet
  this table drops stays dropped.
- The addresses come from the site files. `chp-site onlyoffice egress-render` writes
  `/etc/chp/workstation-egress-addr.nft` before every load, so a re-IP of the server needs only a restart.
- The resolver is the server's address, because clients resolve through the server.
- The unit has **no ExecStop**. Stopping it leaves the table in place (fail closed); only removing the package deletes
  the table.
- **At boot it fails closed too.** A render failure (a damaged site file, a bad address) is not fatal: the last good
  address file is loaded (a failed render never overwrites it). With no file, or when nft refuses the table, the unit
  fails and `OnFailure=` starts `chp-workstation-egress-lockdown.service`: the table `inet chp_workstation_lockdown`
  lets only loopback out, and the journal line `EGRESS LOCKDOWN` (tag `chp-egress-lockdown`) is Wazuh rule 100628,
  level 12. The agent cannot send until the link is back, so the manager's disconnected-agent check (71) is the first
  signal. Fix the cause, then `systemctl restart chp-workstation-egress`: a good load removes the lock-down table.
- NTP leaves only from chronyd, and only to the `NTP_UPSTREAM` addresses when every entry is an address; when any
  entry is a host name, to any address.
- Refused packets are logged with the prefix `CHP-WS-EGRESS` (DNS: `CHP-WS-EGRESS-DNS`), at most 6 a minute. Wazuh
  rule 100627 puts them in the daily summary (level 7).
- Multicast and broadcast are dropped without a log line.
- **Firefox and every other program are confined too.** The workstation has no internet, by design (owner, Plan 3).

## Expected findings

- `rpm -V onlyoffice-desktopeditors` reports the AI Tools folder missing. That is expected (G4).
- AIDE sees `/etc/hosts` and `/etc/chp/workstation-egress-addr.nft` change at `enable`, and again when the server's
  address changes.

## POA&M items (Task 10 writes the guide and the seed items)

1. **Non-validated crypto in the editor.** ONLYOFFICE bundles Chromium (CEF, `libcef.so`) with **BoringSSL** linked
   in. It does not read the system's FIPS mode or crypto policy and is **not FIPS-validated**.
   - In this workflow the editor makes no TLS connection: it opens and saves local files, and `chp-site doc` (the
     system OpenSSL) does the transport.
   - Its network features are blocked: the egress table, the hosts block and the preseed.
   - Seed text: "ONLYOFFICE bundles a non-validated TLS stack (Chromium BoringSSL); network features are blocked."
2. **Chromium runs `--no-sandbox`** (`chrome-sandbox` is not setuid). The embedded browser shows only local app
   content here. This is an owner-level risk statement.
3. **The app runs `unconfined_t`** (the users are unconfined), 1.2 GB under `/opt/onlyoffice`.
4. **Auto-recovery copies are CUI outside the working folder** until the sweep (12 h after the last session) or
   `chp-site doc close` removes them. They sit on the workstation's LUKS2 disk, in a home folder of mode 0700.

## Not proven here (Task 11, live)

The unit tests run on a Mac. They check the files and evaluate the rule forms against the rendered addresses. They
do **not** load the table into a kernel. The following still need a live check on a workstation:

- the table loads with firewalld running and survives `firewall-cmd --reload`;
- the egress test with an IPv6 default route present and a tap capture;
- chronyd's NTP sockets carry the uid `chrony`, and `meta skuid "chrony"` resolves at early boot (before
  kanidm-unixd runs);
- the reset or ICMP error that firewalld's input `reject` sends may have no socket and no established state: it may
  then be dropped and logged here (a remote host sees a timeout instead of a refusal);
- the Qt `/etc/xdg` fallback is read, and the `useai`/`pluginsDisabled`/`lockPortals` keys have an effect (the spike
  saw none for the last two);
- the trigger runs on a vendor upgrade;
- `KillUserProcesses=yes` after a reboot;
- the polkit rule refuses `loginctl enable-linger` for a user;
- the sweep's privilege drop under SELinux and fapolicyd;
- Wazuh rules 100626, 100627 and 100628, with `wazuh-logtest`;
- the lock-down: break the site files with no address file present, reboot, and see the lock-down table and the
  alert after recovery.
