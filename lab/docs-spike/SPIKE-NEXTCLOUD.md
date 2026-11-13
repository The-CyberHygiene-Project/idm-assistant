# Spike: NextCloud on a hardened CHP server (ISO 0.7.0 Plan 1, Task 1)

**Result: NextCloud 35.0.3 runs on a FIPS, SELinux-enforcing, fapolicyd, CUI-profile CHP server installed from ISO
0.6.0, signs in through Kanidm (password + TOTP), never reaches the internet, refuses every share of CUI/FCI, tags by
folder, audits to Wazuh, and restores from `/backup`. No product blocker.** Every step below was run on the lab
(2026-11-12); raw output is in `logs/` (numbered in run order). Rebuild: `README.md`.

Five findings matter beyond NextCloud and need decisions in Plan 2 (details in their sections; review fixes of
2026-11-12 in `logs/38-42`):

1. **fapolicyd does not check file opens by processes in their own mount namespace while `allow_filesystem_mark = 0`.**
   Observed on iso5-docs (server) and iso5-dcli (client): `head` of an untrusted `.php` file is denied in the host
   namespace and allowed under `systemd-run -p PrivateTmp=yes` (`logs/31`); php-fpm (`PrivateTmp=yes`) downloaded users'
   `.php`/`.py` files unchecked (`logs/30`). `allow_filesystem_mark = 0` is the RHEL default and CHP never changes it, so
   the other CHP hosts are probably affected too, but they were **not tested**. Only file **opens** on `/data`, `/home`
   were tested; **execute** and other mounts were not. Units that run in their own mount namespace on these two hosts
   (`logs/39`): chronyd, dbus-broker, irqbalance, kanidm-unixd(-tasks), ModemManager, NetworkManager, rsyslog, suricata,
   systemd-logind, systemd-udevd, usbguard on both; plus httpd, php-fpm, kanidmd, named, step-ca on the server (Wazuh
   is not among them). **Turning it on is not simply "stricter": it broke php-fpm's downloads of users' script files at
   once (HTTP 503, `logs/32`) until rule 65 was added.** On released hosts it may start blocking daemons that work
   today only because they are unchecked (suricata, kanidmd, named, step-ca, …). Plan 2 must trial it per host role
   (server and workstation) before shipping it. iso5-docs runs with it on since `logs/31`; iso5-dcli is as installed.
2. **The "0 FANOTIFY records" gates and the collector's fapolicyd signal: not shown blind, but not a full count
   either.** Side-by-side (`logs/38`): a php-fpm denial (daemon, no login uid) added 2 FANOTIFY records and 2 to
   `fapolicyd-cli --check-status`; an admin-session denial added 1 and 1. So **daemon denials do reach the audit log**
   here; my first claim that they do not was wrong. What was observed: early in the work the counter said 8 denials
   while the audit log held 3 FANOTIFY records (`logs/11`), unexplained; the counter resets when fapolicyd restarts while
   the audit log does not; and `fagenrules --load` does not drop fapolicyd's decision cache (a removed rule kept
   allowing until a restart, `logs/38`), so a gate run right after a rule change can pass on stale decisions. The places
   that rely on the FANOTIFY count (not changed now; Plan 2 decides): `lab/iso5/prove.sh` 82, 169, 360;
   `lab/iso4/prove.sh` 52, 187, 301; `lab/iso3/prove.sh` 71, 132; `lab/security/prove-r1.sh` 58, `prove-s1.sh` 60, 121,
   `prove-w1.sh` 50, `prove-y1.sh` 55; `lab/host/iso1-install-test.sh` 42; the **shipped** collector
   `collector/idm-collect` 266 (`ausearch -m FANOTIFY -ts recent`, `resp=2`); and the records that cite those gates:
   `appliance/release/RELEASE-RECORD-0.1.0.md` (53, 60: "0 FANOTIFY events ever"), `0.1.1`, `0.5.6`, `0.7.8`,
   `lab/iso3`, `lab/iso4`, `lab/iso5` PROOF-RECORDs, `lab/security/PROOF-RECORD-{ISO-0.6.0,W1,W2,Y1,R1,S1}.md`,
   `SPIKE-{SURICATA,YARA,REVIEW}.md`, `lab/aide/PROOF-RECORD.md`, `lab/iso-requirements.md`. **The diagnostic
   collector's fapolicyd signal and every past "0 denials" gate share finding 1's blind spot**: a denial that never
   happens (because a namespaced daemon is not checked) is counted by neither method.
3. **Kanidm owns `SERVER_IP:443`**, so NextCloud cannot also use 443 on the server's address. The spike serves
   `https://files.docs.lab.test:8443` (Plan 2 options below).
4. **PHP 8.3 is the newest PHP stream on the Rocky 9.8 DVD** (`dnf module list`: 8.1, 8.2, 8.3; `logs/42`) **and
   NextCloud 35 already calls it deprecated** ("Nextcloud 37 may require at least PHP 8.4"). NextCloud 35 runs on it
   (shown); that 36 will too is an **inference** from that message, not shown. The product needs a plan before 37.
5. **Copy-out-of-CUI bypass** (`logs/41`): a `cui-users` member also has write + share in Operations and their own home,
   so a CUI file copied or moved there could be shared internally and by public link, and lab02 read it; a copy carries
   no tag. A prototype control (refuse copy/move out of CUI/FCI/Archive) stops the WebDAV/browser copy and move;
   **download then re-upload still works**, which nothing in NextCloud stops: an owner decision (§Copy out).

## Lab

| Host | Role | Disk | Notes |
|---|---|---|---|
| iso5-docs | server, 192.168.100.53, `52:54:00:c4:05:53` | 1863 GiB sparse, size guard 50 GB (never tripped; image 14 GB at the end) | raised to 8 GiB RAM / 4 vCPU after the scan (`install.sh mem`) |
| iso5-dcli | client, 192.168.100.54, `52:54:00:c4:05:54` | 120 GiB | for row 36 |

**Hosts table: not one row added to `lab/iso5/hosts` but a separate lab site** (`hosts`, `site.conf.in`,
`docs.lab.test`, `SECURITY_ADDONS=yes`), because `chp_site/hosts.py` allows exactly one server per site and NextCloud
belongs on the server that runs Kanidm. The iso5 lab was not touched (its helpers in `aero:/tmp/iso2` are reused, never
deleted). Install chain: `install.sh prep/server/firstboot/export/client` all PASS (`logs/01-06`), from the released
ISO 0.6.0-rc2 (sha256 `0cb27c14…7cac0`, checked on aero).

**CUI scan before anything: 108 pass / 2 fail on both hosts** (the two accepted AIDE rules,
`aide_periodic_cron_checking`, `aide_scan_notification`; `scan-results/*.xml.xz` (xz, as earlier proof records), `logs/07`). **After all the NextCloud work:
108 / 2 on iso5-docs, the same two rules** (`scan-results/after-nextcloud/iso5-docs.xml.xz`): NextCloud, httpd, PHP, PostgreSQL, the
egress table and the fapolicyd changes moved no rule.

## Packages (Step 2)

All from the **Rocky 9.8 DVD** (`aero:/data/lab-inputs/Rocky-9.8-x86_64-dvd.iso`, sha256 = the published CHECKSUM),
attached read-only to the server as a virtio disk and used with `--repofrompath` and `gpgcheck=1` (`spike.sh dvd-on`;
SATA cannot hot-plug and USBGuard correctly blocks a USB disk). Every installed httpd, mod_ssl, apr, php and postgresql
package carries `RSA/SHA256 … Key ID 702d426d350d275d` (Rocky Release key 2022, in the rpm database), and `rpm -K` of
the DVD's php-fpm and postgresql-server packages says `digests signatures OK` (`logs/42`).

| Choice | Version | Why |
|---|---|---|
| PHP | `php:8.3` stream, 8.3.29 (php-fpm, -cli, -gd, -mbstring, -intl, -xml, -pgsql, -process, -bcmath, -gmp, -opcache, -pecl-zip, -pecl-apcu) | NextCloud 35 needs PHP >= 8.3 (`lib/versioncheck.php`: 8.3 to < 8.6); 8.3 is the newest stream on the DVD (`dnf module list`, `logs/42`). **No php-sodium in Rocky** (libsodium is EPEL-only): NextCloud lists it as recommended, not required. |
| Database | `postgresql:16`, 16.13 | NextCloud 35 supports 14 to 18. Unix socket only (`listen_addresses = ''`), **peer authentication**: the OS user `apache` is the database role, so there is **no database password anywhere**; `password_encryption` is scram-sha-256 (FIPS-safe) for any later password. 15 and 18 are also on the DVD (`logs/42`); 16 chosen as the middle of NextCloud's window. |
| Web server | httpd 2.4.62 + mod_ssl + php-fpm (proxy_fcgi) | the stock SELinux `httpd_t` policy covers it; NextCloud's shipped `.htaccess` works. Only one listener (`*:8443`): `Listen 80` commented out, `ssl.conf`/`welcome.conf`/`userdir.conf`/`autoindex.conf` disabled. |
| Cache | APCu (`memcache.local`), file locking in the database | no extra daemon; Redis not needed at this size |

**NextCloud** 35.0.3 (current stable, built 2026-11-12): sha256 = the published `.sha256` and a good GPG signature by
Nextcloud Security `2880 6A87 8AE4 23A2 8372 792E D758 99B9 A724 937A`. **App-store apps** (`fetch-inputs.sh`): each
release's RSA-SHA512 signature verified with the app's certificate, and that certificate verified against the
NextCloud code-signing root shipped in the (verified) server tarball, CN = app id: groupfolders 23.0.1 (Team folders),
files_accesscontrol 6.0.1, user_oidc 8.13.0 (`MANIFEST.txt`). Shipped in the server tarball already: systemtags,
admin_audit, password_policy, bruteforcesettings, files_downloadlimit, workflowengine. Plus the spike's own
`chp_foldertag` (Step 7).

**The spike RPM** `nextcloud-chp-35.0.3-0.spike4.el9.noarch` (`nextcloud.spec`, 33,895 files, 250 MB,
sha256 `84ed0ee0…a7b6986`): **unsigned. Trust decision recorded: installed with `dnf --nogpgcheck` on the server
(`localpkg_gpgcheck = 1` refuses it otherwise); fapolicyd then trusts its files through the rpm database like any
installed package.** Plan 2 signs it into the repo.

- **Build host: the Mac (Homebrew rpm 6.1, `_rpmformat 4`), not aero.** aero runs fapolicyd, which denies any process
  reading untrusted PHP/JS (`70-trusted-lang.rules`), so `rpmbuild`'s `%install` copy failed there. I tried to add a
  temporary aero fapolicyd rule for the build directory; **the permission system refused it** (it would weaken the
  hypervisor's control) and I did not work around it. **Plan 2 needs a decision:** a fapolicyd rule on aero
  limited to the build directory (owner approval), a small build VM, or the Mac. EL9's rpm 4.16 installs the
  Mac-built v4 package without complaint.
- **Code under `/usr/lib/nextcloud`, not `/usr/share`.** fapolicyd's `fapolicyd-filter.conf` drops `/usr/share/` from the
  trust database except `*.php`, `*.js`…, so `occ` (no extension) and every `*.mjs` would be untrusted: `occ` failed
  with "Operation not permitted" (spike2, `logs/11`). Under `/usr/lib` every file is in the trust database except types
  the filter drops everywhere (json, html, png, md: 5,348 files, none a language type).
- Config in `/etc/nextcloud` (`apache`, `httpd_sys_rw_content_t`), symlinked from the code tree; data on
  `/data/nextcloud/data` (the 0.6.0 `/data` LV, `rw,nosuid,nodev`); logs in `/var/log/nextcloud`.

## Under the CUI profile (Step 3): every denial and its fix

| # | What failed | Cause | Minimal fix |
|---|---|---|---|
| 1 | `occ` "Could not open input file" | fapolicyd trust filter drops `/usr/share` | code tree moved to `/usr/lib/nextcloud` (package) |
| 2 | install: "Can't write into config directory" (EPERM on `config.php`) | `config.php` is PHP that NextCloud writes itself: untrusted | **trust entry** `fapolicyd-cli --file add /etc/nextcloud/config.php --trust-file nextcloud` (path trust; CHP uses `integrity = none`, so later rewrites stay trusted) |
| 3 | `password_hash` "Password hashing failed" | **FIPS: PHP's Argon2id does not work** | `hashing_default_password = true` (bcrypt) for the one local account (break-glass admin); people have no NextCloud password |
| 4 | httpd would not start | mod_ssl's `Listen 443` collides with Kanidm on `SERVER_IP:443` | httpd listens on 8443 only |
| 5 | NextCloud could not reach Kanidm (curl error 7; `strace`: `connect() = -EACCES`, **no AVC even with dontaudit off**) | SELinux: `httpd_t` may not connect to `http_port_t` | **boolean `httpd_can_network_relay = on`** (http ports only; not `httpd_can_network_connect`); the egress rule limits where to |
| 6 | downloads of users' `.py`/`.php` files: HTTP 503 (once filesystem marks were on) | fapolicyd: a stored script is "untrusted language" even when only read | **rule** `rules.d/65-chp-nextcloud.rules`: `allow perm=open exe=/usr/sbin/php-fpm : dir=/data/nextcloud/data/ ftype=%languages` (+ `/usr/bin/php`, and `rsync`/`sha256sum` for the backup); open only, never execute; other programs stay denied (`logs/32`) |
| 7 | `firewall-cmd` rule let in only `192.168.100.0` | my mistake: `chp-site get SUBNET` is the network address; the CIDR is `chp-site get SUBNET_CIDR` (`192.168.100.0/24`, `logs/40`) | the spike reads `SUBNET` from `site.conf` (Plan 2: use `SUBNET_CIDR`; a `SUBNET_CIDR` key or fix `get`) |
| 8 | the audit log stayed empty | admin_audit writes at level 1; `loglevel = 2` drops it | `log.condition = {apps: [admin_audit]}` |

**At the end: 0 left.** After the final reboot, a full run (four OIDC sign-ins with the Files page and its 57 scripts
and styles, uploads, tags, shares, visibility, a backup, the tag check) gave **"Denied accesses: 0" of 63,621, and 0 AVC
records since boot** (`logs/35`), with filesystem marks on. The only denials seen during the work were the cases in
the table and the deliberate negatives.

**HTTPS:** `files.docs.lab.test` added to the site zone (`files IN A SERVER_IP`, serial bumped, `rndc reload`); the
certificate comes from the site's step-ca over ACME exactly as Kanidm's does (`step-cli ca certificate … --provisioner
acme --kty EC --crv P-384`, port 80 opened only for the challenge): `CN=files.docs.lab.test`, issuer
`docs.lab.test CA Intermediate CA`, 24 h. Renewal: not yet automated in the spike. ACME (http-01) needs port 80
opened for each issue, as `cert-renew-kanidm` does (`step ca renew` while still valid needs no port); Plan 2 needs a
timer like Kanidm's, with `systemctl reload httpd`. **firewalld:** `rule family=ipv4 source address=192.168.100.0/24 port port=8443
protocol=tcp accept` (LAN only); reached from aero (192.168.100.1): 200 (`logs/12`).

**Port choice for Plan 2 (Kanidm has `SERVER_IP:443`):** (a) keep NextCloud on 8443 (no change to anything existing;
users type `:8443`; the spike's choice); (b) a second server address for `files.` (hosts table gains an optional
field); (c) an SNI router in front of both (changes the identity server's front door). Recommendation: (a).

## No internet (Step 4) — §Outbound

**Settings:** `has_internet_connection = false`, `appstoreenabled = false`, `updatechecker = false`,
`upgrade.disable-web = true`, `lookup_server = ''`, `gs.enabled = false`, `reference_opengraph = false`,
`knowledgebaseenabled = false`, `check_for_working_wellknown_setup = false`, `enable_previews = false`; apps off:
`text office firstrunwizard recommendations survey_client nextcloud_announcements updatenotification federation
sharebymail weather_status support app_api webhook_listeners files_external contactsinteraction dashboard circles
photos related_resources user_status files_reminders privacy suspicious_login`; outgoing/incoming federation and
lookup-server sharing off (`files_sharing` app config). `federatedfilesharing`, `lookup_server_connector` and
`cloud_federation_api` cannot be disabled (core); their settings are off.

**Below the application:** an nftables table of its own, `inet chp_nextcloud_egress` (`pkg/nextcloud-egress.nft`,
loaded by `chp-nextcloud-egress.service` before php-fpm/httpd; survives `firewall-cmd --reload`): packets whose socket
belongs to `apache` (php-fpm workers, cron, occ) may go only to loopback and the server's own address; anything else is
**logged (`CHP-NC-EGRESS`, with UID) and rejected**. SELinux: `httpd_can_network_connect` stays **off**; only
`httpd_can_network_relay` is on (fix 5). In the lab only (not product properties): the bridge has no route out (aero
`ip_forward = 0`) and the site DNS has no forwarders (`recursion no`; `apps.nextcloud.com`: no answer).

**Proof (`logs/21`):** a probe OIDC provider whose discovery URL is an internet address (93.184.215.14) made NextCloud's
own HTTP client in **php-fpm (`httpd_t`)** connect when the login route was requested: NextCloud logged "cURL error 7:
Failed to connect to 93.184.215.14 port 443: Connection refused" and the kernel logged
`CHP-NC-EGRESS … DST=93.184.215.14 … DPT=443 … UID=48 GID=48`; the rule's counter rose. The same from the apache user
outside the web server (curl to 1.1.1.1:443, a TCP connect to 8.8.8.8:53): refused and logged. The probe provider was
deleted. **A bug found and fixed:** the first rule (`meta skuid != apache accept`) does not match packets that have no
socket, so the kernel's own IGMP/MLD reports were refused after the reboot; the rule now jumps on a positive
`meta skuid "apache"` match.

**Limits of the egress rule, and Plan 2 prototypes (`logs/40`):**

- **Any service on the server's own address is allowed.** The local resolver is the main one: at a site with
  `DNS_FORWARDERS` set, named recurses (`recursion yes; forward only`, `render.py` 78-80), so DNS queries from NextCloud
  could tunnel data out; any local relay or proxy on the server would do the same. **Prototype:** the apache user gets
  no DNS at all (`pkg/nextcloud-egress-nodns.nft`: port 53 logged as `CHP-NC-EGRESS-DNS` and refused) and NextCloud's own
  names (`idm.`, `files.`) come from `/etc/hosts`. Result: `dig @SERVER_IP example.com` as apache times out and is
  logged, and the Kanidm sign-in still works. That is the variant loaded on iso5-docs now. Proposal for Plan 2: ship
  that (hosts entries rendered from the site), or accept the resolver as a channel and document it.
- **If the table fails to load, NextCloud ran unblocked**: the unit was only `Before=` php-fpm/httpd. **Prototype**
  (`pkg/nextcloud-bindsto.conf`, a drop-in for php-fpm and httpd: `BindsTo=` + `After=` the egress unit, and
  `ExecStartPre=nft list table inet chp_nextcloud_egress`): with the table file missing, the egress unit fails and php-fpm
  and httpd stop and will not start ("A dependency job … failed"); with the table deleted at run time, the next php-fpm
  start fails on the pre-check. **Gap left:** deleting the table while php-fpm runs is not noticed until a restart; Plan 2
  needs a monitor check (table present, its rules intact).

**Admin overview (`occ setupchecks`, `logs/36`), every warning explained:** "Errors in the log: 9" = the deliberate
outbound probe and the two attempts before fix 5, plus background jobs of apps switched off; "Mimetype migrations" (a
maintenance command); "App directories owner" (by design: the code tree is root-owned and read-only); "PHP 8.3 is
deprecated" (finding 4); "imagick", "2FA not enforced" (sign-in is Kanidm's TOTP), "server ID", "remote address" (the
command line has none), "memcache for locking". **No outbound-attempt error is left unexplained.**

## Sign-in through Kanidm (Step 5)

Protocol: **OIDC** (user_oidc 8.13.0; Kanidm signs id tokens with **ES256**, user_oidc verifies it; **PKCE S256** on).
The exact Kanidm commands (as `idm_admin`; `logs/14`, `logs/15`, `kanidm.sh`):

```
kanidm group create cui-users ; kanidm group create doc-reviewers
kanidm person create lab01 "Docs Lab 01" ; kanidm group add-members chp_users lab01 ; kanidm group add-members cui-users lab01
kanidm person posix set lab01                      # lab01 only: host sign-in for row 36
kanidm person credential create-reset-token lab01  # then: kanidm person credential use-reset-token <t>
                                                   #   password -> totp (label, code) -> [unix-password] -> commit
kanidm system oauth2 create nextcloud "NextCloud" https://files.docs.lab.test:8443
kanidm system oauth2 add-redirect-url nextcloud https://files.docs.lab.test:8443/index.php/apps/user_oidc/code
kanidm system oauth2 update-scope-map nextcloud chp_users openid profile email groups
kanidm system oauth2 prefer-short-username nextcloud
kanidm system oauth2 update-claim-map nextcloud chp_groups cui-users cui-users
kanidm system oauth2 update-claim-map nextcloud chp_groups doc-reviewers doc-reviewers
kanidm system oauth2 update-claim-map nextcloud chp_groups chp_users chp-users
kanidm system oauth2 update-claim-map-join nextcloud chp_groups array
kanidm system oauth2 show-basic-secret nextcloud   # -> /etc/nextcloud/oidc-secret (0640 root:apache), never printed
```

NextCloud side (`setup.sh oidc`): `occ user_oidc:provider kanidm --clientid=nextcloud --clientsecret-file=…
--discoveryuri=https://idm.docs.lab.test/oauth2/openid/nextcloud/.well-known/openid-configuration --mapping-uid=preferred_username
--unique-uid=0 --mapping-groups=chp_groups --group-provisioning=1 --group-whitelist-regex='^(cui-users|doc-reviewers|chp-users)$'`;
`allow_multiple_user_backends = 0` (the login page goes straight to Kanidm; the break-glass admin uses `/login?direct=1`);
`occ security:certificates:import` of the site root (NextCloud has its own CA bundle); `allow_local_remote_servers =
true` (Kanidm is a LAN address; the egress rule is what limits destinations).

**Claims** (lab04, an id token from an identical throwaway client `claimprobe`, deleted afterwards; `logs/18`):
`iss https://idm.docs.lab.test/oauth2/openid/<client>`, `sub` (UUID), `preferred_username lab04`, `name "Docs Lab 04"`,
`chp_groups ["cui-users", "doc-reviewers"]`, `groups` (every group as UUID and `name@idm.docs.lab.test`, including
Kanidm's built-ins: hence the separate `chp_groups` claim), `scopes`, `auth_time`, `exp` (15 min), alg ES256. No email
claim (the lab people have none).

**Sign-in (`oidc_login.py`, a scripted browser through SSH tunnels: the same redirects and HTML forms):** NextCloud
-> Kanidm `/ui/oauth2` -> `/ui/login/begin` (user name) -> `/ui/login/totp` (code) -> `/ui/login/pw` (password) ->
consent -> NextCloud. `SIGNED IN: id=lab01 … groups=['cui-users'] backend=user_oidc` (`logs/17`); lab02/03/04 the same
with their groups (`logs/19`, `logs/23`). A wrong TOTP was refused ("Login Failed Reason: incorrect totp"; it happened
by accident: the lab clocks differ by about 8 s, so the script now takes the time from Kanidm's `Date` header).

**Host sign-in unchanged: row 36 3/3 on iso5-dcli** (`chp-site pam-test gdm-password lab01`, POSIX password + the host's
GA code; `PAM_OK` x3; token label `var_auth_t`; `logs/20`). Honest account: my first three runs sent no code (a script
bug), pam_faillock locked lab01 (`deny = 3`, `unlock_time = 0`, the CUI setting, correct), the lock made the next runs
fail even when GA and Kanidm accepted, an admin `faillock --reset` cleared it, then 3/3. The Kanidm web credential
(password + TOTP) and the host credential (POSIX password + host GA token) are separate, as the owner decided.

## Folders and sharing (Step 6)

All by `occ` (`folders.sh`; no web UI, no app password needed for any setting):

| Setting | Route |
|---|---|
| team folders | `occ groupfolders:create CUI` (… FCI, Archive, Operations, Internal, Public; ids 1-6, each its own storage) |
| access | `occ groupfolders:group <id> cui-users read write delete` (**no `share`**) for CUI/FCI/Archive; `… chp-users read write delete share` for the other three |
| advanced permissions | `occ groupfolders:permissions <id> --enable` |
| reviewer layer | `occ groupfolders:permissions <id> --group doc-reviewers -- / +read -write -create -delete -share` (all six) |
| sharing policy | `occ config:app:set core shareapi_allow_resharing no`, `shareapi_enforce_links_password yes`, `shareapi_enforce_expire_date yes` (7 d), `shareapi_allow_public_upload no` |
| group sync | Kanidm claim map (above) + user_oidc `--group-provisioning=1`; `occ group:add chp-users` first so folders can name it |

**Proofs (`proofs.py share|see`, `logs/25`, re-run after the restore and after the reboot):**

- internal share of a CUI file to lab02 (not `cui-users`): **refused** (HTTP 403 "You are not allowed to share …");
  even to lab04 (in `cui-users`): refused; the CUI folder itself: refused
- public link on a CUI file: **refused**; on an FCI file: refused
- control: an Operations file shared to lab02: allowed
- lab03 (`doc-reviewers`, not `cui-users`): sees Internal, Operations, Public only; GET of the CUI file by path: 404;
  reads Operations; cannot write there
- lab04 (`doc-reviewers` + `cui-users`): sees CUI, **reads** the CUI file, **cannot** change it, add to CUI or delete
  (403 each); the file is unchanged afterwards

These folder proofs authenticate with each user's **app password (HTTP Basic)**, not an OIDC browser session; the
server-side permission, ACL and share checks are the same for both (the sign-in itself is proved separately).

Note for Plan 2: an ACL rule overrides the group's folder permissions for a user in both groups (lab04), which is
exactly the owner's reviewer rule. **As built, reviewers lose write, create, delete and share on ALL six folders**,
including Operations, Internal and Public; the owner should confirm that is meant (the design says "a read-only layer"). Download limits (`files_downloadlimit`) are on but only apply to share links, and
CUI/FCI have none.

## Tag by folder (Step 7)

**Mechanism: the spike app `chp_foldertag`** (`chp_foldertag/`, ~100 lines, in the RPM): it listens to NodeCreated /
NodeWritten / NodeCopied / NodeRenamed, and a file whose mount is a team folder named in its rules
(`occ config:app:set chp_foldertag rules --value='{"1":"1","2":"2"}'`, team folder id -> system tag id) gets that
tag through `ISystemTagObjectMapper`. Tags `CUI` and `FCI` are **restricted** (`occ tag:add CUI restricted`): visible,
only admins can assign or remove. Why not a flow rule: workflowengine has no folder/path check (checks are file
name, MIME type, size, tags, request, group), and flow rules cannot be scripted with an app password (the diwai lesson).

**Proofs (`logs/24`, `logs/26`, `logs/35`):** WebDAV PUT into CUI -> `['CUI']`; **browser-style chunked upload** (the web
UI's chunking v2: MKCOL `uploads/…`, chunk PUTs, MOVE `.file`; 40 KB and 7 MB files) into CUI -> `['CUI']`, into FCI
-> `['FCI']`; Operations -> no tag; lab01 cannot remove the tag (DELETE `systemtags-relations` -> 403). The browser
path was scripted, not clicked: the same requests the Files app sends.

**Cannot be switched off silently:** `occ app:disable chp_foldertag` is in the audit log (`App "chp_foldertag"
disabled`) and raises a **level 12** Wazuh alert (rule 100603). **The nightly check** `occ chp:foldertag:check` lists
every file in a ruled folder without its tag (exit 1): it caught a file put straight onto the disk + `groupfolders:scan`
(no upload event) and a file uploaded while the app was off. **Finding: the check must not live in the app it checks**
— with the app disabled its command disappears too ("no commands defined"; it still exits 1, so a timer would notice,
but Plan 2 should run the check from chp-base/chp-site with SQL: team folder storages are `oc_group_folders.storage_id`,
files under `files/`).

## Copy out of CUI (review item, `logs/41`)

**The bypass, before any control:** lab01 (`cui-users`) did a WebDAV COPY of a CUI file into Operations and into their
home, and a MOVE into Operations: all three worked (201). The copies carry **no tag**; the moved file kept its CUI tag
but nothing acts on the tag. From Operations and the home folder an internal share to lab02 **and** a public link were
both accepted (OCS 200), and lab02 read the file (200). The cleanup deleted those files.

**Prototype control: `chp_foldertag` 0.2.0 `ContainListener`** (in RPM spike5): on `BeforeNodeCopiedEvent` /
`BeforeNodeRenamedEvent`, a source in a contained team folder (`occ config:app:set chp_foldertag contain
--value='[1,2,3]'`: CUI, FCI, Archive) and a target anywhere else is aborted with `AbortedEventException` (NextCloud 35
supports this in `HookConnector`). Result after `occ upgrade` (the first run was void: the app version bump left
NextCloud in "upgrade required" and every request got 503): COPY to Operations, MOVE to Operations, COPY to home, MOVE
CUI -> FCI: **refused (403), nothing created**; COPY inside CUI and MOVE from Operations into CUI still work and are
tagged CUI. NextCloud logs `chp_foldertag: REFUSED move out of contained team folder 1: …` (nextcloud.log, level 2;
Plan 2 should send it to the audit trail and Wazuh).

**What it does not stop:** a member **downloads** the CUI file and **uploads** the bytes to Operations, then shares it
(proved: 200, 201, link OCS 200). Copy-and-paste of content, a sync client (not shipped) and screenshots are the same
class. Nothing in NextCloud can tell where uploaded bytes came from; only a content check (the CUI banner/marking
check from §5 of the design, run on uploads outside CUI/FCI) or not giving `cui-users` share rights elsewhere would
narrow it. **That is an owner decision.** A files_accesscontrol rule by tag was not built: a copy has no tag, so it
would only cover moves, which the listener already refuses.

## Audit to Wazuh (Step 8)

`/var/log/nextcloud/audit.log` (admin_audit, JSON) read by the server's Wazuh (the manager reads its own files;
`wazuh/localfile.xml`); Wazuh's built-in JSON decoder; rules `wazuh/chp_nextcloud_rules.xml` (ids 100600-100605):
100601 **level 12** share refused, 100603 level 12 a control app disabled, 100605 level 7 failed sign-in, 100604 level 7
deletion. **NextCloud 35 audits refused shares itself**: `Interaction OCP\Interaction\Actions\ShareAction from user lab01
on 70 to lab02 is restricted: Node is not shareable.` Arrived at the manager (`alerts.json`, `logs/27`): five
share refusals at level 12, the app-disabled line at level 12, the failed sign-in at level 7. Two Wazuh details: the
regexes need `type="pcre2"` (OS_Regex has no grouped alternation; a bad rule stops the manager: it was down for 20 s),
and a `Login failed` line is taken first by Wazuh's generic rule 2501, so 100605 hangs off 2501. Sample lines (no
secrets): `wazuh/sample-audit-lines.json`. Failed **Kanidm** sign-ins (wrong TOTP) are in kanidmd's journal, which Wazuh
already reads; a rule for them is Plan 2.

## Browser editors off (Step 9)

`text` and `office` disabled; `richdocuments`/ONLYOFFICE not installed; no editor capability advertised; `viewer` and
`files_pdfviewer` on. docx, xlsx, md, PDF uploaded and downloaded byte-for-byte (Operations by lab02, CUI by lab04)
(`logs/29`). With `text` off a Markdown file has no in-browser viewer: download only. Users' script files (.py, .php,
.js, .sh) download after fix 6 (`logs/30`, `logs/32`).

## Backup and restore (Step 10)

`pkg/chp-nextcloud-backup` (+ `.service`, `.timer` nightly 01:40): maintenance mode on, `pg_dump -Fc` (peer auth),
`rsync -aHAX` of the data and `/etc/nextcloud` into `/backup/nextcloud/<UTC stamp>/` (0700), maintenance off, a sha256
MANIFEST, 14 copies kept. 0 fapolicyd denials during it (fix 6 covers rsync), 0 AVCs. **Restore onto a reset server:**
the NextCloud state was destroyed (services stopped, database dropped, `/data/nextcloud`, `config.php` and the OIDC
secret deleted: `status.php` said `installed:false`), then `chp-nextcloud-backup restore <dir>` (MANIFEST checked first)
-> installed, 6 team folders, tag check consistent, `tags` and `see` proofs ALL PASS, lab04 signs in through Kanidm
(`logs/34`). One bug fixed on the way: `pg_restore` as postgres could not read the root-only dump; it now reads stdin.
"Reset" here = the NextCloud state wiped on the same server, not a reinstall from the ISO. The backup holds
`config.php` (instance secret, password salt) and the OIDC client secret: `/backup` must stay encrypted when it leaves
the server (the 0.6.0 backup-drive runbook does that).

**Reboot (`logs/35`):** TPM unlock, every unit active (httpd, php-fpm, postgresql, the egress table, the cron and backup
timers, wazuh-manager, kanidmd, fapolicyd), 0 failed units, 0 denials, 0 AVCs.

## Resource use (`logs/37`)

At rest after the proofs, 8 GiB VM: used 1.7 GiB. Service memory: wazuh-manager 1,281 MB, suricata 539, php-fpm 123,
kanidmd 76, httpd 60, postgresql 39. Disk: code 874 MB (`/usr/lib/nextcloud`), database 74 MB, data 7 MB, backups 15 MB
for three copies. **4 GiB (the install default) is too small for the server with SECURITY_ADDONS and NextCloud; Plan 2
should say 8 GiB.**

## For Plan 2 (decisions and work the spike surfaced)

1. fapolicyd: the namespace gap (finding 1) and the gates and collector that count FANOTIFY (finding 2): changes to
   existing products; owner decision after a per-role trial (item 11).
2. Port: 8443 (recommended) or a second address (finding 3).
3. PHP 8.4 path before NextCloud 37 (finding 4).
4. Build host for a PHP package (aero's fapolicyd blocks it): owner decision.
5. The NextCloud package ships: `/usr/lib/nextcloud`, `rules.d/65-chp-nextcloud.rules`, the `config.php` trust entry in
   `%post`, the egress table + unit (packaged since spike4 as a template), httpd/php-fpm configs that disable the
   stock listeners, the boolean, the cert renewal timer, the backup timer, the Wazuh rules.
6. Use `chp-site get SUBNET_CIDR` for the firewall rule; the site zone needs `files`.
7. The nightly tag check outside the app; the canary (public link on a CUI test file expects 403) fits the same timer.
8. Approval ledger / doc-command transport: not part of this task (Task 2).
9. Egress: BindsTo + pre-check drop-in, a monitor check for the table, and the DNS decision (above).
10. Copy-out containment (`ContainListener`) and its logging into the audit trail; the owner decides on the
    download/re-upload residual (§Copy out).
11. fapolicyd: trial `allow_filesystem_mark = 1` per role; decide the gate (FANOTIFY count vs `--check-status`, run
    after a fapolicyd restart, since a rule reload keeps cached decisions).
