# `chp-site documents enable`: command audit against the real software (Task 9c, 2026-11-14)

**Why:** each blocking defect found on the lab costs the owner a YubiKey re-signing. Round 2 stopped on D3 and D4
(PROOF-RECORD-PLAN2.md). Before the next signing, every external command `enable` runs was checked against the
software installed on **iso5-srv**, **read-only**: `--help` output, sources under `/usr/lib/nextcloud`, unit-file
lists, `fapolicyd-cli --ftype`, and read-only Kanidm `get`/`list` with the existing idm_admin session. No product
change was made on the lab (two scratch files in /root held the audit output and were removed).

**Versions on iso5-srv:** NextCloud 35.0.3 (nextcloud-chp 35.0.3-4: groupfolders 23.0.1, user_oidc 8.13.0,
files_accesscontrol 6.0.1, chp_foldertag 1.0.0), Kanidm 1.11.2 (kanidm-server / kanidm-clients 1.11.2-2.chp),
Wazuh manager 4.14.9, PostgreSQL 16.13, fapolicyd 1.4.3-3.el9 (`integrity = none`), step-cli 0.31.0, firewalld
(default zone `public`), mod_ssl 2.4.62.

**Already proven by a real run (rounds 1-2):** steps start through `settings` ran on the lab: dnf, rpm, /etc/hosts,
named-checkzone, rndc, the egress unit, Wazuh (`wazuh-analysisd -t` + restart), postgresql-setup, psql, install,
restorecon, `occ status`, `maintenance:install` (after W1), every `config:system:set` key, `background:cron`, every
`config:app:set` in SHARING. Round 2 stopped at `apps` (D4). Everything after that point is checked here.

Legend: **OK** = the command, its options and the output shape enable parses match the real software.
**MISMATCH** = fixed in chp-site 0.14.0-3, with a test.

## Defects found and fixed

| # | Where | What the real software does | Fix (chp-site 0.14.0-3) | Tests |
|---|---|---|---|---|
| D3 | step 6 install | fapolicyd denies php reading back the config.php `maintenance:install` writes (`%languages`, `text/x-php`); enable trusted it only AFTER the install; every later occ call was then denied | before the first occ call: write `/etc/nextcloud/config.php` = `<?php $CONFIG = array ( );` (0640 apache:apache, restorecon) when absent, then `_trust_sync`: `fapolicyd-cli --file add` (no entry) or `--file update` (entry differs from the file: stale, malformed, duplicated) + `--update`. A config.php left by a failed install is kept and its entry refreshed, so a re-run recovers. Step 15a (after the last write) uses the same stateless compare | `test_d3_*` (5), the NextCloud fake now denies every occ call while config.php is untrusted (reproduces round 2) |
| D4 | step 8 apps | `occ app:disable appstore` -> "appstore can't be disabled" (core/shipped.json `alwaysEnabled`) | `appstore` dropped from APPS_OFF; `ALWAYS_ENABLED` = shipped.json's list; the store stays off by `appstoreenabled=false` | `test_d4_*` (2): APPS_OFF never holds an always-enabled app; the fake refuses to disable one |
| D5 | step 10 Kanidm | `kanidm group get <missing>` prints **`No matching group '<name>'`** (exit 0), not "No matching entries" (that is person, service-account and oauth2 get). `parse_entry` treated it as unexpected output, so enable would have stopped at the first Kanidm call (cui-users does not exist on a fresh site) | `parse_entry` also takes `No matching group '<name>'` as absent; anything else is still an error | `test_d5_*`, `test_parse_entry_group_get_missing_kanidm_1_11`; the Kanidm fake prints the real text |
| A1 | step 8 apps | the `office` app ("Office overview app", defaultEnabled in NC 35) is **enabled** on iso5-srv; the spike disabled it (editors off, design §3); APPS_OFF did not list it | `office` added to APPS_OFF (it is not always-enabled) | `test_d4_enable_passes_…` (office ends disabled), order test |

## Every command after `settings` (and the fapolicyd interactions)

| Step | Command / interaction | Checked against | Result |
|---|---|---|---|
| 6 | `fapolicyd-cli --file add\|update /etc/nextcloud/config.php --trust-file nextcloud`; `fapolicyd-cli --update` | fapolicyd-cli 1.4.3 `--help` (`-f, --file cmd path`, `--trust-file`, `-u, --update`); W1 in round 2 ran exactly this | OK (order fixed: D3) |
| 6 | pre-install config.php: `<?php $CONFIG = array ( );` | `lib/private/Config.php` readData (`include`, `isset($CONFIG) && is_array`), writeData (`fopen r+` on the existing file); `fapolicyd-cli --ftype` = `text/x-php` (needs the trust entry) | OK |
| 6 | `restorecon /etc/nextcloud/config.php` | `matchpathcon` = `httpd_sys_rw_content_t` (`/etc/nextcloud(/.*)?` fcontext from nextcloud-chp %post) | OK |
| 8 | `app:list --output=json` (`enabled`/`disabled` maps), `app:enable <id>`, `app:disable <id>` | `--help`; live output | OK; D4, A1 |
| 8 | APPS_ON all installed | live `app:list`: every APPS_ON app present (viewer, workflowengine are always-enabled: already on) | OK |
| 9 | `user:info ncadmin` (absent: "user not found", rc 1) | live run | OK |
| 9 | `user:add --password-from-env --display-name … --group admin ncadmin` (OC_PASS in env) | `--help` (NC_PASS/OC_PASS; group created if missing) | OK |
| 10 | `kanidm group get <g>` / `group create <g>` | live get of a missing and an existing group; `group create --help` (`<NAME> [ENTRY_MANAGED_BY]`) | **D5 fixed** |
| 10 | `kanidm system oauth2 get nextcloud` (missing: "No matching entries") | live | OK |
| 10 | `system oauth2 create <name> <displayname> <origin>` | `--help` | OK |
| 10 | `add-redirect-url <NAME> <url>`, `update-scope-map <NAME> <group> <scopes>...`, `prefer-short-username <NAME>`, `update-claim-map <NAME> <CLAIM_NAME> <GROUP> [VALUES]...`, `update-claim-map-join <NAME> <CLAIM_NAME> csv\|ssv\|array`, `show-basic-secret <NAME>` | `--help` of each; the spike's kanidm.sh (worked) | OK |
| 10 | ES256/PKCE refusal attributes `oauth2_jwt_legacy_crypto_enable`, `oauth2_allow_insecure_client_disable_pkce` | present in the kanidmd 1.11.2 binary (attribute-name strings), as are `oauth2_prefer_short_username`, `oauth2_rs_claim_map`, `oauth2_rs_scope_map` | OK (defaults off on a new client) |
| 10 | suggested fix commands `disable-legacy-crypto`, `enable-pkce` | both subcommands exist (`warning-enable-legacy-crypto` / `warning-insecure-client-disable-pkce` are the opposites) | OK |
| 10 | `chp_users` group (scope map, claim map) | live `group get chp_users` (exists) | OK |
| 10 | `/etc/nextcloud/oidc-secret` 0640 root:apache, `restorecon` | fcontext `httpd_sys_rw_content_t`; `--ftype` of a secret-shaped line = `text/plain` (not a %languages type: no trust entry needed) | OK |
| 11 | `getsebool httpd_can_network_relay` ("--> off" today) / `setsebool -P … on` | live | OK |
| 11 | `security:certificates` (table, File Name column) / `security:certificates:import <path>` | `--help`, ListCertificates source (`getName()` = file name), chp-root.crt present (`text/plain`) | OK |
| 11 | `user_oidc:provider kanidm --clientid --clientsecret-file --discoveryuri --scope --unique-uid --mapping-uid --mapping-display-name --mapping-email --mapping-groups --group-provisioning --group-whitelist-regex --check-bearer --send-id-token-hint` | user_oidc 8.13.0 `--help` and UpsertProvider source: every option exists; an existing provider keeps values not given (upsert) | OK |
| 12 | `group:list --output=json` (`{"gid": [members]}`), `group:add <gid>` | `--help`, live (`{"admin":[]}`) | OK |
| 12 | `groupfolders:list --output=json` | ListCommand source: JSON keys `id`, `mountPoint` (renamed from mount_point), `groups` = `{gid: {permissions, displayName, type}}`; `[]` when none | OK (`_folders`, `_perm_has_share` take these) |
| 12 | `groupfolders:create <name>` prints the id | Create source (`writeln((string)$id)`) | OK |
| 12 | `groupfolders:group <id> <group> read write delete [share]`, `… --delete` | Group source: PERMISSION_VALUES read/write/share/delete; `--delete` before the group lookup | OK |
| 12 | `groupfolders:permissions <id> --enable`; `… --group doc-reviewers -- / +read -write -create -delete -share` | ACL `--help` ("Prepend the permission list with --"), `-e`, `-g`; the spike's folders.sh (worked) | OK |
| 13 | `tag:list --output=json` (`{id: {name, access}}`), `tag:add <name> restricted` | SystemTag ListCommand formatTags; `tag:add` access = public/restricted/invisible | OK |
| 13 | `config:app:set chp_foldertag rules\|contain\|contain_allow --value=<json>` | SetConfig source: no `--type` on a new key = VALUE_MIXED; chp_foldertag reads them with `getValueString` (allowed on mixed); no config lexicon in chp_foldertag | OK |
| 14 | `firewall-cmd --permanent --list-rich-rules` / `--add-rich-rule 'rule family="ipv4" source address="<CIDR>" port port="8443" protocol="tcp" accept'` / `--reload` | `--help`; the canonical form firewalld prints (live rules on iso5-srv, spike logs/12) is exactly enable's string, so the "already there" test is exact; CIDR rendered `192.168.100.0/24` (live chp-nextcloud-lan.inc) | OK |
| 14 | `/usr/libexec/chp/cert-renew-nextcloud --issue` -> `step-cli ca certificate <fqdn> <crt> <key> --provisioner acme --kty EC --crv P-384 --force`; renew `step-cli ca renew --force --expires-in 8h --exec …` | script installed (chp-documents); step-cli 0.31.0 `--help` has every flag; `/root/.step/config/defaults.json` present; cert-renew-kanidm uses the same issue line | OK |
| 14 | `systemctl enable --now php-fpm httpd nextcloud-cron.timer chp-nextcloud-backup.timer chp-nextcloud-cert-renew.timer`; `restart php-fpm httpd` | `list-unit-files`: all present; httpd/php-fpm drop-ins (BindsTo egress, ExecStartPre nft list + nextcloud-httpd-stock-off); mod_ssl installed (Listen 8443 https) | OK |
| 15a | `_trust_sync` after the last write | same as step 6 | OK |
| 15 | `systemctl restart fapolicyd`; `fapolicyd-cli --check-status` ("Denied accesses: N") | live | OK |
| check | `user:info <u> --output=json` (`enabled`, `groups`), `user:enable/disable <uid>`, `group:adduser <g> <u>`, `user:auth-tokens:add -n --name <n> <user>` (prints "app password:" then the token, last line), `user:auth-tokens:list <u> --output=json`, `user:auth-tokens:delete <uid> <id>` | `--help` of each, Info and AuthTokens/Add sources (`-n` = no-interaction: a token without the login password, enough for OCS shares) | OK (list JSON shape not seen live: no canary user yet) |

## fapolicyd: every file php/occ reads outside the trusted RPM tree

`integrity = none` on the lab (path trust; the size/sha256 compare is kept so the entry stays true and check 81 can
alert). `fapolicyd-cli --ftype` on iso5-srv:

| File | Type | Needs a trust entry | Status |
|---|---|---|---|
| `/etc/nextcloud/config.php` (also read as `/usr/lib/nextcloud/config/config.php`, a symlink) | text/x-php | yes | trusted before the first occ call (D3) |
| `/etc/nextcloud/oidc-secret` | text/plain | no | OK |
| `/etc/pki/ca-trust/source/anchors/chp-root.crt` | text/plain | no | OK |
| `/etc/hosts` | text/plain | no | OK |
| users' files in `/data/nextcloud/data/` (any type) | any | rule 65 (open only, php-fpm/php/rsync/sha256sum) | OK (chp-documents) |
| `/etc/nextcloud/*.config.php` | — | none exist; NextCloud would include them | OK (none) |

## Not checkable read-only (left for the lab run)

- The Kanidm client's `get` output after `create` on 1.11.2 (attribute names verified in the binary; their values on a
  real client are seen at the run).
- `user:auth-tokens:list --output=json` shape (the canary, nightly check; not part of enable).
- The real ACME issue for `files.<domain>` (same path as the Kanidm certificate, which works on this server).
