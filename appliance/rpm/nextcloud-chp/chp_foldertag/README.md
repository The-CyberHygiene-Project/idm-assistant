# chp_foldertag 1.0

NextCloud app shipped in the `nextcloud-chp` RPM (`/usr/lib/nextcloud/apps/chp_foldertag`). It enforces three
document-store controls on the CHP server and writes every decision to NextCloud's audit log.

1. **Tag by folder.** After a file is created, written, copied or moved, every file at the target (the whole
   subtree for a folder) gets the system tag of the team folder it is now in. On a copy it also gets every
   rule-managed tag the source file had, so a CUI file copied into Archive keeps `CUI`. A move keeps the file id,
   and so its tags. Tags are only ever added.
2. **Containment** (owner decision 3). A copy or move whose source is in a contained team folder (CUI, FCI,
   Archive) and whose target is any other place (another team folder, a home folder) is refused before anything
   is written (WebDAV 403). The exceptions are the pairs in `contain_allow`: CUI to Archive and Archive to CUI.
   Renames and subfolder moves inside one team folder are allowed. A WebDAV MOVE or COPY from a trash item or an
   old version straight into a files path is refused too: only the restore endpoints may bring such content back,
   and they put it back in its own folder with its file id and tags. Downloads are not blocked. admin_audit
   records them (owner decision 2).
3. **Folder guard (stopgap).** PostgreSQL in FIPS mode refuses `MD5()`. NextCloud uses SQL `MD5()` when it moves a
   folder that has contents, or when groupfolders moves a file's old versions to another team folder, and it
   fails half-way: the files are moved on disk but the database is not updated, and they reappear later as new,
   untagged entries. While `SELECT MD5(?)` fails (checked at most every 10 minutes), the app refuses these
   operations before anything moves: renaming, moving or deleting a folder with contents, and moving a file with
   old versions out of its team folder. Single files, empty folders and copies are not affected. The refusal
   stops by itself once the database computes MD5.

The app checks nothing about who may see what. Group access, ACLs and "share off" are groupfolders settings that
chp-site applies.

## Policy (app config, set by `chp-site documents enable`)

Every value is read on each event. Nothing is a constant in the code.

| key | JSON | meaning |
|---|---|---|
| `rules` | object `{"<team folder id>": "<system tag id>"}` | tag by folder |
| `contain` | list `[<team folder id>, ...]` | copy/move out refused |
| `contain_allow` | list `[[<from id>, <to id>], ...]` | exceptions to `contain` |

Example: `occ config:app:set chp_foldertag contain_allow --value='[[1,3],[3,1]]'`.

A key that is missing or empty means nothing is configured. A key that holds the wrong shape fails closed:
- with a bad `contain` or `contain_allow`, every copy or move out of any team folder is refused;
- with bad `rules`, nothing is tagged and each event writes `chp.tag.failed`.

`occ chp:foldertag:check` lists files in ruled folders that lack their tag (exit 1 if any). It is a tool for the
administrator. The nightly check runs outside this app, from chp-site, because the command is gone while the app
is disabled.

## Audit events

Each event is one JSON line in the admin_audit file: system config `logfile_audit`, which is
`/var/log/nextcloud/audit.log` on CHP, or `log_type_audit`/`syslog_tag_audit` if those are set. It uses the same
fallbacks as admin_audit. It is written at **level 2** (WARNING), so the site's `loglevel` 0-2 keeps it. The same
message also goes to `nextcloud.log` (`chp.tag.applied` only at debug level).

Fields written by NextCloud's logger, as on every admin_audit line: `reqId`, `level` (2), `time` (ISO 8601),
`remoteAddr`, `user` (`--` for occ), `app`, `method`, `url`, `scriptName`, `message`, `userAgent`, `version`, and
`occ_command` (occ only). Fields this app sets:

- `app`: always `"chp_foldertag"`. admin_audit's own lines say `"admin_audit"`.
- `message`: `"<event>: <human text>"`.
- `data`: an object. **Every value in it is a string**: NextCloud's log normaliser turns ints and bools into
  strings, and this app writes `"none"` for no value and `"true"`/`"false"` for flags.

| `data.event` | when | other `data` keys |
|---|---|---|
| `chp.contain.refused` | a copy/move out of a contained team folder, or a trash item / old version copied or moved to a files path; also every refusal made while the policy is unreadable | `app`, `op` (`copy`/`move`), `source_folder`, `target_folder` (team folder ids or `none`), `source`, `target` (paths), `reason` |
| `chp.tag.applied` | a rule tag newly assigned to a file (not repeated when the file already has it) | `app`, `op` (`create`/`write`/`copy`/`rename`), `file_id`, `folder`, `tag`, `path` |
| `chp.tag.failed` | a tag could not be assigned, or `rules` is unreadable | `app`, `op`, `file_id`, `folder`, `tag`, `path`, `error` |
| `chp.app.disabled` | any app disabled, including this one (its last line) | `app`, `app_id`, `control` (`true` for chp_foldertag, chp_ledger, admin_audit, groupfolders, files_accesscontrol, user_oidc, systemtags, workflowengine), `actor` (user id, or `occ`) |
| `chp.folderop.refused` | the folder guard refused a move or delete | `app`, `op` (`move`/`delete`), `source`, `target` (`none` for delete), `reason` |

Sample (`chp.contain.refused`, one line in the file):

```json
{"reqId":"...","level":2,"time":"2026-11-13T17:31:49+00:00","remoteAddr":"192.168.100.1","user":"lab01",
 "app":"chp_foldertag","method":"MOVE","url":"/remote.php/dav/files/lab01/CUI/x.txt","scriptName":"/remote.php",
 "message":"chp.contain.refused: refused move from team folder 1 to 2 (out of contained team folder): /lab01/files/CUI/x.txt -> /lab01/files/FCI/x.txt",
 "userAgent":"...","version":"35.0.3.2",
 "data":{"app":"chp_foldertag","event":"chp.contain.refused","op":"move","source_folder":"1","target_folder":"2",
         "source":"/lab01/files/CUI/x.txt","target":"/lab01/files/FCI/x.txt","reason":"out of contained team folder"}}
```

For the Wazuh decoder (Task 5): read the file with `log_format json`, match `app` == `chp_foldertag` and switch on
`data.event`. admin_audit also writes `App "<id>" disabled` for every disable, so a disable leaves a trace even
when this app is the one switched off.

## Licence

Apache-2.0, the repository's licence (`LICENSE` at the top of the repository). Every PHP file carries the SPDX
header. NextCloud itself is AGPL-3.0-or-later. Apache-2.0 code may be combined with it.
