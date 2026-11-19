# chp_ledger 1.0

NextCloud app shipped in the `nextcloud-chp` RPM (`/usr/lib/nextcloud/apps/chp_ledger`). It is the intake of the
controlled-document approval ledger (route L1): the workstation's `chp-site doc` commands send their requests over
NextCloud's own HTTPS (port 8443, no new port), and the app spools them for the root appender
(`chp-site doc-ledger process`, started by `chp-docs-ledger.path`). The app never writes the ledger or the
Compliance areas; the appender does both.

## API (OCS, `OCS-APIRequest: true`)

`POST /ocs/v2.php/apps/chp_ledger/api/v1/request`, JSON body:

| field | kinds | meaning |
|---|---|---|
| `request_id` | all | 32 lowercase hex characters, chosen by the client |
| `kind` | all | `checkout`, `new`, `approve`, `override`, `publish` |
| `file_id` | all | a document in a Compliance area; or, for `new` (and `approve`/`override`/`publish` of a document not yet published), the area folder that will hold it |
| `path` | folder `file_id` only | the new document's name (one path segment, at most 255 bytes); must be empty with a document's `file_id` |
| `sha256` | `approve`, `override`, `publish` | 64 lowercase hex characters; must be empty for `checkout` and `new` |
| `reason` | `override` (required), others optional | at most 2000 bytes of UTF-8 |
| `notes` | optional | at most 2000 bytes of UTF-8 |
| `content`, `pdf_content` | `publish` only, both required | the approved file and its reader PDF, base64; **together at most 64 MiB decoded** |

Answer: `{request_id, state: "queued"}`. Then poll `GET …/api/v1/result/{request_id}`:
`{request_id, state: queued|done|refused|retry, message, entry?}`, from the appender's result file. Only the user who
sent the request reads its result; anyone else, and an unknown id, gets the generic refusal (HTTP 404).

Every refusal carries the same text (`state: refused`), whatever the reason: a malformed field, a file id the user
cannot see, outside the Compliance areas or inside a Superseded area, a duplicate request id, or an internal error.
The HTTP status differs (400, 403, 409, 413, 500). Two other texts exist: not signed in (401), and the rate limit
(429: more than 10 requests a minute by one user; nothing is spooled).

## The spool record

`/var/lib/chp-docs/spool/<request_id>.json` (directory `root:apache 1730`, `httpd_sys_rw_content_t`: apache creates
files there but cannot list the directory or remove another's file). Written as `.<request_id>.tmp` with
`O_CREAT|O_EXCL` (never through a symlink, never over a file), mode 0640, fsynced, then hard-linked to its final name,
which fails if that name exists. The appender reads `<32 hex>.json` names only; a leftover `.tmp` is from a crashed
worker.

Fields: the request's own (`request_id`, `kind`, `file_id`, `sha256`, `reason`, `notes`, `content`, `pdf_content`),
and, from the server:

| field | meaning |
|---|---|
| `user` | the uid NextCloud authenticated (`IUserSession`); a `user` in the body is never read |
| `auth` | `app-password` when NextCloud signed the request in with an app password or device token (Basic, such a token as Bearer, Login Flow v2's token: the session key `app_password`); else `bearer` when an `Authorization: Bearer` header came (a claim only: the appender verifies it); else `session` (browser cookie) |
| `auth_header` | `bearer`, `basic`, `other` or `none`: the header's scheme |
| `nc_app_token` | whether NextCloud's session says `app_password` |
| `bearer_token` | `auth: bearer` only (else null): the raw Bearer header value, for the appender's check at Kanidm's `chp-doc` userinfo. Never logged, its claims never read here; an app password or device token is never spooled |
| `target`, `name`, `path` | `file` or `folder`; the new name (folder only); the path as the user sees it |
| `area_id` | the Compliance area that holds the file id |
| `received_at`, `remote_addr` | UTC time; the client address |

## Policy (app config, set by `chp-site documents enable` from `/etc/chp/documents.conf`)

| key | JSON | from |
|---|---|---|
| `compliance` | list of folder file ids | `CUI_COMPLIANCE_ID`, `INTERNAL_COMPLIANCE_ID` |
| `superseded` | list of folder file ids | `CUI_SUPERSEDED_ID`, `INTERNAL_SUPERSEDED_ID` |

A file id is accepted when the user can see it and an area folder is the file itself or one of its ancestors, with
no Superseded folder on the way (`Internal/Compliance/Superseded` lies inside `Internal/Compliance`). Ancestors are
read from the filecache by parent on the file's own storage, never from the path the user sees. A missing or
malformed key refuses every request.

## Memory

A publish of 64 MiB is about 85 MiB of base64 in the JSON body. NextCloud holds the decoded parameters, and the
spool record is encoded once more: about 2 x 85 MiB at the peak, plus NextCloud's own use, within php-fpm's
`memory_limit = 512M` (chp-documents' pool). The app never decodes the base64 (the appender does). A body far above
the cap is read in full by NextCloud before the app sees it; `post_max_size` is 2G for ordinary uploads.
