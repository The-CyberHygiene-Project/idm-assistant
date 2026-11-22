# Task 14 report: final-review fix wave (A server, B marking/workstation, C records, versions)

**Status: DONE.** Every item A1-A12, B1-B9, C1-C8 and the versions are done; nothing NOT DONE. No lab, no aero, no
push/build/sign, no tag moved. Commits carry no AI co-author trailer.

## Commits

idm-assistant, branch `iso-0.7.0-owner-batch` (from 80c000b):
- `76d0047` A (server)
- `a2d11b4` B (marking, doc, doc_auth)
- `8847610` C (proof record, guide, kit, known issues, spec)
- `5b16631` versions

chp-templates, branch `iso-0.7.0-docs`: `d015ba5` (C1-C3, Rev 2 content 1.2.8). Local tag `templates-1.4.0` NOT
moved (still 1d7b682). **New templates archive sha256** (`git archive --format=tar.gz --prefix=chp-templates-1.4.0/
d015ba5`, the build-rpm.sh method; checked: the same command on 1d7b682 gives the current pin 3bf9d127…):
`9af9dda9f44cd038ab21e12789b9002229da4dd4fd600a7ac65ae4ddc5d656c8`.

## Tests

Full suite 2610 passed (baseline 2539; +71). chp-templates 446 passed, 3 skipped. RED first: every new test was run
against the old code (code files stashed): A 30 failed / 1 passed (the plain-text-taken guard), B marking 23 failed /
2 passed (the "still works" guards), doc 3 failed / 7 passed, doc_auth M7 1 failed. Python 3.9 (/usr/bin/python3
3.9.6): chp_site parses with feature_version 3.9 and imports; test_marking 441/0, review_report 42/0, wazuh 83/0,
doc_ledger 121 passed (4 harness-only failures: the 3.9 shim has no `capsys` and no `tests` package).

Probes: the reviewers' p1-p5 and rv4 (scratchpad/t14/probe.sh, outputs pre14.out / post14.out) and every earlier
probe set via r4/run.sh (probe12, probe12r2, p3s, r12c-f; pre14.out / post14.out). Earlier probes: **no verdict
change** (only timings and a traceback line number in a pre-existing p3s_f trace). One regression was found on the
way and fixed: B3's LF/CR-only split made r12c's `CUI<U+2028>SP` in an FCI body pass; the wrong-banner search now
reads both line readings (see B3). Reviewer probes, now refused: P1-AltSect, P2-PprChange, P2b-TxbxSect,
FCI_P3-AltCUI, FCI_P3b-AltParaCUI, P5-HdrIsDoc, P5b-HdrTypeImage, FCI_WM, Plain-WM, Md-LS, FCI_CUI_Plan name,
xlsx CUI_D insert. Unchanged by design: FCI_P3c-BodyCUI (wrong banner in a docx body: B M2 follow-up, now in known
issues), P6 field code (M8 accepted). The real chp-templates doc templates (cui/fci/noncui x docx/xlsx/md, filled)
pass before and after.

## A (server) - all done

- **A1** RED/GREEN. `_control`/`_text_ok` in doc_ledger: C0, DEL, C1 (and lone surrogates) refused in reason and notes
  (`_shape`; `resolve` now uses the same helper, so it refuses C1 too). PHP `text()` adds
  `preg_match('/[\x00-\x1f\x7f]|\xc2[\x80-\x9f]/', $v)` (byte form of C0/DEL/C1 on validated UTF-8). The client
  (`doc._text`) refuses them plainly before sending. `journal()`: `_journal_line` keeps a line <= 16000 bytes by
  replacing reason/notes, then any other value over 256 JSON bytes, with "(shortened for the journal: N bytes, sha256
  …; the full text is in the ledger)"; a line that still does not fit is never given to logger (its cut is silent)
  and goes to stderr. Tests: 2000 B of \x01 in reason and notes refused (quarantine "… is not valid text"); the
  shortened override line still matches 100643 at level 12 (Wazuh simulator); logger argv; stderr fallback.
- **A2** RED/GREEN. `documents.sql_runner(run, timeout=None)`: a TimeoutExpired is a SiteError("psql timed out after
  N s"); OccStore passes `SQL_TIMEOUT = 45` and wraps every query (`OccStore.sql`): SiteError/TimeoutExpired ->
  StoreError. The reviewer's probe is a test (an OccStore whose sql raises SiteError: checkout refused "could not do
  it … database", no quarantine). `_publish`'s generic `except Exception` now raises `_UndoIncomplete` ("UNDO
  INCOMPLETE (…): parts … may be in the area; … cause …") when the undo failed, so the quarantine record and the
  owner's refusal keep the words. Not changed: the FakeStore-level fakes still raise StoreError, because FakeStore
  stands in for OccStore (after its conversion); the production type (SiteError) is now raised by the sql fakes in
  the new OccStore tests.
- **A3** docs only: known issue "The reader PDF is not compared with the approved document", a residual line under
  the POA&M seed table (kept out of the rows so they stay copies of the template's), a guide note at publish step 8.
- **A4/A5** RED/GREEN. Backup: `UNFINISHED=${CHP_DOCS_UNFINISHED:-/var/lib/chp-docs/unfinished}` rsynced to
  `chp-docs-unfinished/` inside the ledger-lock block (before `exec 8<&-`); restore puts it back only in the branch
  that restores the ledger (a server with none). Restore records which of chp-docs-ledger.path /
  chp-documents-check.timer are active, stops `chp-docs-ledger.path chp-docs-ledger.service chp-documents-check.timer
  chp-documents-check.service` before the database drop, and starts the ones that were running after the trust
  refresh. Tests: runtime backup harness (order flock < unfinished rsync < maintenance on) and a new runtime restore
  harness (stop < DROP < trust < start; unfinished restored; a server with a ledger keeps both).
- **A6** RED/GREEN. `review_report`: rules listed from the ledger (approve, override, publish, resolve, entry,
  routine) are left out of intrusions; the other document-workflow rules (100640-100656, 100633, 100634) at >= 7 are
  kind "documents"; share/move/tag/canary/egress stay "nextcloud". `wazuh.DOC_LEDGER_LISTED_RULES` added.
- **A7** RED/GREEN. `OccStore.read`: path from the file cache split and checked (no "", ".", ".."), opened one
  component at a time with `dir_fd` and O_NOFOLLOW (O_DIRECTORY for folders, O_NONBLOCK for the file), fstat
  S_ISREG, `MAX_READ = 64 MiB` (size and read cap). Tests: middle-component link, file link, FIFO (no hang), "..",
  64 MiB + 1.
- **A8** pending() runs `records_fn()` before `_Shared` (test of the order).
- **A9** RecursionError with ValueError in process_one, _set_aside, _defer, _held_record (and the held-record
  rewrite's except). Tests with 200000-deep arrays/objects.
- **A10** new rule 100656 (quarantine-purged, level 7); start-marker-clear-failed joins 100652 (level 7); the
  catch-all stays last; guide alert table row added.
- **A11** `_reader_of`: checkout/new/publish of a .pdf whose stem equals a current non-PDF file in the same folder is
  refused ("… is the reader copy of …; check out … instead"), before anything else is decided.
- **A12** test_doc_ledger `or`->`and` (the first clause now `"bearer_token" not in`: the entry legitimately says
  auth "bearer"); `_broken`, `_answer` journal through `_safe`; `timeout 300 "$OCC" maintenance:mode --on` (fails:
  "backup FAILED: … did not finish in 300 s", exit 75, the trap records FAILED, removes the copy, maintenance off; the
  lock goes with the process). The test harness gained a fake `timeout` (macOS has none).

## B (marking / workstation) - all done

- **B1** `_wrong_lines(root)` for header/footer parts (wrong-banner search only): every w:p and DrawingML a:p in the
  part (text boxes, shapes, drawings, objects, hidden runs), a nested paragraph its own line, each mc:AlternateContent
  read once per branch (Choice/Fallback), every `*:textpath/@string`; only w:del / w:moveFrom left out. The required
  banner still uses `_part_lines` (strict). Note: hidden runs are now searched for the wrong banner (fail closed).
- **B2** `_Docx.sects` = only the body's last-child sectPr and the pPr/sectPr of body-level paragraphs (through
  w:sdt/w:sdtContent and w:customXml), not on a deleted (w:del/w:moveFrom) paragraph mark; `bad_sects` = every other
  sectPr outside w:sectPrChange -> problem `BAD_SECT` in every mode; `_ins_docx` refuses up front; its count guard
  (all_sects) unchanged. Tests: AltSect, PprChange, TxbxSect, deleted mark, table cell; sdt/customXml/sectPrChange
  still fine.
- **B3** `_Md.lines` = split on `\r\n|\r|\n` (trailing empty dropped, so insert's output is unchanged). Deviation
  from the literal brief, recorded: the wrong banner is searched in BOTH readings (LF/CR and str.splitlines), check
  and `_ins_md`, because LF/CR alone turned r12c's `CUI<U+2028>SP` (FCI body; want FAIL) into a pass (U+2028 is a
  mandatory break in UAX #14, so a renderer may show "CUI" alone). Required banners read from LF/CR lines only.
- **B4** `_Zip.rels` keeps the short type only for the transitional and Strict OOXML relationship namespaces (else the
  whole Type, which matches nothing); a header/footer reference whose relationship is not header/footer -> problem
  (all modes); a part whose root is not w:hdr / w:ftr -> problem and never used for the page-one block; insert
  refuses both. Strict namespace accepted (test).
- **B5** parse_name: at most 200 characters AND 255 UTF-8 bytes; a title starting with CUI_/FCI_ (folded) after the
  prefix is refused ("second CUI_ or FCI_ prefix").
- **B6** `_ins_xlsx`: a non-empty, different left section of the first-page footer -> MarkingError naming the text
  (dry run gives the same refusal; the file is unchanged).
- **B7** send(): 409 on a kept id -> one `_result_once`: final -> that answer; absent (404) -> id dropped, plain
  refusal; held -> poll as before. The old `test_409_and_500…` keeps its 500 case (409 moved to new tests).
  `doc logout --forget` (`_Pending.forget`, under the pending lock) prints how many were forgotten.
- **B8** `Env(run_user="/run/user")`; runtime_dir refuses unless `normpath(XDG_RUNTIME_DIR) == run_user/<uid>`
  (before the tmpfs/private checks, which stay). Test env now uses `<tmp>/run-user/<uid>`.
- **B9** `doc mark` help: "CUI/FCI marks".

## C (records) - all done

- **C1-C3** chp-templates d015ba5: 3.1.3 and 3.4.3 add "when SECURITY_ALERT_LEVEL is 12 or lower; documents enable
  warns otherwise"; 3.4.3 site responsibility adds "keep SECURITY_ALERT_LEVEL at 12 or lower and set ALERT_HOOK while
  the document server is on"; 3.1.3's last sentence as the brief; PROOF-RECORD-PLAN3.md added to the evidence of
  3.3.7, 3.4.2, 3.4.7, 3.13.1, 3.13.6. **Rev 2 content 1.2.7 -> 1.2.8** (my call: 1.4.0-2 with content 1.2.7 is
  already in a signed lab repo, so changed narratives must not reuse 1.2.7): MANIFEST rebuilt, golden ssp.md
  regenerated, test_manifest, RELEASE-NOTES-1.4.0.md ("Final review corrections"). The idm repo's chp-templates
  build pin (build-rpm.sh SHA, test_chp_templates_rpm_static) and its spec changelog ("Rev 2 content 1.2.7") are
  left for the controller's re-tag at staging.
- **C4** PROOF-RECORD-PLAN3.md "Verdicts (both rounds)": round 1 97/18/9/9 with every FAIL, PARTLY (18) and NOT
  RUN (9) item from task-11c-report.md; round 2 28/2/2/4/1 + B15 PASS (log 228) = 29/2/2/4, every PARTLY/FAIL/NOT
  RUN; the regression re-run (log 229, uncommitted, the worker's) recorded as "16 of 33 GREEN, none failed, still
  running" at the time of writing; the round-1 fault-injection/restoration table copied from the 11c report. The
  worker's logs 228/229 were read, not committed; PROOF-RECORD-PLAN3.md had no uncommitted worker edits.
- **C5** kit poam-seeds: "NIST requirement numbers PENDING OWNER CONFIRMATION" marker; lines 11-14 now say the
  library has poam.due_t08..t16 from chp-templates 1.4.0 (content 1.2.7).
- **C6** guide: MD5 folder-move steps "not yet proven in the lab as a whole" + what round 1 ran and that the
  access-rule copy (steps 1-2) was not exercised (the guide test requires the phrase "not yet proven in the lab");
  T-15 row names ncadmin; the time cross-reference names "From 0.7.0 on: time from the CHP server" above;
  site.conf.template `https://files.<your domain>:8443`. Also: doc logout --forget and the 409 drop in the
  pending-request paragraph; notes/reason "one line".
- **C7** known issues: P3-D6 section; "Server-side residuals" (P3-D3 residual, areas not compared with the ledger,
  out/ never pruned, check 82 can hold the monitor ~4 min: verify + pending each wait up to 120 s); the 12b residuals
  and the body/cell/PDF-middle wrong-banner gap under T-16; A-I-3 (reader PDF) under Limits of use.
- **C8** spec: new §14 (owner decision 2026-11-20, time from the CHP server, NTP 123/udp to SUBNET as the one new
  port, tailoring) and a "Superseded in part" note in §4.

## Versions

chp-site 0.14.0-12; nextcloud-chp 35.0.3-8 (chp_ledger 1.0.3, info.xml + %global ledger_ver); chp-documents
0.1.0-12 (Requires chp-site >= 0.14.0-12, nextcloud-chp >= 35.0.3-8); chp-onlyoffice 0.1.0-7; chp-identity-client
0.2.4-6; chp-identity-server 0.1.2-8 (chp-site >= 0.14.0-12, chp-identity-client >= 0.2.4-6). Changelogs dated Sun
Nov 22 2026; static pin tests updated. NEW vs signed 0.14.0 grows to 6 packages (+ nextcloud-chp); ~/go.sh
expectations and the staging record are the controller's.

## Concerns

- B1 now searches hidden runs and every shape for the WRONG banner: a hidden "CUI" in an FCI_/non-CUI header is
  refused (fail closed; no template or ONLYOFFICE sample is affected).
- B2 refuses a tracked-deleted section break in every mode, including the non-CUI area (fail closed; accept or reject
  the change first).
- B7 changes an earlier tested behaviour on purpose (409 + nothing held: was pending forever, now dropped).
- The regression gate (log 229) was still running when C4 was written; the record says so and leaves the final count
  to the lab worker.
- Content 1.2.8 and the new archive sha need the controller's re-tag and the idm pin update at staging.

## Task 14b

- Backup: fd 8 released before both `exit 75` paths and first in the EXIT trap; trap writes `status FAILED` before any occ call, bounds `occ maintenance:mode --off` with `timeout $OCC_TIMEOUT` (CHP_OCC_TIMEOUT, default 300; failure logged, not fatal), removes the half copy last. Service: `TimeoutStartSec=6h` with justifying comment.
- Restore: EXIT trap after `was` is computed; on failure logs "restore FAILED: document units were stopped; restarted them" (or "could not restart: ...") and starts the units that were running. The web stack stays stopped on purpose (database half restored).
- Scrub: spec section 4 heading and PROOF-RECORD-PLAN3.md neutralised. Remaining "diwai" (16 files, 29 lines; most: iso-0.7.0-design.md 10) and "claude/anthropic" (10 files, 27 lines; docs/dc2-planning/CLAUDE.md 4, iso-plan5a 8) left for the owner.
- chp-documents release 0.1.0-13; tests 2613 passed (2610 + 3 new; 2 pin assertions and 1 index-based test updated).
