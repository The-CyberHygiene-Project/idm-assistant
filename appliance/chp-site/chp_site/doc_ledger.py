# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site doc-ledger process|verify|export|purge-quarantine (ISO 0.7.0 design §4, Plan 3 Task 4): the root appender
of the controlled-document workflow. It is the only writer of the document ledger and of the Compliance areas.

Requests arrive from the NextCloud app chp_ledger (route L1) as spool files, /var/lib/chp-docs/spool/<32 hex>.json,
written by apache; chp-docs-ledger.path starts this program (as root) when one lands. For each request it:
  - reads it without following a symlink, checks its shape (anything malformed is set aside in quarantine/, with no
    Bearer token and no file bytes in the record);
  - answers a request id it has already appended with that entry (idempotent: a re-sent request is never refused
    after a successful append);
  - checks a Bearer at Kanidm's chp-doc userinfo (pinned to the site CA, no redirects) and that it names the user
    NextCloud authenticated; Kanidm unreachable or the token refused = state "retry" (the client signs in again and
    re-sends the same request id), never a quarantine;
  - under flock on the ledger: re-checks the area (inside a Compliance area, not under a Superseded one), applies the
    per-cycle author/approver rules, does the server-side publish (compare-and-write, supersede, tag, reader PDF,
    undone on any failure), appends one hash-chained entry and updates the ledger.head witness;
  - writes out/<id>.json (owner, state, message, entry) for the app, then deletes the spool file (it holds a token);
  - writes every entry (and every refusal, retry and quarantine) as one JSON line to the journal,
    SYSLOG_IDENTIFIER=chp-docs-ledger (ruling F4: Wazuh alerts on approvals and overrides at once).

The ledger is the same design as the review sign-off ledger (review_ledger): one JSON line per entry carrying the
SHA-256 of the line before, a head witness, the head exported to the site stick, and the same verify exit codes
(0 OK, 1 problems, 2 site stick not present).

A document is a series of versions: <prefix><title>_vX.Y[-DRAFT].<ext> in one area folder (marking.parse_name, the
same parser the workstation uses). Its key ("doc") is "<folder file id>/<prefix><title><ext>". A cycle runs from the
last publish of that document (or its creation) to now; Authors(cycle) = whoever created it in the cycle + everyone
who checked it out in the cycle (+ the publisher, who must be one of them)."""
import base64
import binascii
import calendar
import errno
import fcntl
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple, Optional

from . import review_ledger as rl
from .sitefile import SiteError

BASE = Path("/var/lib/chp-docs")
SITE_CA = "/etc/pki/ca-trust/source/anchors/chp-root.crt"
IDENT = "chp-docs-ledger"
GENESIS = "0" * 64
REQ_NAME = re.compile(r"[0-9a-f]{32}\.json")             # fullmatch only: "$" would also accept a trailing newline
HEX64 = re.compile(r"[0-9a-f]{64}")
USER = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
KINDS = ("checkout", "new", "approve", "override", "publish")
AUTHS = ("bearer", "app-password", "session")
MAX_SPOOL = 128 * 1024 * 1024                             # 64 MiB of file bytes as base64, plus the request
MAX_TEXT = 2000
MAX_TOKEN = 16384
TIMEOUT = 10
OCC_TIMEOUT = 120                 # per occ call; a publish makes at most 7 writes and reads
SQL_TIMEOUT = 45                  # per psql query (final review A I-2: the ledger lock is held meanwhile)
MAX_READ = 64 * 1024 * 1024       # a canonical file read back (the publish cap, chp_ledger MAX_CONTENT)
BUDGET = 600                      # process() starts no new request after this many seconds: the rest wait for the
                                  # next start (the path unit triggers again while spool files remain), so a request is
                                  # never cut off by the unit's TimeoutStartSec (45 min > BUDGET + one worst case)
FIELDS = ("seq", "ts", "kind", "user", "auth", "kanidm_sub", "session_id", "request_id", "doc", "file_id", "path",
          "sha256", "cycle", "prev")
OPTIONAL = ("reason", "notes", "cr", "pdf_sha256", "supersedes", "resolves")
CUI_TAG = "CUI"
DEGRADED = ("the document server is in DEGRADED mode (the database cannot compute MD5, so NextCloud refuses moves of "
            "files with old versions; design §12)")


class Result(NamedTuple):
    state: str                      # done | refused | retry
    message: str
    entry: Optional[dict]


class Node(NamedTuple):
    """A NextCloud file or folder as the appender sees it. path = "<team folder>/<path inside it>"; ancestors = the
    file ids from the parent up to the team folder's root (read from the file cache by parent, never from a path)."""
    file_id: int
    type: str                       # file | folder
    name: str
    path: str
    ancestors: tuple
    etag: str


class StoreError(Exception):
    """A NextCloud operation failed."""


class OccTimeout(StoreError):
    """occ timed out at OCC_TIMEOUT: the write it was doing may or may not have happened (unknown outcome). killed:
    False when its process group could not be killed (it may still be running)."""
    def __init__(self, msg, killed=True):
        super().__init__(msg)
        self.killed = killed


class Maintenance(StoreError):
    """occ refused because NextCloud is in maintenance mode (the nightly backup): retry later, never refused (Task 11a
    fix round 1, m3). The text is NextCloud 35's lib/private/Console/Application.php writeMaintenanceModeInfo()."""


MAINTENANCE_TEXT = "is in maintenance mode"


class Degraded(StoreError):
    """A move refused because the database cannot compute MD5 (design §12, FolderGuardListener)."""


class KanidmUnavailable(Exception):
    """Kanidm could not be reached or failed (outage): retry."""


class TokenRejected(Exception):
    """Kanidm refused the token (expired, revoked, or never valid): retry with a fresh sign-in."""


class KanidmRefused(Exception):
    """An answer that is never retried: not https, a redirect, a certificate that does not chain to the site CA."""


class LedgerError(SiteError):
    pass


class LedgerBusy(LedgerError):
    """A reader waited READ_WAIT seconds for the appender's exclusive lock (a long publish): not checked this time."""


class _Refuse(Exception):
    pass


class _UndoIncomplete(Exception):
    """An unexpected error in a publish whose undo could not be completed (final review A I-2): its text starts with
    UNDO INCOMPLETE, so the quarantine record and the owner's refusal say so (never "nothing was published")."""


class _Retry(Exception):
    pass


class _NotAppended(Exception):
    """The ledger line could not be written; `cut`: a partial line was cut back off (else the ledger needs the ISSO)."""
    def __init__(self, err, cut):
        super().__init__(str(err))
        self.cut = cut


def _write_line(fd, data):
    n = os.write(fd, data)
    if n != len(data):
        raise OSError(errno.EIO, f"short write to the ledger ({n} of {len(data)} bytes)")


def _safe(journal, rec):
    """A journal line after the append: its failure never turns "done" into anything else."""
    try:
        journal(rec)
    except Exception:                                     # noqa: BLE001
        pass


class Ctx:
    """Everything the appender touches, injectable for tests. site = the parsed site.conf (read at each run: approver
    accounts are re-checked against what is configured at approve time); conf = /etc/chp/documents.conf."""
    def __init__(self, *, base=BASE, site, conf, store, userinfo=None, marking=None, mark_values=None,
                 journal=None, now=time.time, chown=None):
        self.base = Path(base)
        self.site, self.conf, self.store = site, conf, store
        self.userinfo = userinfo or kanidm_userinfo
        self._marking = marking
        self._mark_values = mark_values
        self.journal = journal or globals()["journal"]
        self.now = now
        self.chown = chown or _chown_apache

    @classmethod
    def system(cls):
        from . import documents as D
        from .sitefile import parse_site, read_file
        conf = D._kv(Path("/") / D.CONF)
        site = parse_site(read_file(Path("/etc/chp/site.conf"), "site.conf"))
        return cls(site=site, conf=conf, store=OccStore(conf))

    @property
    def marking(self):
        if self._marking is None:
            from . import marking                         # Task 5; imported only when a publish needs it
            self._marking = marking
        return self._marking

    def mark_values(self):
        if self._mark_values is not None:
            return self._mark_values()
        return self.marking.MarkValues.from_site(self.site)

    # paths
    @property
    def spool(self):
        return self.base / "spool"

    @property
    def out(self):
        return self.base / "out"

    @property
    def quarantine(self):
        return self.base / "quarantine"

    @property
    def work(self):
        return self.base / "work"

    @property
    def unfinished(self):
        return self.base / "unfinished"

    @property
    def ledger(self):
        return self.base / "ledger" / "ledger.jsonl"

    @property
    def head(self):
        return self.base / "ledger" / "ledger.head"


def _chown_apache(p):
    """Results are root:apache 0640 (the app reads them; out/ is read-only to the web server)."""
    if os.geteuid() != 0:
        return
    import grp
    os.chown(p, 0, grp.getgrnam("apache").gr_gid)


JOURNAL_SIZE = 16384               # logger --size
JOURNAL_MAX = 16000                # a line longer than this is shortened (room for logger's own header)


def _shortened(v):
    b = v.encode("utf-8", "surrogatepass") if isinstance(v, str) else json.dumps(v).encode()
    return f"(shortened for the journal: {len(b)} bytes, sha256 {_sha(b)}; the full text is in the ledger)"


def _journal_line(rec):
    """The JSON line for logger, always at most JOURNAL_MAX bytes when it can be (final review A I-1: logger --size
    cuts a longer line SILENTLY, exit 0, and a cut JSON line matches no Wazuh rule, so an override's 100643 alert was
    lost). First reason and notes, then any other long text, are replaced by their size and sha256 (the ledger keeps
    them); the event, kind, user and path stay, so the rules still match. None: it still does not fit."""
    line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    if len(line.encode()) <= JOURNAL_MAX:
        return line
    rec = dict(rec)
    for k in ("reason", "notes"):
        if k in rec and rec[k] not in (None, ""):
            rec[k] = _shortened(rec[k])
    line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    if len(line.encode()) > JOURNAL_MAX:
        for k, v in list(rec.items()):
            if k not in ("event", "kind") and len(json.dumps(v).encode()) > 256:
                rec[k] = _shortened(v)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    return line if len(line.encode()) <= JOURNAL_MAX else None


def journal(rec):
    """One JSON line to the journal with SYSLOG_IDENTIFIER=chp-docs-ledger. Never a token or file bytes (callers
    pass entries and short records only). logger's 1 KiB default would cut a long entry: --size; a line that would
    still be cut is shortened first (_journal_line), and one that cannot be is never handed to logger (its cut would
    be silent) but goes to stderr. A logger that fails is never silent (Task 11a item 6b): the line goes to stderr,
    which systemd puts in the unit's journal (journalctl -u chp-docs-ledger); a caller's flow is never changed by it."""
    line = _journal_line(rec)
    if line is None:
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        why = f"the line is {len(line.encode())} bytes, longer than logger takes ({JOURNAL_SIZE})"
    else:
        try:
            r = subprocess.run(["logger", "-t", IDENT, "--size", str(JOURNAL_SIZE), "--", line], check=False,
                               timeout=10)
            why = None if r.returncode == 0 else f"exit {r.returncode}"
        except (OSError, subprocess.SubprocessError) as e:
            why = f"{type(e).__name__}: {e}"
    if why is not None:
        try:
            print(f"{IDENT}: logger failed ({why[:200]}); the journal line was: {line[:JOURNAL_SIZE]}", file=sys.stderr,
                  flush=True)
        except (OSError, ValueError):
            pass


def _ts(now):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _nfc(s):
    return unicodedata.normalize("NFC", s)


def _dir0700(p):
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(p, 0o700)


# ---------- Kanidm ----------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Kanidm's userinfo never redirects; a redirect is refused, never followed (the token would go with it)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise KanidmRefused(f"Kanidm's userinfo answered with a redirect (HTTP {code}); refused, not followed")


def _opener(cafile):
    ctx = ssl.create_default_context(cafile=cafile)       # the site CA only; no system store
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                       urllib.request.HTTPSHandler(context=ctx))


def _userinfo_call(url, token, opener, timeout):
    q = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    try:
        with opener.open(q, timeout=timeout) as f:
            raw = f.read(65536)
    except KanidmRefused:
        raise
    except urllib.error.HTTPError as e:
        if e.code in (400, 401, 403):
            raise TokenRejected(f"HTTP {e.code}") from None
        if 300 <= e.code < 400:
            raise KanidmRefused(f"Kanidm's userinfo answered with a redirect (HTTP {e.code}); refused") from None
        raise KanidmUnavailable(f"HTTP {e.code}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise KanidmRefused(f"Kanidm's certificate does not verify against the site CA ({e.reason})") from None
        raise KanidmUnavailable(str(e.reason)) from None
    except ssl.SSLCertVerificationError as e:
        raise KanidmRefused(f"Kanidm's certificate does not verify against the site CA ({e})") from None
    except (OSError, ValueError, http.client.HTTPException) as e:   # timeouts, resets, a broken HTTP answer
        raise KanidmUnavailable(str(e)) from None
    try:
        ui = json.loads(raw)
    except ValueError:
        raise KanidmRefused("Kanidm's userinfo did not answer JSON") from None
    if not isinstance(ui, dict):
        raise KanidmRefused("Kanidm's userinfo did not answer a JSON object")
    return ui


def kanidm_userinfo(url, token, cafile=SITE_CA, timeout=TIMEOUT):
    """Kanidm's chp-doc userinfo for this Bearer: https only, the host from documents.conf, the site CA only, no
    redirects, no proxy, a timeout. Raises KanidmUnavailable / TokenRejected (retry) or KanidmRefused."""
    if not isinstance(url, str) or not url.startswith("https://"):
        raise KanidmRefused(f"KANIDM_USERINFO_URL must be an https:// URL (it is {url!r})")
    return _userinfo_call(url, token, _opener(cafile), timeout)


# ---------- the ledger ----------

def entry_hash(line):
    return rl.entry_hash(line)


def _lines(path):
    try:
        return rl._lines(path)
    except SiteError as e:
        raise LedgerError(str(e).split(":")[0] + ": the last line is incomplete (an interrupted write?)") from None


def read(path, head, require_head=False):
    """Every entry, after checking the chain and the head witness; LedgerError naming the first bad line.
    require_head (verify, export; Task 11a item 6c): a ledger with entries but no ledger.head is a problem (deleted,
    or the head write after the first entry failed). The appender does not require it: its next entry rewrites it."""
    lines = _lines(path)
    out, prev = [], GENESIS
    for n, ln in enumerate(lines, 1):
        try:
            e = json.loads(ln)
        except ValueError:
            raise LedgerError(f"ledger {path}: line {n} is not a valid entry") from None
        if not isinstance(e, dict) or not set(FIELDS) <= set(e) <= set(FIELDS + OPTIONAL):
            raise LedgerError(f"ledger {path}: line {n} has the wrong fields")
        if e["prev"] != prev:
            raise LedgerError(f"ledger {path}: entry {n} does not follow entry {n - 1} (the chain is broken there)")
        out.append(e)
        prev = entry_hash(ln)
    hf = Path(head)
    if hf.exists():
        try:
            count, h = hf.read_text().split()[:2]
            count = int(count)
        except ValueError:
            raise LedgerError(f"{hf} is unreadable") from None
        if len(lines) < count or (count and entry_hash(lines[count - 1]) != h):
            raise LedgerError(f"ledger {path} is missing or shorter than its recorded head ({count} entries)")
    elif require_head and lines:
        raise LedgerError(f"{hf} (ledger.head, the head witness) is missing although the ledger has {len(lines)} "
                          "entries: deleted, or the head write after an entry failed (journal event head-write-failed); "
                          "compare with the site stick (chp-site doc-ledger verify --stick); the next entry rewrites it")
    return out


READ_WAIT = 120                    # a reader (verify, pending, export, the review) waits this long for the appender


class _Shared:
    """The ledger under a SHARED flock (Task 9 review M1): a reader never sees the appender's half-written line; it
    waits up to `wait` seconds while a request holds the exclusive lock, then raises LedgerBusy. No ledger file yet:
    nothing to lock (read() then checks the head witness on its own)."""
    def __init__(self, path, wait=None, clock=time.monotonic, sleep=time.sleep):
        wait = READ_WAIT if wait is None else wait
        self.path, self.wait, self.clock, self.sleep, self.fd = Path(path), wait, clock, sleep, None

    def __enter__(self):
        try:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return self
        end = self.clock() + self.wait
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if self.clock() >= end:
                    os.close(self.fd)
                    self.fd = None
                    raise LedgerBusy(f"the document ledger is locked by the appender (a request in progress) for more "
                                     f"than {self.wait} s; try again later") from None
                self.sleep(0.5)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
        return False


def read_shared(path, head, wait=None, require_head=False):
    """read(), under the shared lock."""
    with _Shared(path, READ_WAIT if wait is None else wait):
        return read(path, head, require_head)


class _Ledger:
    """The ledger under an exclusive flock (the whole decide + publish + append runs inside it)."""
    def __init__(self, ctx):
        self.path, self.head = ctx.ledger, ctx.head

    def __enter__(self):
        _dir0700(self.path.parent)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX)
            os.fchmod(self.fd, 0o600)
            self.entries = read(self.path, self.head)
        except BaseException:
            os.close(self.fd)
            raise
        return self

    def __exit__(self, *exc):
        os.close(self.fd)
        return False

    def by_request(self, rid):
        return next((e for e in self.entries if e["request_id"] == rid), None)

    def append(self, e, journal=None):
        """Write the entry's line, then the head witness. A line that cannot be written and fsynced in full is cut
        back off (ftruncate to the size before it) and _NotAppended is raised: nothing was appended. Once the line is
        fsynced the entry IS appended: a failure to write the head is only journalled (the head is a witness that
        may lag; the next append rewrites it)."""
        try:                                              # nothing written yet: any failure here = not appended
            lines = _lines(self.path)
            e = dict(e, seq=len(lines) + 1, prev=entry_hash(lines[-1]) if lines else GENESIS)
            line = json.dumps(e, sort_keys=True, separators=(",", ":"))
            data = (line + "\n").encode()
            size = os.fstat(self.fd).st_size
        except (OSError, SiteError, ValueError, TypeError) as err:
            raise _NotAppended(err, True) from None
        try:
            _write_line(self.fd, data)
            os.fsync(self.fd)
        except OSError as err:
            try:
                os.ftruncate(self.fd, size)
                os.fsync(self.fd)
                cut = True
            except OSError:
                cut = False
            raise _NotAppended(err, cut) from None
        self.entries.append(e)
        try:
            self._write_head(e, line)
        except OSError as err:
            if journal:
                _safe(journal, {"event": "head-write-failed", "seq": e["seq"], "error": str(err)[:200]})
        return e

    def _write_head(self, e, line):
        tmp = self.head.with_name(self.head.name + ".tmp")
        hf = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(hf, "w") as f:
            f.write(f"{e['seq']} {entry_hash(line)}\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.head)


def verify(ledger, head, stick_heads=None, say=print, wait=None):
    """0 = the chain and head verify (and every stick head is still in the chain); 1 = a problem (review_ledger's
    exit codes; 2, the stick not present, is the command's; 3 = busy: the appender held the lock too long)."""
    try:
        entries = read_shared(ledger, head, wait, require_head=True)
    except LedgerBusy as e:
        say(f"BUSY: {e}")
        return 3
    except LedgerError as e:
        say(f"PROBLEM: {e}")
        return 1
    problems = []
    if stick_heads is not None:
        try:
            problems = rl.verify_heads(ledger, stick_heads)
        except SiteError as e:
            problems = [str(e)]
    for p in problems:
        say(f"PROBLEM: {p}")
    if problems:
        return 1
    say(f"OK: chain and head match, {len(entries)} entries; "
        + ("stick anchor OK" if stick_heads is not None else "stick anchor NOT checked (run with --stick)"))
    return 0


def export(stick, ctx=None, now=None):
    """<stick>/docs-ledger/: a copy of the ledger, verify.txt, and the head appended to heads.txt."""
    ctx = ctx or Ctx.system()
    out = Path(stick) / "docs-ledger"
    out.mkdir(parents=True, exist_ok=True)
    with _Shared(ctx.ledger):                            # the copy and its check see the same, whole lines
        if ctx.ledger.exists():
            shutil.copyfile(ctx.ledger, out / "ledger.jsonl")
        try:
            read(ctx.ledger, ctx.head, require_head=True)
            problems = []
        except LedgerError as e:
            problems = [str(e)]
        count, h = rl.head(ctx.ledger)
    (out / "verify.txt").write_text("OK: chain and head match\n" if not problems else
                                    "PROBLEMS:\n" + "".join(f"- {p}\n" for p in problems))
    with open(out / "heads.txt", "a") as f:
        f.write(f"{count} {h} {_ts(now if now is not None else ctx.now())}\n")
    return {"head": (count, h), "problems": problems}


# ---------- spool, results, quarantine ----------

def _unlink_raw(p):
    os.unlink(p)


def _hold_raw(src, dst):
    os.rename(src, dst)


def _unlink(ctx, p):
    """Delete a spool file (it holds a Bearer token); a failure is logged, never raised. A file that cannot be deleted
    is moved aside into the root-only quarantine (Task 11a item 6a): left in the spool it would re-trigger the path
    unit until its trigger limit stops the appender for every request."""
    try:
        _unlink_raw(p)
    except FileNotFoundError:
        pass
    except OSError as e:
        _safe(ctx.journal, {"event": "spool-unlink-failed", "file": p.name, "error": str(e)[:200]})
        _hold(ctx, p, e)


def _hold(ctx, p, err):
    """Move an undeletable spool file into quarantine/ (root 0700; the file 0600) under a name never reused, and say
    so (Wazuh 100645, at once). One that cannot be moved either is alerted once (appender-failed, Wazuh 100646): the
    path unit will re-trigger on it, and only root can clear it."""
    try:
        _dir0700(ctx.quarantine)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ctx.now()))
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", p.name)[:64]
        dest = next(q for q in (ctx.quarantine / f"{stamp}-held-{n}-{safe}" for n in range(1000))
                    if not os.path.lexists(q))
        _hold_raw(p, dest)
    except (OSError, StopIteration) as e2:
        _stuck(ctx, p, err, e2)
        return
    note = ""
    try:
        if stat.S_ISREG(os.lstat(dest).st_mode):
            os.chmod(dest, 0o600)
            _held_record(ctx, p.name, dest, err)          # fix round 1, m1: the Bearer token goes at once
    except (OSError, ValueError, RecursionError) as e:
        note = f"; it still holds its Bearer token until purge-quarantine (rewrite failed: {str(e)[:80]})"
    _safe(ctx.journal, {"event": "quarantine", "request_id": p.name[:32] if REQ_NAME.fullmatch(p.name) else None,
                        "user": None, "why": f"the spool file {_clean(p.name, 80)} could not be deleted "
                                             f"({str(err)[:120]}): moved aside to quarantine as {dest.name}{note}"})


def _held_record(ctx, name, dest, err):
    """Replace a held regular file by its record: no Bearer token, no file bytes, the original's size and sha256."""
    h, n, head = hashlib.sha256(), 0, b""
    fd = os.open(dest, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            if n <= MAX_SPOOL:
                head += chunk
            n += len(chunk)
    try:
        req = json.loads(head) if n <= MAX_SPOOL else None
    except (ValueError, RecursionError):
        req = None
    rec = {"held_from": name, "held_at": _ts(ctx.now()), "original_sha256": h.hexdigest(), "bytes": n,
           "why": f"could not be deleted from the spool ({str(err)[:200]})",
           "request": _sanitize(req) if isinstance(req, dict) else {"unparsed": True}}
    tmp = dest.with_name(dest.name + ".rec")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _stuck_marker(ctx, name):
    return ctx.work / f"stuck-{_sha(name.encode('utf-8', 'surrogateescape'))[:32]}"


def _identity(p):
    """The spool file as it is (device, inode, size, mtime, ctime): a new file of the same name differs."""
    st = os.lstat(p)
    return f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"


def _marker_lines(m):
    fd = os.open(m, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        return f.read(4096).split("\n")


def _already_stuck(ctx, p):
    """True when THIS file (same name and identity) was set aside before and could be neither deleted nor moved: it
    is left alone, silently (P3-D11, logs/167: it was re-quarantined and re-alerted on every run). The marker holds
    the name and the identity; one of an older format (the name only) does not match, so the file is judged once
    more and the marker rewritten."""
    try:
        lines = _marker_lines(_stuck_marker(ctx, p.name))
        return len(lines) >= 2 and lines[0] == p.name and lines[1] == _identity(p)
    except (OSError, ValueError):
        return False


def _stuck(ctx, p, err, err2):
    m = _stuck_marker(ctx, p.name)
    try:
        ident = _identity(p)
    except OSError:
        ident = ""
    try:
        old = _marker_lines(m)
    except (OSError, ValueError):
        old = None
    if old is not None and old[0] == p.name and (len(old) < 2 or old[1] == ident):
        if len(old) < 2 and ident:                        # an older marker (name only): add the identity
            _write_marker(ctx, m, p.name, ident, replace=True)
        return                                            # alerted already: the path unit re-triggers on it
    _write_marker(ctx, m, p.name, ident, replace=old is not None)   # none written: alerted again next time
    _safe(ctx.journal, {"event": "appender-failed", "file": _clean(p.name, 80),
                        "message": f"the spool file {_clean(p.name, 80)} cannot be deleted or moved aside "
                                   f"({str(err)[:100]}; {str(err2)[:100]}): the path unit re-triggers on it until its "
                                   "limit stops the appender; remove it as root, then systemctl reset-failed "
                                   "chp-docs-ledger.path"})


def _write_marker(ctx, m, name, ident, replace=False):
    try:
        _dir0700(ctx.work)
        if replace:
            os.unlink(m)
        fd = os.open(m, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{name}\n{ident}")
        return True
    except OSError:
        return False


def _clear_stuck(ctx):
    """The markers of stuck spool files that are gone now (so a new one of the same name alerts again)."""
    try:
        ms = [m for m in ctx.work.iterdir() if m.name.startswith("stuck-")]
    except OSError:
        return
    for m in ms:
        try:
            name = _marker_lines(m)[0]
            if name and "/" not in name and os.path.lexists(ctx.spool / name):
                continue
            os.unlink(m)
        except OSError:
            continue


def _read_spool(p):
    """The spool file's bytes, never through a symlink, at most MAX_SPOOL; None if it is gone."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        data = f.read(MAX_SPOOL + 1)
    if len(data) > MAX_SPOOL:
        raise OSError(errno.EFBIG, f"larger than {MAX_SPOOL} bytes")
    return data


def _write_result(ctx, rid, user, state, message, entry=None, keep_final=False):
    """out/<id>.json, root:apache 0640, via a temporary file and rename. Never over another user's result (the app
    shows a result only to its owner; a request id reused by someone else must not take it over). False = not
    written because it belongs to someone else."""
    final = ctx.out / f"{rid}.json"
    try:
        fd = os.open(final, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            cur = json.loads(f.read(1 << 20))
        if isinstance(cur, dict) and cur.get("user") not in (None, user):
            return False
        if keep_final and isinstance(cur, dict) and cur.get("state") in ("done", "refused"):
            return False                                  # a final answer is never replaced by a "retry"
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        pass                                              # unreadable or corrupt: replaced below
    doc = {"request_id": rid, "user": user, "state": state, "message": message}
    if entry is not None:
        doc["entry"] = entry
    tmp = ctx.out / f".{rid}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, sort_keys=True)
            f.flush()
            os.fchmod(f.fileno(), 0o640)
            os.fsync(f.fileno())
        ctx.chown(tmp)
        os.replace(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def _blob(v):
    """A file's bytes in a record: only their size and sha256 (they can be CUI)."""
    if not isinstance(v, str):
        return v
    try:
        b = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        b = v.encode("utf-8", "surrogatepass")
    return {"bytes": len(b), "sha256": _sha(b)}


def _sanitize(r):
    out = {}
    for k, v in r.items():
        if k in ("bearer_token", "nc_app_token"):
            continue
        out[k] = _blob(v) if k in ("content", "pdf_content") else v
    return out


def _quarantine(ctx, p, raw, req, why, *, event="quarantine", answer=True):
    """Set a request aside: a record WITHOUT the Bearer token or the file bytes (an unparsable file only by size and
    sha256) in quarantine/ (root 0700, never overwritten), a journal line, and a refusal for its owner if it has one
    (answer False: a file whose name is not a request id gets no result). The spool file itself is deleted by the
    caller whatever happens. event: "set-aside" when the appender could not start (one appender-failed alert for the
    whole spool instead of one per file)."""
    rid = p.name[:32] if REQ_NAME.fullmatch(p.name) else "stray"
    try:
        _dir0700(ctx.quarantine)
        if isinstance(req, dict):
            rec = _sanitize(req)
        elif raw is None:
            rec = {"unreadable": why}
        elif req is _UNPARSED:
            rec = {"unparsed": True, "bytes": len(raw), "sha256": _sha(raw)}
        else:
            rec = {"not_an_object": type(req).__name__, "bytes": len(raw), "sha256": _sha(raw)}
        doc = {"quarantined_at": _ts(ctx.now()), "spool_file": p.name, "why": why, "request": rec}
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(ctx.now()))
        for n in range(1000):
            q = ctx.quarantine / f"{stamp}-{rid}-{n}.json"
            try:
                fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f, sort_keys=True)
            break
    except Exception as err:                              # noqa: BLE001 - the spool file goes anyway
        ctx.journal({"event": "quarantine-record-failed", "spool_file": p.name, "error": str(err)[:200]})
    user = req.get("user") if isinstance(req, dict) else None
    _safe(ctx.journal, {"event": event, "request_id": rid if rid != "stray" else None,
                        "user": user if isinstance(user, str) else None, "why": why[:300]})
    if answer and rid != "stray" and isinstance(user, str) and USER.fullmatch(user):
        try:
            _write_result(ctx, rid, user, "refused", "refused: the request could not be processed and was set aside "
                                                     f"for the ISSO ({why[:200]})")
        except Exception as err:                          # noqa: BLE001
            ctx.journal({"event": "result-write-failed", "request_id": rid, "error": str(err)[:200]})
    return Result("refused", f"quarantined: {why}", None)


_UNPARSED = object()


def purge_quarantine(ctx=None):
    """Remove every quarantine record (after the ISSO has looked at them; each was logged when it was made). Root."""
    if os.geteuid() != 0:
        raise SiteError("doc-ledger purge-quarantine must run as root (sudo)")
    ctx = ctx or Ctx.system()
    n = 0
    if ctx.quarantine.exists():
        for q in sorted(ctx.quarantine.iterdir()):
            if q.is_symlink() or q.is_file():             # a held link is removed itself, never its target
                q.unlink()
                n += 1
            elif q.is_dir():                              # a held folder (an undeletable *.json directory, 11a 6a)
                shutil.rmtree(q)                          # rmtree never follows a link inside it
                n += 1
    ctx.journal({"event": "quarantine-purged", "count": n})
    return n



# ---------- unfinished publishes (monitor check 82) and the ISSO's resolve entry (Plan 3 Task 9) ----------
# A publish writes a durable record unfinished/<request id> (root 0600 in a 0700 folder) under the ledger lock BEFORE
# its first write, and journals "publish-started". A clean end (its ledger entry, or publish-undone) removes the
# record; publish-undo-failed keeps it, with the failed steps. So a publish cut short (the service killed, the power
# lost) or one that left parts in the area stays listed whatever the journal's retention (Task 9 review I2) until the
# ISSO has looked at the area and runs chp-site doc-ledger resolve: a hash-chained ledger entry (kind "resolve",
# cycle 0: it never joins a document's cycle, so the author/approver rules and CR numbering are unchanged), and the
# record goes. The journal is a second source only, and only root's lines count (I1: anyone can write the tag).
PENDING_GRACE = 1800              # a journal-only start younger than this may still be running
RID = re.compile(r"[0-9a-f]{32}")
RESOLVE_KIND = "resolve"          # a ledger kind only the root CLI writes: never accepted from the spool (KINDS)


def journal_records(run=subprocess.run):
    """Every retained journal line of the appender, as (epoch, record) in order; lines that are not a JSON object are
    skipped. SiteError when journalctl itself fails (check 82 then alerts: unknown is never OK)."""
    try:
        # _UID is set by journald itself: a `logger -t chp-docs-ledger` by anyone but root is not the appender
        r = run(["journalctl", "-q", "--no-pager", "-o", "json", f"SYSLOG_IDENTIFIER={IDENT}", "_UID=0"],
                capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        raise SiteError(f"journalctl could not be run ({e})") from None
    if r.returncode != 0:
        raise SiteError(f"journalctl failed (exit {r.returncode}): {(r.stderr or '').strip()[:200]}")
    out = []
    for ln in (r.stdout or "").splitlines():
        try:
            j = json.loads(ln)
            msg = j["MESSAGE"]
            if isinstance(msg, list):                     # journalctl writes a non-UTF-8 message as a byte array
                msg = bytes(msg).decode("utf-8", "replace")
            rec = json.loads(msg)
            t = int(j["__REALTIME_TIMESTAMP"]) / 1e6
        except (ValueError, KeyError, TypeError):
            continue
        if isinstance(rec, dict):
            out.append((t, rec))
    return out


def _mark_unfinished(ctx, rid, rec):
    """Write unfinished/<rid> atomically (0600 in a 0700 folder, fsynced, never through a symlink). Raises OSError."""
    _dir0700(ctx.unfinished)
    tmp = ctx.unfinished / f".{rid}.tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(dict(rec, request_id=rid), f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, ctx.unfinished / rid)
    dfd = os.open(ctx.unfinished, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _clear_unfinished(ctx, rid):
    """A clean end: the record goes. A failure is journalled, never raised (the record then stays listed: safe)."""
    try:
        os.unlink(ctx.unfinished / rid)
    except FileNotFoundError:
        pass
    except OSError as e:
        _safe(ctx.journal, {"event": "unfinished-clear-failed", "request_id": rid, "error": str(e)[:200]})


def unfinished_records(ctx):
    """Every durable record: [{request_id, state, at, doc, failed}]. One that cannot be read is listed too
    (state "unfinished", doc "?"): unknown is never OK."""
    out = []
    try:
        names = sorted(os.listdir(ctx.unfinished))
    except FileNotFoundError:
        return out
    for n in names:
        if not RID.fullmatch(n):
            continue
        try:
            fd = os.open(ctx.unfinished / n, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as f:
                r = json.load(f)
            if not isinstance(r, dict):
                raise ValueError("not an object")
        except (OSError, ValueError):
            r = {"state": "unfinished", "doc": "?", "at": 0}
        out.append({"request_id": n, "state": "undo-failed" if r.get("state") == "undo-failed" else "unfinished",
                    "at": r.get("at") if isinstance(r.get("at"), (int, float)) else 0,
                    "doc": r.get("doc"), "failed": r.get("failed") if isinstance(r.get("failed"), list) else []})
    return out


def unresolved(records, entries, now, grace=PENDING_GRACE, files=()):
    """The publishes the ISSO must look at: [{request_id, state ("unfinished" | "undo-failed"), at, doc, failed}].
    `files` (unfinished_records, read under the ledger lock) are the record: an unfinished one is listed unless its
    entry is in the ledger (a removal that failed after a clean publish); an undo-failed one until it is resolved.
    `records` (the journal, root's lines only) add starts the files do not hold; a start there is closed only by the
    ledger's own entry or by publish-undone, never by a journal "ledger" line. An undo that failed is never closed by a
    later end event of the same request. Request ids that are not 32 hex are ignored."""
    published = {e.get("request_id") for e in entries if e.get("kind") == "publish"}
    resolved = {}                                         # request id -> when the ISSO resolved it
    for e in entries:
        if e.get("kind") == RESOLVE_KIND:
            try:
                resolved[e.get("resolves")] = calendar.timegm(time.strptime(e["ts"], "%Y-%m-%dT%H:%M:%SZ"))
            except (KeyError, TypeError, ValueError):
                continue
    state = {}
    for t, r in sorted(records, key=lambda x: x[0]):
        rid, ev = r.get("request_id"), r.get("event")
        if not isinstance(rid, str) or not RID.fullmatch(rid):
            continue
        cur = state.get(rid)
        if ev == "publish-undo-failed":
            state[rid] = {"request_id": rid, "state": "undo-failed", "at": t, "doc": r.get("doc"),
                          "failed": r.get("failed") if isinstance(r.get("failed"), list) else []}
        elif cur is not None and cur["state"] == "undo-failed":
            continue
        elif ev == "publish-started":
            state[rid] = {"request_id": rid, "state": "unfinished", "at": t, "doc": r.get("doc"), "failed": [],
                          "journal": True}
        elif cur is not None and ev == "publish-undone":
            del state[rid]
    for f in files:
        rid = f.get("request_id")
        if not isinstance(rid, str) or not RID.fullmatch(rid):
            continue
        cur = state.get(rid)
        if f["state"] == "undo-failed" or cur is None or cur["state"] != "undo-failed":
            state[rid] = dict(f)
    # a resolve covers what happened before it: the same request failing again later is listed again
    out = [p for rid, p in state.items() if not (rid in resolved and p["at"] <= resolved[rid] + 1)
           and (p["state"] == "undo-failed" or (rid not in published and (not p.get("journal")
                                                                         or p["at"] <= now - grace)))]
    for p in out:
        p.pop("journal", None)
    return sorted(out, key=lambda p: p["at"])


def _control(c):
    """A C0 or C1 control character, or DEL (final review A I-1: refused in reason and notes, as chp_ledger does)."""
    return ord(c) < 32 or 127 <= ord(c) <= 159


def _text_ok(v):
    """reason / notes as chp_ledger takes them: UTF-8 text of at most MAX_TEXT bytes with no control character."""
    try:
        return isinstance(v, str) and len(v.encode()) <= MAX_TEXT and not any(_control(c) for c in v)
    except UnicodeEncodeError:                            # a lone surrogate: not text
        return False


def _clean(x, n=300):
    return "".join(" " if ord(c) < 32 or 127 <= ord(c) <= 159 else c for c in str(x))[:n]


def pending_text(p):
    when = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(p["at"]))
    if p["state"] == "undo-failed":
        what = (f"publish {p['request_id']} ({_clean(p['doc'])}) failed at {when} and its UNDO INCOMPLETE "
                f"({_clean('; '.join(map(str, p['failed'])) or 'steps unknown')}): parts may be in the area")
    else:
        what = (f"publish {p['request_id']} ({_clean(p['doc'])}) started at {when} and never finished (the appender "
                "was stopped?): the area may hold half of it")
    return (what + f"; check the area, then: chp-site doc-ledger resolve {p['request_id']} --reason \"...\"")


def resolve(ctx, request_id, reason, *, operator, records, now=None):
    """Append the ISSO's resolve entry for one unfinished publish (after checking the area by hand). Root (the CLI
    checks). The entry is chained like every other and journalled (Wazuh 100651, level 7)."""
    if not isinstance(request_id, str) or not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise SiteError("resolve needs the request id (32 hex) that chp-site doc-ledger pending prints")
    reason = (reason or "").strip()
    if not reason or not _text_ok(reason):
        raise SiteError(f"resolve needs a --reason: what was checked and done (one line, at most {MAX_TEXT} bytes)")
    now = ctx.now() if now is None else now
    with _Ledger(ctx) as led:
        open_ = {p["request_id"]: p for p in unresolved(records, led.entries, now, files=unfinished_records(ctx))}
        p = open_.get(request_id)
        if p is None:
            raise SiteError(f"{request_id} is not an unfinished publish (chp-site doc-ledger pending lists them; one "
                            "already resolved is not listed)")
        e = {"ts": _ts(now), "kind": RESOLVE_KIND, "user": str(operator)[:200], "auth": "root", "kanidm_sub": None,
             "session_id": None, "request_id": os.urandom(16).hex(), "doc": p["doc"] if isinstance(p["doc"], str)
             else "", "file_id": None, "path": "", "sha256": "", "cycle": 0, "resolves": request_id,
             "reason": reason}
        try:
            e = led.append(e, ctx.journal)
        except _NotAppended as err:
            raise SiteError(f"the ledger could not be written ({str(err)[:200]}); nothing was recorded"
                            + ("" if err.cut else "; the ledger may end in a partial line: chp-site doc-ledger "
                                                  "verify")) from None
        _clear_unfinished(ctx, request_id)                # resolved: the record goes (a leftover is covered by the entry)
    _safe(ctx.journal, {"event": "ledger", **e})
    return e


def pending(ctx, records_fn=None, now=None):
    """chp-site doc-ledger pending: (the unresolved publishes, or raises LedgerError / LedgerBusy). Reads the ledger
    and the durable records under the shared lock, so no request is half-way while it looks. The journal is read
    BEFORE the lock (final review A M-6: journalctl can take long, and the appender waits for the lock meanwhile): a
    publish that starts after it has its durable record, and one that ends meanwhile has its entry in the ledger."""
    records_fn = records_fn or journal_records
    recs = records_fn()
    with _Shared(ctx.ledger):
        entries = read(ctx.ledger, ctx.head)
        files = unfinished_records(ctx)
    return unresolved(recs, entries, ctx.now() if now is None else now, files=files)

# ---------- one request ----------

def _shape(r):
    """None if the request has the shape chp_ledger writes, else what is wrong."""
    k = r.get("kind")
    if k not in KINDS:
        return "unknown kind"
    if r.get("auth") not in AUTHS:
        return "unknown auth"
    fid = r.get("file_id")
    if not isinstance(fid, int) or isinstance(fid, bool) or fid <= 0:
        return "file_id is not a file id"
    t = r.get("target")
    if t not in ("file", "folder"):
        return "target is not file or folder"
    name = r.get("name")
    if t == "folder":
        if not isinstance(name, str) or not name or len(name.encode()) > 255 or name in (".", "..") \
                or any(c in name for c in "/\\") or any(ord(c) < 32 or ord(c) == 127 for c in name):
            return "name is not one valid file name"
    elif name not in (None, ""):
        return "a file target has no name"
    if (k == "checkout" and t != "file") or (k == "new" and t != "folder"):
        return f"{k} names the wrong kind of target"
    s = r.get("sha256") or ""
    if not isinstance(s, str) or (k in ("approve", "override", "publish")) != bool(HEX64.fullmatch(s)) \
            or (s and not HEX64.fullmatch(s)):
        return "sha256 is missing or not 64 hex"
    for f in ("reason", "notes"):
        v = r.get(f)
        if v is not None and not _text_ok(v):
            return f"{f} is not valid text"
    for f in ("content", "pdf_content"):
        v = r.get(f)
        if (k == "publish") != isinstance(v, str) or (v is not None and not isinstance(v, str)):
            return f"{f} is missing or not allowed"
    if r["auth"] == "bearer":
        tok = r.get("bearer_token")
        if not isinstance(tok, str) or not tok or len(tok) > MAX_TOKEN or any(c.isspace() for c in tok):
            return "the Bearer token is missing or malformed"
    return None


def process_one(spool_path, ctx=None):
    """One spool file -> Result(state, message, entry|None). Writes out/<id>.json before the spool file is deleted;
    the spool file is always deleted (only names <32 hex>.json are ever touched)."""
    ctx = ctx or Ctx.system()
    p = Path(spool_path)
    if not REQ_NAME.fullmatch(p.name):
        return Result("refused", f"{p.name!r} is not a request file name (ignored)", None)
    if _already_stuck(ctx, p):
        return Result("refused", STUCK_AGAIN, None)
    raw = req = None
    try:
        try:
            raw = _read_spool(p)
        except OSError as e:
            why = "a symbolic link (not followed)" if e.errno == errno.ELOOP else f"unreadable ({e.strerror or e})"
            return _quarantine(ctx, p, None, None, why)
        if raw is None:
            return Result("refused", "the request is gone", None)
        try:
            req = json.loads(raw)
        except (ValueError, RecursionError):              # RecursionError: nested too deep (final review A M-7)
            return _quarantine(ctx, p, raw, _UNPARSED, "not valid JSON")
        if not isinstance(req, dict):
            return _quarantine(ctx, p, raw, req, "not a JSON object")
        rid = p.name[:32]
        if req.get("request_id") != rid:
            return _quarantine(ctx, p, raw, {k: v for k, v in req.items() if k != "user"},
                               "its request_id does not match its file name")
        user = req.get("user")
        if not isinstance(user, str) or not USER.fullmatch(user):
            return _quarantine(ctx, p, raw, {k: v for k, v in req.items() if k != "user"}, "no valid user")
        bad = _shape(req)
        if bad:
            return _quarantine(ctx, p, raw, req, bad)
        try:
            return _handle(ctx, rid, req)
        except Exception as err:                          # noqa: BLE001 - never crash, never loop
            return _quarantine(ctx, p, raw, req, f"internal error: {type(err).__name__}: {str(err)[:200]}")
    finally:
        _unlink(ctx, p)


def process(ctx=None, budget=BUDGET, clock=time.monotonic):
    """The requests in the spool, oldest first, until `budget` seconds have passed (then the rest wait for the next
    start of the unit)."""
    ctx = ctx or Ctx.system()
    names, strays = [], []
    try:
        with os.scandir(ctx.spool) as it:
            for d in it:
                if REQ_NAME.fullmatch(d.name):
                    try:
                        names.append((d.stat(follow_symlinks=False).st_mtime, d.name))
                    except OSError:
                        continue
                elif _triggers(d.name):
                    strays.append(d.name)
    except FileNotFoundError:
        return []
    _clear_stuck(ctx)
    start, out = clock(), []
    # anything else the path unit's glob (*.json) sees is set aside first: left there it would re-trigger the unit until
    # its limit stops the appender (Task 11a item 6a). chp_ledger writes only <32 hex>.json (and .<id>.tmp). More than
    # STRAY_ALERT_MAX in one run: one alert for them all (fix round 1, m2), each still recorded.
    why = "not a request file name (chp_ledger writes <32 hex>.json only)"
    strays = [n for n in strays if not _already_stuck(ctx, ctx.spool / n)]   # set aside before, undeletable: counted once
    many = len(strays) > STRAY_ALERT_MAX
    for n in sorted(strays):
        out.append(_set_aside(ctx, ctx.spool / n, why, answer=False, event="set-aside" if many else "quarantine"))
    if many:
        _safe(ctx.journal, {"event": "quarantine", "request_id": None, "user": None,
                            "why": f"{len(strays)} files in the spool were {why}; set aside in quarantine (first: "
                                   + ", ".join(_clean(n, 40) for n in sorted(strays)[:STRAY_ALERT_MAX]) + ")"})
    for _, n in sorted(names):
        if out and clock() - start > budget:
            _safe(ctx.journal, {"event": "budget-reached", "processed": len(out), "waiting": len(names) - len(out)})
            break
        out.append(process_one(ctx.spool / n, ctx))
    return out


STRAY_ALERT_MAX = 5                # strays in one run alerted one by one; more = one aggregated line


def _triggers(name):
    """A name chp-docs-ledger.path's PathExistsGlob=*.json matches (glob(3): a leading dot is never matched)."""
    return name.endswith(".json") and not name.startswith(".")


STUCK_AGAIN = "set aside before and still undeletable (alerted once: appender-failed); left alone"


def _set_aside(ctx, p, why, *, event="quarantine", answer=True):
    """Quarantine one spool file as it is (read without following a symlink; recorded without the token) and remove it
    from the spool (or move it aside)."""
    if _already_stuck(ctx, p):
        return Result("refused", STUCK_AGAIN, None)
    raw = req = None
    try:
        try:
            raw = _read_spool(p)
        except OSError as e:
            return _quarantine(ctx, p, None, None, f"{why}; unreadable ({e.strerror or e})", event=event,
                               answer=answer)
        if raw is None:
            return Result("refused", "the request is gone", None)
        try:
            req = json.loads(raw)
        except (ValueError, RecursionError):
            req = _UNPARSED
        if isinstance(req, dict) and req.get("request_id") != p.name[:32]:
            answer = False                                # never a result under an id the file does not name
        return _quarantine(ctx, p, raw, req, why, event=event, answer=answer)
    finally:
        _unlink(ctx, p)


def run_process(budget=BUDGET):
    """chp-site doc-ledger process (the path unit's service): (results, None), or, when the appender cannot even set
    up (site.conf or documents.conf unreadable, Ctx.system() failing), (the spool deferred, the error): every request
    is deleted and answered "retry" (never over a final result; fix round 1, I2), a stray set aside, and
    appender-failed is journalled ONCE until a start succeeds again (Task 11a item 6a). Either way the spool is
    emptied: no restart storm, no permanent stop."""
    try:
        ctx = Ctx.system()
    except Exception as err:                              # noqa: BLE001 - whatever stops the set-up
        ctx = Ctx(base=BASE, site={}, conf={}, store=None)
        return _cannot_start(ctx, err), f"{type(err).__name__}: {str(err)[:300]}"
    try:
        os.unlink(ctx.work / "start-failed")
    except FileNotFoundError:
        pass
    except OSError as e:
        _safe(ctx.journal, {"event": "start-marker-clear-failed", "error": str(e)[:200]})
    return process(ctx, budget), None


def _cannot_start(ctx, err):
    """The appender cannot set up: one appender-failed alert (until a start succeeds), and every request in the spool is
    deleted (no token kept, nothing re-triggers) and answered "retry" (fix round 1, I2): never "refused", since a spool
    file can outlive its own append (killed between the append and the unlink), and never over a final (done /
    refused) result. The client re-sends the same id; the next good start answers an appended one from the ledger."""
    why = f"the appender could not start: {type(err).__name__}: {str(err)[:200]}"
    m = ctx.work / "start-failed"
    if not os.path.lexists(m):
        _safe(ctx.journal, {"event": "appender-failed",
                            "message": f"chp-site doc-ledger could not start ({type(err).__name__}: {str(err)[:300]}): "
                                       "document requests are answered retry (nothing recorded) until it is fixed "
                                       "(journalctl -u chp-docs-ledger)"})
        try:
            _dir0700(ctx.work)
            fd = os.open(m, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except OSError:
            pass                                          # no marker: alerted again next time (never silent)
    try:
        names = sorted(n for n in os.listdir(ctx.spool) if _triggers(n))
    except FileNotFoundError:
        return []
    out = []
    for n in names:
        p = ctx.spool / n
        if not REQ_NAME.fullmatch(n):
            out.append(_set_aside(ctx, p, why + "; not a request file name", event="set-aside", answer=False))
            continue
        out.append(_defer(ctx, p, why))
    return out


def _defer(ctx, p, why):
    rid = p.name[:32]
    try:
        try:
            raw = _read_spool(p)
            req = json.loads(raw) if raw is not None else None
        except (OSError, ValueError, RecursionError):
            req = None
        user = req.get("user") if isinstance(req, dict) and req.get("request_id") == rid else None
        ok_user = isinstance(user, str) and USER.fullmatch(user)
        _safe(ctx.journal, {"event": "deferred", "request_id": rid, "user": user if ok_user else None,
                            "why": why[:300]})
        msg = (f"pending: {why[:200]}; nothing was recorded; run the command again later (the ISSO has been "
               "alerted)")
        if ok_user:
            try:
                _write_result(ctx, rid, user, "retry", msg, keep_final=True)
            except Exception as e:                        # noqa: BLE001
                _safe(ctx.journal, {"event": "result-write-failed", "request_id": rid, "error": str(e)[:200]})
        return Result("retry", msg, None)
    finally:
        _unlink(ctx, p)


def _answer(ctx, rid, user, state, message, entry=None):
    try:
        if not _write_result(ctx, rid, user, state, message, entry):
            _safe(ctx.journal, {"event": "result-not-written", "request_id": rid, "user": user,
                                "why": "the result belongs to another user"})
    except Exception as err:                              # noqa: BLE001 - after an append: still "done"
        _safe(ctx.journal, {"event": "result-write-failed", "request_id": rid, "error": str(err)[:200]})
    return Result(state, message, entry)


def _handle(ctx, rid, r):
    user, kind = r["user"], r["kind"]

    # 1. a request id already appended: its entry (before Kanidm: a re-send with an expired token is still "done")
    try:
        with _Ledger(ctx) as led:
            prior = led.by_request(rid)
    except LedgerError as e:
        return _broken(ctx, rid, user, e)
    if prior is not None:
        return _prior(ctx, rid, user, prior)

    # 2. identity: every request needs a Bearer that Kanidm's chp-doc userinfo verifies for this very user (design:
    # identity comes only from Kanidm; app passwords, Login Flow v2 tokens and browser sessions are refused)
    if r["auth"] != "bearer":
        how = {"app-password": "an app password (or a Login Flow token)", "session": "a browser session"}[r["auth"]]
        return _refused(ctx, rid, r, f"refused: {kind} needs a Kanidm-verified Bearer sign-in (chp-site doc login); "
                                     f"this request came with {how}")
    try:
        ident = _verify_bearer(ctx, r)
    except _Retry as e:
        ctx.journal({"event": "retry", "request_id": rid, "user": user, "kind": kind, "why": str(e)[:200]})
        return _answer(ctx, rid, user, "retry", str(e))
    except _Refuse as e:
        return _refused(ctx, rid, r, str(e))

    # 3. under the lock: decide, act, append
    try:
        with _Ledger(ctx) as led:
            prior = led.by_request(rid)
            if prior is not None:
                return _prior(ctx, rid, user, prior)
            undo, warn = [], []
            try:
                e = _decide_and_act(ctx, led, r, ident, undo, warn)
            except _Refuse as err:
                return _refused(ctx, rid, r, str(err))
            except Maintenance as err:                    # the nightly backup: nothing was written (fix round 1, m3)
                msg = ("pending: the document server is in maintenance mode (the nightly backup); nothing was "
                       "recorded; run the command again in a few minutes")
                _safe(ctx.journal, {"event": "retry", "request_id": rid, "user": user, "kind": kind,
                                    "why": str(err)[:200]})
                return _answer(ctx, rid, user, "retry", msg)
            except StoreError as err:
                return _refused(ctx, rid, r, f"refused: the document server could not do it ({str(err)[:300]}); "
                                             "nothing was recorded; run the command again")
            try:
                e = led.append(e, ctx.journal)
                if e["kind"] == "publish":
                    _clear_unfinished(ctx, rid)            # the clean end, still under the lock
            except _NotAppended as err:
                # step 9 failed: the publish's writes are undone, so nothing is live without its entry
                failed = _undo(ctx.store, undo)
                if undo:
                    _journal_undo(ctx, r, e.get("doc"), failed)
                if failed:
                    msg = _incomplete(f"the ledger could not be written: {str(err)[:160]}", failed)
                else:
                    msg = (f"refused: the ledger could not be written ({str(err)[:160]}); nothing was recorded"
                           + ("; nothing was published (undone)" if undo else ""))
                if not err.cut:
                    _safe(ctx.journal, {"event": "ledger-partial-line", "request_id": rid, "error": str(err)[:200]})
                    msg += "; the ledger may end in a partial line: the ISSO must check it (chp-site doc-ledger verify)"
                return _refused(ctx, rid, r, msg)
    except LedgerError as err:
        return _broken(ctx, rid, user, err)
    # appended: from here on, whatever fails, the answer is "done"
    _safe(ctx.journal, {"event": "ledger", **e})
    return _answer(ctx, rid, user, "done", _done_text(e) + _warn_text(warn), e)


_CLAIM = re.compile(r"[;.(]?\s*\(?[Nn]othing was (?:published|written|recorded)[^;.)]*\)?")


def _incomplete(cause, failed):
    """The refusal when the undo could not be completed: never a claim that nothing was published."""
    cause = _CLAIM.sub("", cause).strip().rstrip(";.").strip()
    if cause.startswith("refused: "):
        cause = cause[len("refused: "):]
    return (f"refused: the publish failed ({cause[:400]}); UNDO INCOMPLETE ({'; '.join(failed)}): parts of it may be in "
            "the area; the ISSO must check the area (and the journal, event publish-undo-failed) before anyone "
            "publishes this document again")


def _journal_undo(ctx, r, doc, failed):
    rid = r["request_id"]
    _safe(ctx.journal, {"event": "publish-undo-failed" if failed else "publish-undone", "request_id": rid,
                        "doc": doc, **({"failed": failed} if failed else {})})
    if not failed:
        _clear_unfinished(ctx, rid)
        return
    try:                                                  # parts may be in the area: the record stays, with the steps
        _mark_unfinished(ctx, rid, {"state": "undo-failed", "at": ctx.now(), "doc": doc, "failed": failed})
    except OSError as e:
        _safe(ctx.journal, {"event": "unfinished-record-failed", "request_id": rid, "stage": "undo-failed",
                            "error": str(e)[:200]})


def _warn_text(warn):
    """The marking check's warnings (superseded citations), in the result message only: never refused, never in the
    ledger entry (Task 11a item 4)."""
    if not warn:
        return ""
    return ("; marking warnings (not refused; fix them in the next version): " + "; ".join(map(_clean, warn)))[:2000]


def _done_text(e):
    if e["kind"] == "publish":
        return f"published {e['path']} as {e['cr']} (ledger entry {e['seq']})"
    return f"{e['kind']} recorded (ledger entry {e['seq']})"


def _prior(ctx, rid, user, prior):
    if prior["user"] != user:
        ctx.journal({"event": "refused", "request_id": rid, "user": user, "why": "request id already used"})
        return Result("refused", "refused: that request id is already used", None)
    return _answer(ctx, rid, user, "done", _done_text(prior), prior)


def _broken(ctx, rid, user, err):
    _safe(ctx.journal, {"event": "ledger-broken", "request_id": rid, "error": str(err)[:300]})
    return _answer(ctx, rid, user, "refused", "refused: the document ledger does not verify, so nothing can be "
                                              "recorded; the ISSO must restore it (chp-site doc-ledger verify)")


def _refused(ctx, rid, r, message):
    _safe(ctx.journal, {"event": "refused", "request_id": rid, "user": r["user"], "kind": r["kind"],
                 "file_id": r["file_id"], "message": message[:500]})
    return _answer(ctx, rid, r["user"], "refused", message)


def _verify_bearer(ctx, r):
    url = ctx.conf.get("KANIDM_USERINFO_URL", "")
    client = ctx.conf.get("DOC_OIDC_CLIENT") or "chp-doc"
    if not url:
        raise _Refuse("refused: KANIDM_USERINFO_URL is not set in /etc/chp/documents.conf (run chp-site documents enable)")
    try:
        ui = ctx.userinfo(url, r["bearer_token"])
    except KanidmUnavailable as e:
        raise _Retry(f"pending: Kanidm could not be reached to check your sign-in ({str(e)[:100]}); nothing was "
                     "recorded; run the command again in a minute") from None
    except TokenRejected:
        raise _Retry("pending: Kanidm did not accept your sign-in token (it may have expired); nothing was recorded; "
                     "run the command again (it signs in again if needed)") from None
    except KanidmRefused as e:
        raise _Refuse(f"refused: {e}") from None
    name = ui.get("preferred_username")
    if name != r["user"]:
        raise _Refuse(f"refused: the Bearer token belongs to {name!r}, but NextCloud signed this request in as "
                      f"{r['user']}")
    aud = ui.get("aud")
    auds = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if client not in auds and ui.get("azp") != client:
        raise _Refuse(f"refused: the Bearer token was not issued to {client}")
    sub = ui.get("sub")
    sid = ui.get("sid")
    return {"sub": sub if isinstance(sub, str) else None, "session_id": sid if isinstance(sid, str) else None}


# ---------- the rules ----------

class _Target(NamedTuple):
    folder: int                     # the area folder that holds the document
    area: int                       # the Compliance area id
    cui: bool
    name: str
    node: Optional[Node]            # the named file (a file target), else None
    path: str
    doc: str
    series: str
    parts: object


def _ids(ctx, *keys):
    out = []
    for k in keys:
        v = str(ctx.conf.get(k, "")).strip()
        if not v.isdigit():
            raise _Refuse(f"refused: {k} is not set in /etc/chp/documents.conf (run chp-site documents enable)")
        out.append(int(v))
    return out


def _series(ctx, name):
    try:
        parts = ctx.marking.parse_name(name)
    except Exception as e:                                # noqa: BLE001 - the name rule's own message
        raise _Refuse(f"refused: {name}: the name does not follow the name rule "
                      f"(<CUI_|FCI_><title>_vX.Y[-DRAFT]): {str(e)[:200]}") from None
    title = getattr(parts, "title", None)
    if not title or not getattr(parts, "version", None):
        raise _Refuse(f"refused: {name}: the name does not follow the name rule (<CUI_|FCI_><title>_vX.Y[-DRAFT])")
    return f"{getattr(parts, 'prefix', '') or ''}{title}{os.path.splitext(name)[1].lower()}", parts


def _target(ctx, r):
    """Re-check the area here (the app's check is a pre-filter): the folder must be a Compliance area or inside one,
    and not a Superseded area or inside one, by file ids from the file cache."""
    comp = _ids(ctx, "CUI_COMPLIANCE_ID", "INTERNAL_COMPLIANCE_ID")
    sup = _ids(ctx, "CUI_SUPERSEDED_ID", "INTERNAL_SUPERSEDED_ID")
    generic = "refused: not a controlled document (it is not in CUI/Compliance or Internal/Compliance)"
    node = ctx.store.info(r["file_id"])
    if node is None:
        raise _Refuse(generic)
    if r["target"] == "file":
        if node.type != "file" or not node.ancestors:
            raise _Refuse(generic)
        folder, chain, name, path = node.ancestors[0], node.ancestors, _nfc(node.name), node.path
    else:
        if node.type != "folder":
            raise _Refuse(generic)
        folder, chain, name = node.file_id, (node.file_id,) + tuple(node.ancestors), _nfc(r["name"])
        path = f"{node.path}/{name}"
    if any(i in sup for i in chain):
        raise _Refuse(generic)
    area = next((i for i in chain if i in comp), None)
    if area is None:
        raise _Refuse(generic)
    series, parts = _series(ctx, name)
    return _Target(folder, area, area == comp[0], name, node if r["target"] == "file" else None, path,
                   f"{folder}/{series}", series, parts)


def _cycle(entries, doc):
    mine = [e for e in entries if e["doc"] == doc]
    n = 1 + sum(e["kind"] == "publish" for e in mine)
    return n, [e for e in mine if e["cycle"] == n]


def _won_race(entries, doc, cycle, user):
    """The publish by someone else that ended the previous cycle of `doc` when `user` was one of ITS authors (a lost
    publish race: P3-D4); else None."""
    if cycle < 2:
        return None
    prev = [x for x in entries if x["doc"] == doc and x["cycle"] == cycle - 1]
    pubs = [x for x in prev if x["kind"] == "publish"]
    return pubs[-1] if pubs and pubs[-1]["user"] != user and user in _authors(prev) else None


def _authors(cyc):
    out = []
    for e in cyc:
        if e["kind"] in ("new", "checkout") and e["user"] not in out:
            out.append(e["user"])
    return out


def _approvers(ctx):
    isso = (ctx.site.get("DOC_ISSO_ACCOUNT") or "").strip()
    appr = [a for a in (ctx.site.get("DOC_APPROVER_ACCOUNTS") or []) if a]
    return isso, appr


def _current(ctx, folder, series, exclude=None):
    out = []
    for n in ctx.store.children(folder):
        if n.type != "file" or n.file_id == exclude:
            continue
        try:
            s, _ = _series(ctx, _nfc(n.name))
        except _Refuse:
            continue
        if s == series:
            out.append(n)
    return out


def _reader_of(ctx, folder, name):
    """The current non-PDF document whose reader PDF `name` is (same name, .pdf), or None (final review A M-10: a
    reader copy is made by publish from its document; checked out, created or published as a document of its own it
    would start a second series under the reader's name)."""
    stem, ext = os.path.splitext(name)
    if ext.lower() != ".pdf":
        return None
    for n in ctx.store.children(folder):
        nst, next_ = os.path.splitext(_nfc(n.name))
        if n.type == "file" and nst == stem and next_.lower() != ".pdf":
            return n
    return None


def _decide_and_act(ctx, led, r, ident, undo, warn=None):
    t = _target(ctx, r)
    kind, user = r["kind"], r["user"]
    if kind in ("checkout", "new", "publish"):
        doc = _reader_of(ctx, t.folder, t.name)
        if doc is not None:
            raise _Refuse(f"refused: {t.name} is the reader copy of {doc.name} (publish makes it from that document), "
                          f"not a document of its own; check out {doc.name} instead")
    cycle, cyc = _cycle(led.entries, t.doc)
    starts = [i for i, e in enumerate(cyc) if e["kind"] in ("new", "checkout")]
    authors = _authors(cyc)
    e = {"ts": _ts(ctx.now()), "kind": kind, "user": user, "auth": r["auth"], "kanidm_sub": ident["sub"],
         "session_id": ident["session_id"], "request_id": r["request_id"], "doc": t.doc,
         "file_id": t.node.file_id if t.node else None, "path": t.path, "sha256": r.get("sha256") or "",
         "cycle": cycle}
    if r.get("notes"):
        e["notes"] = r["notes"]

    if kind == "checkout":
        e["sha256"] = _sha(ctx.store.read(t.node.file_id))   # freshness is recorded by the server, never the client
        return e

    if kind == "new":
        if cyc:
            raise _Refuse(f"refused: {t.series} already has a change in progress (started by {authors[0] if authors else cyc[0]['user']}); "
                          "use chp-site doc checkout")
        cur = _current(ctx, t.folder, t.series)
        if cur:
            raise _Refuse(f"refused: {t.series} already exists in this area as {cur[0].name}; use chp-site doc "
                          "checkout to change it")
        return e

    if kind in ("approve", "override"):
        isso, appr = _approvers(ctx)
        if not isso and not appr:
            raise _Refuse("refused: approvals are not set up on this site: DOC_ISSO_ACCOUNT and DOC_APPROVER_ACCOUNTS "
                          "are empty in site.conf (set them on the site stick and apply it)")
        if kind == "approve":
            if user not in [isso] + appr:
                raise _Refuse(f"refused: {user} is not an approver (DOC_ISSO_ACCOUNT, DOC_APPROVER_ACCOUNTS)")
            if not starts:
                raise _Refuse(f"refused: nothing to approve: {t.series} has no checkout or new in this cycle")
            if user in authors:
                did = "checked it out" if any(x["user"] == user and x["kind"] == "checkout" for x in cyc) \
                    else "created it"
                raise _Refuse(f"refused: {user} {did} in this cycle, so {user} is an author of this change (authors: "
                              f"{', '.join(authors)}); an approver must be someone else (a reviewer reads the "
                              "document without checking it out)")
            return e
        if not isso:
            raise _Refuse("refused: no ISSO is set (DOC_ISSO_ACCOUNT is empty), so nobody can override")
        if user != isso:
            raise _Refuse(f"refused: only the ISSO (DOC_ISSO_ACCOUNT, {isso}) may override")
        if not (r.get("reason") or "").strip():
            raise _Refuse("refused: an override needs a reason (--reason)")
        # spec §4: only when no approver account other than the author exists (the ISSO included: an ISSO who is not
        # an author of this change approves it normally)
        others = [a for a in [isso] + appr if a not in authors]
        if others:
            raise _Refuse(f"refused: not a one-person site: approver account(s) other than the author exist "
                          f"({', '.join(others)}); ask one of them to approve")
        if not starts:
            raise _Refuse(f"refused: nothing to approve: {t.series} has no checkout or new in this cycle")
        e["reason"] = r["reason"]
        return e

    return _publish(ctx, led, r, t, e, cyc, starts, authors, undo, [] if warn is None else warn)


# ---------- publish ----------

def _b64(v, what):
    try:
        return base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        raise _Refuse(f"refused: the {what} is not valid base64") from None


def _run_group(argv, input=b"", timeout=None):
    """Run argv in its own session; on a timeout SIGKILL the whole process group (runuser cannot pass a SIGKILL on
    to php, which would go on writing after we probed), wait a bounded time, then raise OccTimeout."""
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)
    try:
        out, err = p.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        killed, note = True, ""
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as e:                              # e.g. PermissionError: still a timeout, outcome unknown
            killed, note = False, f"; its process group could not be killed ({e.strerror or e}) and may still run"
            try:
                p.kill()
            except OSError:
                pass
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        what = f"occ {argv[-1] if argv else ''}".strip()
        raise OccTimeout(f"{what}: {'killed' if killed else 'timed out'} after {timeout} s{note}",
                         killed) from None
    return subprocess.CompletedProcess(argv, p.returncode, out, err)


def _put_step(s, undo, folder, name, data):
    """files:put, and its undo step. A put that fails may still have landed (occ killed at OCC_TIMEOUT after the
    server wrote the file): the area is probed by name (the name was free before) and a landed file gets its undo
    step; a probe that fails too records the outcome as unknown, so the undo reports itself INCOMPLETE."""
    try:
        n = s.put(folder, name, data)
    except Exception as err:
        what = f"files:put {name}: failed ({str(err)[:80]}) and its outcome is unknown"
        try:
            landed = next((c for c in s.children(folder) if c.type == "file" and _nfc(c.name) == name), None)
            ours = landed is not None and _sha(s.read(landed.file_id)) == _sha(data)
        except Exception as perr:                         # noqa: BLE001
            undo.append(("unknown", f"{what} ({str(perr)[:80]}): {name} may be in the area"))
        else:
            if ours:
                undo.append(("delete", landed.file_id))   # provably ours: the same bytes, under a name that was free
            elif landed is not None:                      # never delete a file we cannot prove is ours
                undo.append(("unknown", f"{what}: {name} is in the area with other bytes (a partial write?)"))
            elif isinstance(err, OccTimeout):             # killed: the cache may not show a write that happened
                undo.append(("unknown", f"{what}: occ was killed at the timeout and {name} is not seen in the file "
                                        "cache, which can miss a write cut off between the disk and the cache"))
        raise
    undo.append(("delete", n.file_id))
    return n


def _move_step(s, undo, node, dest, back):
    """files:move to `dest`, and its undo step (move back to `back`). A failed move is probed by file id: a move that
    landed gets its undo step; an unknown outcome makes the undo INCOMPLETE."""
    try:
        s.move(node.file_id, dest)
    except Exception as err:
        try:
            now = s.info(node.file_id)
        except Exception as perr:                         # noqa: BLE001
            undo.append(("unknown", f"files:move {node.name}: failed ({str(err)[:80]}) and its outcome is unknown "
                                    f"({str(perr)[:80]}): it may be in Superseded"))
        else:
            if now is not None and now.ancestors[:1] == (dest,):
                undo.append(("move", node.file_id, back))
            elif now is None:
                undo.append(("unknown", f"files:move {node.name}: failed ({str(err)[:80]}) and file id "
                                        f"{node.file_id} is no longer found"))
            elif isinstance(err, OccTimeout):
                undo.append(("unknown", f"files:move {node.name}: failed ({str(err)[:80]}) and its outcome is "
                                        "unknown: occ was killed at the timeout; the file cache still shows it in "
                                        "place, which can lag a move cut off midway"))
        raise
    undo.append(("move", node.file_id, back))


def _undo(store, undo):
    failed = []
    for step in reversed(undo):
        try:
            if step[0] == "unknown":
                failed.append(step[1])
            elif step[0] == "delete":
                store.delete(step[1])
            else:
                store.move(step[1], step[2])
        except Exception as e:                            # noqa: BLE001 - try every step, report what failed
            failed.append(f"{step[0]} {step[1]}: {str(e)[:120]}")
    return failed


def _publish(ctx, led, r, t, e, cyc, starts, authors, undo, warn):
    """Server-side publish, under the ledger lock: compare-and-write of the Compliance area. Any failure before the
    append undoes the writes already made; nothing is ledgered as published."""
    s = ctx.store
    user, name = r["user"], t.name
    if getattr(t.parts, "draft", False) or "-DRAFT" in name:
        raise _Refuse(f"refused: {name} is still -DRAFT: rename it without -DRAFT (the approved file, unchanged), "
                      "then publish")
    content = _b64(r["content"], "file content")
    pdf = _b64(r["pdf_content"], "reader PDF")
    sha = _sha(content)
    if sha != r["sha256"]:
        raise _Refuse("refused: the file sent is not the one this request names (its sha256 differs)")
    if user not in authors:
        won = _won_race(led.entries, t.doc, e["cycle"], user)
        if won is not None:                               # P3-D4: another author's publish ended this user's cycle
            raise _Refuse(f"refused: the current version changed since your checkout: {won.get('user')} published "
                          f"{won.get('path')} as {won.get('cr')} (ledger entry {won.get('seq')}), which ended the "
                          "change you checked out; check out the current version again (chp-site doc checkout) and "
                          "make your change on it")
        raise _Refuse(f"refused: {user} is not an author of this change (only {', '.join(authors) or 'nobody'} may "
                      "publish it: they created it or checked it out in this cycle)")
    after = cyc[starts[-1] + 1:] if starts else []
    if not any(x["sha256"] == sha and ((x["kind"] == "approve" and x["user"] not in authors) or x["kind"] == "override")
               for x in after):
        raise _Refuse("refused: no valid approval of this exact file (sha256) after the cycle's last checkout, by an "
                      "approver who is not an author")
    is_pdf = os.path.splitext(name)[1].lower() == ".pdf"
    if is_pdf and pdf != content:
        raise _Refuse("refused: a PDF document is its own reader copy: the reader PDF sent must be the same file")
    sup_folder = _ids(ctx, "CUI_SUPERSEDED_ID" if t.cui else "INTERNAL_SUPERSEDED_ID")[0]

    # 1-2. the canonical copy now (read by the server) against this cycle's server-recorded checkout
    cur = _current(ctx, t.folder, t.series)
    if len(cur) > 1:
        raise _Refuse(f"refused: {t.series} has {len(cur)} current versions in the area "
                      f"({', '.join(n.name for n in cur)}); an administrator must resolve that first")
    old = cur[0] if cur else None
    checkouts = [x for x in cyc if x["kind"] == "checkout"]
    last_co = checkouts[-1] if checkouts else None
    supersedes = None
    if old is not None:
        if _nfc(old.name) == name:
            raise _Refuse(f"refused: {name} is the current version's name: a published file is never changed in "
                          "place; give the new version a new version number")
        old_sha = _sha(s.read(old.file_id))
        if last_co is None or last_co["file_id"] != old.file_id or last_co["sha256"] != old_sha:
            raise _Refuse(f"refused: the current version {old.name} changed since the cycle's last checkout (it is "
                          "not the copy that was checked out); check it out again")
        supersedes = old.file_id
    elif last_co is not None:
        # the checked-out version is gone from the area: allowed only if an administrator already moved it, unchanged,
        # to Superseded (the way out of DEGRADED mode)
        moved = s.info(last_co["file_id"])
        if moved is None or sup_folder not in ((moved.file_id,) + tuple(moved.ancestors)) \
                or _sha(s.read(moved.file_id)) != last_co["sha256"]:
            raise _Refuse(f"refused: the version checked out in this cycle ({last_co['path']}) is no longer in the "
                          "area; check out the current version again")
        supersedes = moved.file_id
    listing = s.children(t.folder)
    names = {_nfc(n.name) for n in listing}
    sup_names = {_nfc(n.name) for n in s.children(sup_folder)}
    pdf_name = os.path.splitext(name)[0] + ".pdf"
    if name in names or (not is_pdf and pdf_name in names):
        raise _Refuse(f"refused: {name if name in names else pdf_name} already exists in the area")
    old_pdf = None
    if old is not None:
        if _nfc(old.name) in sup_names:
            raise _Refuse(f"refused: {old.name} already exists in Superseded; an administrator must resolve that first")
        if not is_pdf:
            on = os.path.splitext(_nfc(old.name))[0] + ".pdf"
            old_pdf = next((n for n in s.children(t.folder) if n.type == "file" and _nfc(n.name) == on), None)
            if old_pdf is not None and on in sup_names:
                raise _Refuse(f"refused: {on} already exists in Superseded; an administrator must resolve that first")

    # 3 was the sha256 check above. 4. the marks, checked again here, on the bytes received and the reader PDF
    warn += _check_marks(ctx, t, name, content, pdf_name if not is_pdf else None, pdf, _versions(ctx, listing))

    # 5-8. compare-and-write, supersede, tag, reader PDF; undone on any failure (also when step 9 fails: the caller
    # holds `undo`). The intent is journalled first, so a publish cut short (the service killed) can be found.
    # the durable record first (Task 9 review I2): no write to the area without it. A record already there is an
    # earlier attempt of this very request that never ended cleanly (killed, or its undo failed): it is never
    # overwritten (a clean retry would then clear it without the ISSO; round 2, a); only resolve removes it
    rid = r["request_id"]
    if os.path.lexists(ctx.unfinished / rid):
        raise _Refuse(f"refused: an earlier attempt of this request left an unfinished publish (killed, or an "
                      f"incomplete undo); the ISSO must check the area and resolve {rid} first (chp-site doc-ledger "
                      "pending / resolve); nothing was written")
    try:
        _mark_unfinished(ctx, rid, {"state": "unfinished", "at": ctx.now(), "doc": t.doc, "name": name, "user": user})
    except OSError as err:
        _safe(ctx.journal, {"event": "unfinished-record-failed", "request_id": rid, "stage": "start",
                            "error": str(err)[:200]})
        raise _Refuse(f"refused: the publish could not be recorded as started ({str(err)[:160]}); nothing was "
                      "written; run the command again") from None
    _safe(ctx.journal, {"event": "publish-started", "request_id": r["request_id"], "user": user, "doc": t.doc,
                        "name": name, "supersedes": old.file_id if old is not None else None})
    try:
        if old is not None:
            now = s.info(old.file_id)
            if now is None or now.etag != old.etag or _sha(s.read(old.file_id)) != old_sha \
                    or now.ancestors[:1] != (t.folder,):
                raise _Refuse(f"refused: the current version {old.name} changed while publishing (a second publish or "
                              "an administrator's edit); nothing was written; check it out again")
        new = _put_step(s, undo, t.folder, name, content)
        if _sha(s.read(new.file_id)) != sha:
            raise _Refuse("refused: the copy written does not read back as the approved file")
        if old is not None:
            try:
                _move_step(s, undo, old, sup_folder, t.folder)
            except Degraded as err:
                raise _Refuse(f"refused: the old version {old.name} could not be moved to Superseded: {DEGRADED} "
                              f"({str(err)[:160]}). Nothing was published (the new copy was removed). The old version "
                              "cannot be moved by hand either: keep the approved file, tell the administrator, and run "
                              "publish again once chp-site documents status no longer says DEGRADED (see the guide)") from None
            if old_pdf is not None:
                try:
                    _move_step(s, undo, old_pdf, sup_folder, t.folder)
                except Degraded as err:
                    raise _Refuse(f"refused: the old reader PDF {old_pdf.name} could not be moved to Superseded: "
                                  f"{DEGRADED} ({str(err)[:160]}). Nothing was published") from None
        if t.cui and CUI_TAG not in s.tags(new.file_id):
            raise _Refuse(f"refused: {name} did not get its {CUI_TAG} tag in the CUI area (chp_foldertag); nothing was "
                          "published (undone); check chp-site documents status")
        if not is_pdf:
            pn = _put_step(s, undo, t.folder, pdf_name, pdf)
            if _sha(s.read(pn.file_id)) != _sha(pdf):
                raise _Refuse("refused: the reader PDF written does not read back as the one sent")
            if t.cui and CUI_TAG not in s.tags(pn.file_id):
                raise _Refuse(f"refused: {pdf_name} did not get its {CUI_TAG} tag; nothing was published (undone)")
    except (_Refuse, StoreError) as err:
        failed = _undo(s, undo)
        undo.clear()
        _journal_undo(ctx, r, t.doc, failed)
        if not failed and isinstance(err, Maintenance):
            raise err                                     # nothing left in the area: the caller answers "retry"
        if failed:
            msg = _incomplete(str(err), failed)
        else:
            msg = str(err) if isinstance(err, _Refuse) else (f"refused: the document server could not publish "
                                                             f"({str(err)[:300]}); nothing was published")
        raise _Refuse(msg) from None
    except Exception as err:
        failed = _undo(s, undo)
        undo.clear()
        _journal_undo(ctx, r, t.doc, failed)
        if failed:                                        # quarantined as an internal error: the words must stay
            raise _UndoIncomplete(f"UNDO INCOMPLETE ({'; '.join(failed)[:300]}): parts of the publish may be in the "
                                  f"area; the ISSO must check it; cause {type(err).__name__}: {str(err)[:200]}") \
                from err
        raise

    # 9. the entry (appended by the caller, still under the lock)
    year = e["ts"][:4]                                     # the entry's own year: one clock reading per entry
    n = 1 + sum(1 for x in led.entries if x["kind"] == "publish" and x["ts"][:4] == year)
    e.update(file_id=new.file_id, path=new.path, sha256=sha, cr=f"CR-{year}-{n:04d}", pdf_sha256=_sha(pdf))
    if supersedes is not None:
        e["supersedes"] = supersedes
    return e


def _versions(ctx, listing):
    """{series (prefix+title): its highest version 'X.Y'} of the files in the document's area folder (the listing the
    publish already read): marking's citation check (the workstation's doc._versions, on the server's own view)."""
    out, best = {}, {}
    for n in listing:
        if n.type != "file":
            continue
        try:
            p = ctx.marking.parse_name(_nfc(n.name))
            key = f"{getattr(p, 'prefix', '') or ''}{p.title}"
            v = str(p.version)
            vt = tuple(int(x) for x in v.split("."))
        except Exception:                                 # noqa: BLE001 - not a controlled name: not a citation target
            continue
        if key not in best or vt > best[key]:
            best[key], out[key] = vt, v
    return out


def _check_marks(ctx, t, name, content, pdf_name, pdf, current=None):
    """marking.check on the bytes received (and the reader PDF), in a root-only work folder that is always emptied.
    Returns the document's warnings (superseded citations, from `current`); they never refuse."""
    _dir0700(ctx.work)
    d = Path(tempfile.mkdtemp(dir=ctx.work))
    try:
        values = ctx.mark_values()
        problems, warnings = [], []
        for fname, data in ((name, content),) + (((pdf_name, pdf),) if pdf_name else ()):
            f = d / fname
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            # citations are checked in the document only (marking never reads them in a PDF; the reader PDF is
            # derived from it)
            rep = ctx.marking.check(f, t.cui, values, current if fname == name else None)
            if not rep.ok:
                what = "the reader PDF " + fname if fname == pdf_name else fname
                problems += [f"{what}: {p}" for p in (rep.problems or ["marking check failed"])]
            elif fname == name:
                warnings += [str(w) for w in (getattr(rep, "warnings", None) or [])]
        if problems:
            raise _Refuse("refused: the marking check on the server failed: " + "; ".join(problems)[:1500])
        return warnings
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------- NextCloud ----------

class OccStore:
    """NextCloud for the appender. Reads come from the file cache (SQL, as apache over the socket) and the canonical
    bytes from the team folder's storage on the disk (as root). Writes go through `occ files:put` (bytes on stdin),
    `files:move` and `files:delete --skip-trash` (the undo only), as the NextCloud account DOC_PUBLISH_USER
    (documents.conf; documents enable makes chp-publisher): a local account with no usable password whose
    groupfolders user rules alone may write the Compliance and Superseded areas. Through occ, the
    writes fire NextCloud's own events, so chp_foldertag tags them and the audit log records them. (Not WebDAV: that
    needs a stored credential for an account with access to CUI.)"""
    OCC = ["runuser", "-u", "apache", "--", "/usr/bin/php", "-d", "apc.enable_cli=1", "-d", "memory_limit=512M",
           "/usr/lib/nextcloud/occ"]

    def __init__(self, conf, run=subprocess.run, sql=None, data="/data/nextcloud/data/__groupfolders", occ_run=None):
        from . import documents as D
        self.user = (conf.get("DOC_PUBLISH_USER") or "").strip()
        self.run = run
        # occ: in its own process group, killed whole at the timeout (a test's fake `run` stands in for both)
        self.occ_run = occ_run or (_run_group if run is subprocess.run else run)
        self._sql = sql or D.sql_runner(run, timeout=SQL_TIMEOUT)
        self.data = Path(data)

    def sql(self, query):
        """documents.sql_runner raises SiteError (psql failed, timed out, or answered no JSON): a database blip is a
        StoreError like any other NextCloud failure (retry/undo paths), never a quarantine (final review A I-2)."""
        try:
            return self._sql(query)
        except StoreError:
            raise
        except SiteError as e:
            raise StoreError(f"the NextCloud database could not be read ({str(e)[:200]})") from None
        except subprocess.TimeoutExpired:
            raise StoreError(f"the NextCloud database did not answer in {SQL_TIMEOUT} s") from None

    def _occ(self, *argv, data=b""):
        if not self.user:
            raise StoreError("server-side publish is not set up: documents.conf has no DOC_PUBLISH_USER (run chp-site "
                             "documents enable)")
        try:
            if self.occ_run is _run_group:
                r = _run_group(self.OCC + list(argv), input=data, timeout=OCC_TIMEOUT)
            else:
                r = self.occ_run(self.OCC + list(argv), input=data, capture_output=True, timeout=OCC_TIMEOUT)
        except OccTimeout as e:
            how = "its process group was killed" if e.killed else \
                "its process group could not be killed and may still run"
            raise OccTimeout(f"occ {argv[0]} timed out after {OCC_TIMEOUT} s ({how})", e.killed) from None
        except subprocess.TimeoutExpired:
            raise OccTimeout(f"occ {argv[0]} timed out after {OCC_TIMEOUT} s") from None
        if r.returncode != 0:
            text = (r.stderr or b"").decode("utf-8", "replace") + (r.stdout or b"").decode("utf-8", "replace")
            last = (text.strip().splitlines() or [f"exit {r.returncode}"])[-1][:300]
            if MAINTENANCE_TEXT in text:
                raise Maintenance(f"occ {argv[0]}: NextCloud is in maintenance mode")
            raise (Degraded if "md5" in text.lower() else StoreError)(f"occ {argv[0]}: {last}")

    def _row(self, fid):
        rows = self.sql(
            "SELECT f.fileid, f.parent, f.name, f.path, f.etag, m.mimetype, g.folder_id, g.mount_point "
            "FROM oc_filecache f JOIN oc_mimetypes m ON m.id = f.mimetype "
            f"JOIN oc_group_folders g ON g.storage_id = f.storage WHERE f.fileid = {int(fid)}")
        return rows[0] if rows else None

    def info(self, fid):
        row = self._row(fid)
        if row is None:
            return None
        anc = self.sql(
            "WITH RECURSIVE a(fileid, parent, storage, d) AS (SELECT fileid, parent, storage, 0 FROM oc_filecache "
            f"WHERE fileid = {int(fid)} UNION ALL SELECT f.fileid, f.parent, f.storage, a.d + 1 FROM oc_filecache f "
            "JOIN a ON f.fileid = a.parent AND f.storage = a.storage WHERE a.d < 64) "
            "SELECT fileid, d FROM a WHERE d > 0 ORDER BY d")
        p = row["path"]
        rel = p[len("files/"):] if p.startswith("files/") else ("" if p == "files" else p)
        path = row["mount_point"] + ("/" + rel if rel else "")
        typ = "folder" if row["mimetype"] == "httpd/unix-directory" else "file"
        return Node(int(row["fileid"]), typ, row["name"], path, tuple(int(a["fileid"]) for a in anc), row["etag"])

    def children(self, folder):
        rows = self.sql(f"SELECT fileid FROM oc_filecache WHERE parent = {int(folder)} ORDER BY fileid")
        return [n for n in (self.info(int(r["fileid"])) for r in rows) if n is not None]

    def read(self, fid):
        """The canonical bytes, opened one path component at a time from the team folders' root with O_NOFOLLOW (a
        symbolic link anywhere below it is refused, never followed), a regular file only, at most MAX_READ bytes
        (final review A M-5)."""
        row = self._row(fid)
        if row is None:
            raise StoreError(f"file id {fid} is not in the file cache")
        parts = [str(int(row["folder_id"]))] + str(row["path"]).split("/")
        if any(x in ("", ".", "..") for x in parts):
            raise StoreError(f"cannot read {row['path']} (not a plain path in the file cache)")
        fds = []
        try:
            try:
                fds.append(os.open(self.data, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)))
                for x in parts[:-1]:
                    fds.append(os.open(x, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0),
                                       dir_fd=fds[-1]))
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=fds[-1])
            except OSError as e:
                why = "a symbolic link (not followed)" if e.errno in (errno.ELOOP, errno.ENOTDIR) else \
                    (e.strerror or str(e))
                raise StoreError(f"cannot read {row['path']} ({why})") from None
        finally:
            for d in fds:
                os.close(d)
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise StoreError(f"cannot read {row['path']} (not a regular file)")
            if st.st_size > MAX_READ:
                raise StoreError(f"cannot read {row['path']} (larger than {MAX_READ} bytes)")
            data = fh.read(MAX_READ + 1)
        if len(data) > MAX_READ:
            raise StoreError(f"cannot read {row['path']} (larger than {MAX_READ} bytes)")
        return data

    def _view(self, node):
        return f"/{self.user}/files/{node.path}"

    def put(self, folder, name, data):
        node = self.info(folder)
        if node is None:
            raise StoreError(f"folder id {folder} is not in the file cache")
        self._occ("files:put", "-", f"{self._view(node)}/{name}", data=data)
        q = name.replace("'", "''")
        rows = self.sql(f"SELECT fileid FROM oc_filecache WHERE parent = {int(folder)} AND name = '{q}'")
        if not rows:
            raise StoreError(f"{name} is not in the file cache after occ files:put")
        return self.info(int(rows[0]["fileid"]))

    def move(self, fid, folder):
        node, dest = self.info(fid), self.info(folder)
        if node is None or dest is None:
            raise StoreError("the file or the target folder is not in the file cache")
        self._occ("files:move", self._view(node), f"{self._view(dest)}/{node.name}")
        return self.info(fid)

    def delete(self, fid):
        node = self.info(fid)
        if node is None:
            return
        self._occ("files:delete", "--force", "--skip-trash", self._view(node))   # an undo: the copy never published

    def tags(self, fid):
        rows = self.sql("SELECT t.name FROM oc_systemtag_object_mapping m JOIN oc_systemtag t ON t.id = m.systemtagid "
                        f"WHERE m.objecttype = 'files' AND m.objectid = '{int(fid)}'")
        return {r["name"] for r in rows}
