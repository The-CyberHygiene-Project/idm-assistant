"""aider spike, phase 2 (THROWAWAY PROTOTYPE): the human gate between aider and a host, and the AI-change log.

Every command aider proposes passes through ask(): [Y]es / [N]o / [E]xplain / [R]evert-last. Before a Y the files the
command will touch are snapshotted on the host; R restores the last approved command's snapshot and restarts the
services it touched. Irreversible commands are flagged before the choice and need the typed word "yes".
Every event goes to a hash-chained JSONL log; every approved command also writes an audit record on the host."""
import base64
import hashlib
import json
import re
import shlex
import time
from pathlib import Path

IRREVERSIBLE = re.compile(r"\b(rm|shred|dd|mkfs|wipefs|userdel|groupdel|passwd|chpasswd|kanidm(?![-\w])|curl|wget|scp|rsync|"
                          r"cryptsetup|clevis|semodule -r|truncate|reboot|poweroff|shutdown|ga-enrol|revoke|unexpire)\b")
SERVICE = re.compile(r"systemctl\s+(?:restart|reload|stop|start|enable|disable)\s+(?:--now\s+)?([\w@.-]+)")
# Commands that change files they do not name: the gate backs those files up too (missing from facts() = no revert).
AUTHSELECT_FILES = [f"/etc/authselect/{n}" for n in ("authselect.conf", "nsswitch.conf", "user-nsswitch.conf", "system-auth",
                                                     "password-auth", "fingerprint-auth", "smartcard-auth", "postlogin")]
IMPLIED_FILES = [(re.compile(r"\bauthselect\s+(apply-changes|select|enable-feature|disable-feature)\b"), AUTHSELECT_FILES)]
READ_ONLY = re.compile(r"^(sshd -t|visudo -c|authselect (check|current|list\S*)|kanidm-unix status|"
                       r"systemctl (status|is-active|is-enabled)|id|getent|ls|cat|stat|grep)\b")


def facts(cmd, host):
    """What code (not the AI) can say about a command."""
    try:
        words = shlex.split(cmd)
    except ValueError:
        words = cmd.split()
    paths = sorted({w for w in words if w.startswith("/") and not w.startswith("/dev/")})
    services = sorted(set(SERVICE.findall(cmd)))
    for pat, implied in IMPLIED_FILES:
        if pat.search(cmd):
            paths = sorted(set(paths) | set(implied))
    bare = re.sub(r"^sudo\s+(-\S+\s+)*", "", cmd.strip())
    known = paths or services or READ_ONLY.search(bare)
    reversible = not IRREVERSIBLE.search(cmd) and bool(known)  # can't tell what it changes -> can't promise a revert
    return {"host": host, "files": paths, "services": services, "root": True, "reversible": reversible,
            "note": "file contents and service states can be restored" if reversible else
                    "CANNOT be reverted (deletes, changes credentials/keys, or talks to another system)"
                    if IRREVERSIBLE.search(cmd) else "CANNOT be reverted (the gate can't tell what this command changes)"}


class Log:
    """Append-only JSONL; each entry carries the hash of the previous one, so deletions and edits are detectable."""

    def __init__(self, path):
        self.path = Path(path)
        self.prev = "0" * 64
        if self.path.exists():
            lines = self.path.read_text().splitlines()
            if lines:
                self.prev = json.loads(lines[-1])["hash"]

    def write(self, event, **fields):
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields, "prev": self.prev}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        with self.path.open("a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.prev = rec["hash"]
        return rec


def verify(path):
    """Re-compute the chain; return the index of the first broken entry, or None if intact."""
    prev = "0" * 64
    for i, line in enumerate(Path(path).read_text().splitlines()):
        rec = json.loads(line)
        h = rec.pop("hash")
        if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != h:
            return i
        prev = h
    return None


def _wrap(text, indent="   "):
    import textwrap
    return "\n".join(textwrap.fill(p, 72, initial_indent=indent, subsequent_indent=indent) for p in str(text).splitlines() if p.strip())


# Every safety finding (code) in words a non-specialist can weigh: who gains or loses what. Unknown -> shown as is.
PLAIN = [
    (r"NEW privilege grant WITHOUT password: (\S+)", r"Gives \1 full administrator (root) power with NO password."),
    (r"NEW privilege grant: (\S+)", r"Gives \1 new administrator (root) power."),
    (r"^sudo: no authentication", "Lets someone run administrator commands without proving who they are."),
    (r"login group restriction removed", "Lets ANY directory account log in to this server, not just approved users."),
    (r"unixd: broad login group", "Widens who may log in to this server to a large or catch-all group."),
    (r"no longer valid TOML", "Breaks the login service's settings file: directory accounts cannot log in at all."),
    (r"^file emptied", "Empties a settings file: the service that uses it will fail."),
    (r"second step removed", "Removes the second login step (authenticator code): a stolen password is enough."),
    (r"^GA |jump skips GA", "Removes or bypasses the authenticator-code check at login."),
    (r"break-glass", "Locks out the emergency administrator account used when everything else fails."),
    (r"^sshd: weakened", "Makes remote login easier to break into (password or root login allowed)."),
    (r"unverified or plain-text", "Stops checking the identity server is genuine: logins could be intercepted."),
]


def plain(finding):
    for pat, words in PLAIN:
        m = re.search(pat, finding)
        if m:
            return m.expand(words) if "\\" in words else words
    return finding


def render_form(host, fields, changes, checks, reversible, n=None, total=None):
    """The decision form: Problem / Cause / Action / Downside / Choice. Lines checked by code are marked; the AI's
    words are plain sentences. Organized, not longer -- the raw diff waits for E."""
    bar = "=" * 72
    head = f" DECISION {n} of {total} on {host}" if n and total else f" DECISION on {host}"
    down = [_wrap(f"! SAFETY CHECK: {plain(c)}") for c in checks]
    down.append("   Can be undone: yes, R restores it (checked by code)" if reversible else
                "   *** CANNOT be undone by R (checked by code) ***")
    down.append(_wrap("If it is wrong: " + fields["downside"]))
    return "\n".join([
        "", bar, head, bar,
        " PROBLEM DETECTED", _wrap(fields["problem"]), _wrap("Why it matters: " + fields["implications"]), "",
        f" LIKELY CAUSE  ({'found by ' + fields['cause_by'] if 'diagnostic' in fields['cause_by'] else fields['cause_by']})",
        _wrap(fields["cause"]), "",
        " PROPOSED ACTION", _wrap(fields["action"]), _wrap("Changes: " + changes), "",
        " POTENTIAL DOWNSIDE", *down, "",
        " If unsure, press N: nothing on " + host + " changes.",
        "-" * 72,
        " CHOICE:  Y = apply   N = skip   E = show the exact change   R = undo the last change",
        " Type your choice, then press Enter."])


NO_AI = {"implications": "(AI summary unavailable)", "cause": "(AI summary unavailable)",
         "cause_by": "not diagnosed", "action": "(AI summary unavailable)", "downside": "(AI summary unavailable)"}


class Gate:
    """host_run(cmd) -> (rc, output) runs a command as root on the target; brief(**item) -> dict of the form's plain-language
    fields (problem, implications, cause, cause_by, action, downside) -- the AI may write them, code facts are added here;
    keys() -> one of y/n/e/r (and read_word() for the typed 'yes'); say(text) shows text to the operator."""

    def __init__(self, host, host_run, brief, log, operator, keys, read_word, say):
        self.host, self.run, self.brief, self.log, self.operator = host, host_run, brief, log, operator
        self.n, self.total, self.problem = 0, None, ""            # problem = the reported symptom, shown even without AI
        self.history = []                                          # (n, what, outcome) for the session summary
        self.interpret = None                                      # optional (what, rc, output) -> one plain sentence (AI)
        self.keys, self.read_word, self.say = keys, read_word, say
        self.last = None                                   # (cmd, snapshot dict, services) of the last approved command

    def _snapshot(self, files):
        """{path: base64 | "__ABSENT__" | None}. The body is fenced by markers, because the host's output can carry
        other text (client2's ssh banner did, and a backup with the banner in it emptied the file on revert)."""
        snap = {}
        for p in files:
            q = shlex.quote(p)
            rc, out = self.run(f"if [ -f {q} ]; then echo '<<B64'; base64 -w0 {q} || exit 3; echo; echo 'B64>>'; "
                               f"elif [ -e {q} ]; then echo __NOTFILE__; else echo __ABSENT__; fi")
            m = re.search(r"<<B64\n([A-Za-z0-9+/=]*)\nB64>>", out)
            if rc == 0 and m:
                snap[p] = m.group(1)
            elif rc == 0 and re.search(r"^__ABSENT__$", out, re.M):
                snap[p] = "__ABSENT__"
            else:
                snap[p] = None                              # no clean backup (incl. a directory: not a file to restore)
        return snap

    def _restore(self, p, b64):
        """Put one file back and prove it by its hash on the host. True only if the host's file now matches."""
        q = shlex.quote(p)
        if b64 == "__ABSENT__":
            self.run(f"rm -f {q}")
            rc, _ = self.run(f"test ! -e {q}")
            return rc == 0
        self.run(f"echo {b64} | base64 -d > {q}")
        _, out = self.run(f"sha256sum {q}")
        return hashlib.sha256(base64.b64decode(b64)).hexdigest() in out

    def _form(self, kind, subject, detail, findings, changes, reversible):
        self.n += 1
        self.say(f"\nPreparing decision {self.n}{f' of {self.total}' if self.total else ''} (plain-language summary, up to a minute)...")
        try:
            fields = {**NO_AI, **self.brief(kind=kind, subject=subject, detail=detail, findings=findings,
                                             reversible=reversible)}
        except Exception as e:                                       # the code facts still stand without the AI
            fields = {**NO_AI, "problem": self.problem or str(subject)}
            self.log.write("brief-failed", host=self.host, error=str(e)[:500])
        fields["problem"] = self.problem or fields.get("problem", "")
        self.log.write("briefed", host=self.host, subject=subject, form=fields)
        return render_form(self.host, fields, changes, findings, reversible, self.n, self.total)

    def _done(self, what, outcome):
        self.history.append((self.n, what, outcome))

    def _result(self, what, ok, changed, out):
        """RESULT section, same style as the form: outcome in words; what changed (checked by code, by comparing the
        files before and after); for a failure the system's own words, at most two lines, and the AI's reading."""
        msg = [l.strip() for l in _clean(out).splitlines() if l.strip()][-2:]
        lines = ["-" * 72, f" RESULT of decision {self.n}: {'DONE' if ok else 'FAILED'}"]
        if changed is None:
            lines.append("   What changed: not known (this command names no files) ")
        elif changed:
            lines.append(_wrap(f"What changed on {self.host}: {', '.join(changed)} (checked by code)"))
        else:
            lines.append(_wrap(f"What changed on {self.host}: nothing (checked by code)"))
        if not ok and msg:
            lines.append(_wrap("System's own message: " + " / ".join(msg)))
            if self.interpret:
                try:
                    lines.append(_wrap("What it means (AI's reading): " + self.interpret(what, msg)))
                except Exception:
                    pass
        lines.append("-" * 72)
        self.say("\n".join(lines))
        self._done(what, "DONE" if ok else ("FAILED, changed nothing" if changed == [] else "FAILED"))

    def _changed(self, snap):
        if not snap:
            return None
        after = self._snapshot(list(snap))
        return sorted(p for p in snap if after.get(p) != snap[p])

    def summary(self):
        lines = ["=" * 72, f" SESSION SUMMARY on {self.host}"]
        lines += [f"   {n}. {what} -- {outcome}" for n, what, outcome in self.history] or ["   (no decisions)"]
        lines.append(f"   R undoes: {self.last[0]}" if self.last else "   R undoes: nothing left to undo")
        lines.append("=" * 72)
        return "\n".join(lines)

    def revert(self):
        if not self.last:
            self.say("Nothing to revert.")
            return False
        cmd, snap, services = self.last
        failed = sorted(p for p, b64 in snap.items() if b64 is None or not self._restore(p, b64))
        for s in services:
            self.run(f"systemctl restart {shlex.quote(s)}")
        if failed:
            self.log.write("revert-failed", host=self.host, command=cmd, operator=self.operator, failed=failed)
            self.say(f"*** REVERT FAILED for {failed}: the file on {self.host} does NOT match the backup. Fix by hand. ***")
            return False
        self.log.write("revert", host=self.host, command=cmd, operator=self.operator, restored=sorted(snap))
        self.run(f"auditctl -m {shlex.quote(f'chp-ai revert host={self.host} approver={self.operator} cmd_sha={_sha(cmd)}')}")
        self.say(f"Reverted: {cmd}")
        self.last = None
        return True

    def ask(self, cmd, proposal_text=""):
        f = facts(cmd, self.host)
        self.log.write("proposed", host=self.host, command=cmd, proposal=proposal_text[:2000], facts=f)
        changes = "runs the command below" + (f"; files: {', '.join(f['files'])}" if f["files"] else "") + \
                  (f"; restarts: {', '.join(f['services'])}" if f["services"] else "")
        form = self._form("command", cmd, cmd, [], changes, f["reversible"])
        while True:
            self.say(form)
            k = self.keys()
            if k == "e":
                self.log.write("explained", host=self.host, command=cmd)
                self.say(f"\n EXACT CHANGE: this command runs as root on {self.host}:\n   {cmd}\n   ({f['note']})")
                continue
            if k == "r":
                self.revert()
                continue
            if k == "n":
                self.log.write("refused", host=self.host, command=cmd, operator=self.operator)
                self._done(f"Run: {cmd}", "SKIPPED (nothing changed)")
                return None
            if k == "y":
                if not f["reversible"]:
                    self.say("\n You chose YES. This change CANNOT be undone (shown above).\n"
                             " Please confirm your choice: type yes to go ahead, or no to cancel. Then press Enter.")
                    if self.read_word().strip().lower() != "yes":
                        self.log.write("refused", host=self.host, command=cmd, operator=self.operator, why="irreversible, not confirmed")
                        self._done(f"Run: {cmd}", "SKIPPED (nothing changed)")
                        return None
                snap = self._snapshot(f["files"]) if f["reversible"] else {}
                if None in snap.values():
                    self.log.write("refused", host=self.host, command=cmd, operator=self.operator, why="no clean backup")
                    self.say("Could not back up the files this touches, so it was NOT run.")
                    self._done(f"Run: {cmd}", "NOT RUN (no backup possible)")
                    return None
                rc, out = self.run(cmd)
                self.run(f"auditctl -m {shlex.quote(f'chp-ai approved host={self.host} approver={self.operator} rc={rc} cmd_sha={_sha(cmd)}')}")
                self.log.write("ran", host=self.host, command=cmd, operator=self.operator, rc=rc, output=_redact(out)[:2000],
                               snapshot=sorted(snap))
                if f["reversible"]:
                    self.last = (f"Run: {cmd}", snap, f["services"])
                self._result(f"Run: {cmd}", rc == 0, self._changed(snap), out)
                return rc, out


    def ask_file(self, path, new_text, diff, findings):
        """A proposed edit of one host file. findings = automatic safety findings (code, not the AI); any finding
        means the typed word "yes" is needed. Y writes the file in place (keeps owner, mode, SELinux label)."""
        self.log.write("proposed-edit", host=self.host, path=path, diff=diff[:4000], findings=findings)
        form = self._form("edit", path, diff, findings, f"edits the file {path}", True)
        while True:
            self.say(form)
            k = self.keys()
            if k == "e":
                self.log.write("explained", host=self.host, path=path)
                self.say(f"\n EXACT CHANGE to {path} on {self.host} (- removed, + added):\n{diff}")
                continue
            if k == "r":
                self.revert()
                continue
            if k == "n":
                self.log.write("refused", host=self.host, path=path, operator=self.operator)
                self._done(f"Edit {path}", "SKIPPED (nothing changed)")
                return False
            if k == "y":
                if findings:
                    self.say("\n You chose YES. This change has a SAFETY WARNING (shown above).\n"
                             " Please confirm your choice: type yes to apply it, or no to cancel. Then press Enter.")
                    if self.read_word().strip().lower() != "yes":
                        self.log.write("refused", host=self.host, path=path, operator=self.operator, why="safety finding, not confirmed")
                        self._done(f"Edit {path}", "SKIPPED (nothing changed)")
                        return False
                snap = self._snapshot([path])
                if snap[path] is None:
                    self.log.write("refused", host=self.host, path=path, operator=self.operator, why="no clean backup")
                    self.say(f"Could not back up {path} on {self.host}, so the edit was NOT applied.")
                    self._done(f"Edit {path}", "NOT DONE (no backup possible)")
                    return False
                b64 = base64.b64encode(new_text.encode()).decode()
                rc, out = self.run(f"echo {b64} | base64 -d > {shlex.quote(path)}")
                self.run(f"auditctl -m {shlex.quote(f'chp-ai approved host={self.host} approver={self.operator} rc={rc} edit={path}')}")
                self.log.write("edited", host=self.host, path=path, operator=self.operator, rc=rc, sha256=_sha(new_text))
                _, now = self.run(f"sha256sum {shlex.quote(path)}")
                ok = rc == 0 and hashlib.sha256(new_text.encode()).hexdigest() in now     # proven by the host's hash
                self.last = (f"Edit {path}", snap, [])
                self._result(f"Edit {path}", ok, [path] if ok else self._changed(snap), out)
                return ok


ANSI = re.compile(r"\x1b\[[0-9;]*m")
BANNER = re.compile(r"^(\\S|Kernel \\r on \\m)$")


def _clean(text):
    """Output without terminal colour codes and the host's login banner."""
    return "\n".join(l for l in ANSI.sub("", text or "").splitlines() if not BANNER.match(l.strip()))


WORDS = {"y": "y", "yes": "y", "n": "n", "no": "n", "e": "e", "explain": "e", "details": "e",
         "r": "r", "revert": "r", "undo": "r", "q": "q", "quit": "q"}


def parse_choice(text, allowed):
    """A typed answer (then Enter) -> one letter of allowed, or None. Whole words only: 'es' or 'yesno' is not an
    answer, so leftover keystrokes can never approve anything."""
    k = WORDS.get(text.strip().lower())
    return k if k and k in allowed else None


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def _redact(text):
    text = re.sub(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "<token>", text)
    text = re.sub(r"(?i)(password|passphrase|secret|token)\s*[:=]\s*\S+", r"\1=<redacted>", text)
    return text
