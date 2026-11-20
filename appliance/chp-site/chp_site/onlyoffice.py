# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site onlyoffice enable|sweep|egress-render (ISO 0.7.0 Plan 3 Task 8): the workstation side of the editor
spike's gates. Root only.

  enable         (workstation, DOCUMENTS=yes; client-enrol's "docs" step) installs chp-onlyoffice (it pulls
                 ONLYOFFICE Desktop Editors 10.0.0, re-signed with the project key, and poppler-utils), checks that
                 the AI Tools plugin is gone and fapolicyd runs, renders the egress addresses, maps the vendor names
                 to 0.0.0.0 in /etc/hosts, turns linger off, and starts the egress table and the sweep timer.
  egress-render  writes /etc/chp/workstation-egress-addr.nft from the site files (the egress unit runs it before
                 every load, so the table always follows the site's server address). G3.
  egress-lockdown   (the lock-down unit, before its log line) records when the lock-down began and why.
  egress-recovered  (the egress unit after a good load, and monitor check 83) journals ONE recovery line for a
                 lock-down (Wazuh WS_RECOVERED_RULE, 12) or a render failure (WS_RECOVERED_RENDER_RULE, 7) that has
                 ended, once the Wazuh agent is connected: lines written while the link was down never reached the
                 manager (Task 13a, P3-D7).
  sweep          (chp-onlyoffice-sweep.timer, hourly) removes ONLYOFFICE's auto-recovery copies (CUI) of closed or
                 abandoned sessions: only for a user with NO running process at all (so never a live editor session,
                 nor a logged-in user's), and only recovery folders untouched for SWEEP_HOURS. The removal runs as
                 that user (never root inside a user's home) with doc.remove_editor_copies, the close hook's
                 function. It also turns linger off again for anyone who has it (ruling F3). Every removal is one
                 "removed ..." line under the journal tag chp-doc-sweep (Wazuh rule DOC_SWEEP_RULE, level 3). G2."""
import ipaddress
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import doc as DOC
from .hosts import server_of
from .sitefile import SiteError

SWEEP_HOURS = 12
SWEEP_TAG = "chp-doc-sweep"
MIN_UID = 1000
EGRESS_ADDR = "etc/chp/workstation-egress-addr.nft"
EGRESS_TABLE = "chp_workstation_egress"
EGRESS_UNIT = "chp-workstation-egress.service"
SWEEP_TIMER = "chp-onlyoffice-sweep.timer"
PACKAGE = "chp-onlyoffice"
TEMPLATES_PACKAGE = "chp-templates"              # doc new's marked templates (P3-D2: never installed on workstations)
STATE_DIR = "var/lib/chp/workstation-egress"     # P3-D7: what happened while the link was down (root 0700)
AGENT_STATE = "/var/ossec/var/run/wazuh-agentd.state"
RECOVERED_TAG = "chp-egress-recovered"
LOCKDOWN_TABLE = "chp_workstation_lockdown"
AI_PLUGIN = "/opt/onlyoffice/desktopeditors/editors/sdkjs-plugins/{9DC93CDB-B576-4F0C-B55E-FCC9C48DD007}"
LINGER_DIR = "/var/lib/systemd/linger"
# The vendor names the spike found in the binaries and web apps (update check, templates, registration, DocSpace,
# help): kept as defence in depth under the egress table (the control), as the spike recommends.
VENDOR_NAMES = ("download.onlyoffice.com", "templates.onlyoffice.com", "templates-embed.onlyoffice.com",
                "onlyoffice.com", "www.onlyoffice.com", "docspace.onlyoffice.com", "personal.onlyoffice.com")
HOSTS_BEGIN = "# BEGIN chp-onlyoffice: ONLYOFFICE's vendor names lead nowhere (the egress table is the control)"
HOSTS_END = "# END chp-onlyoffice"

processes = DOC.processes


def _p(root, rel):
    return Path(root) / rel.lstrip("/")


# ---------- G3: the egress addresses ----------

def egress_defines(site, hosts):
    """The include of the egress table: the site server, and the site resolver (clients resolve through the server:
    render.net_ks). IPv4 only, as the hosts table is; refuses an address that cannot be the server's.
    Time (owner decision 2026-11-20): a workstation takes time from the CHP server only, so the table lets chronyd
    reach the server's 123/udp and nothing else; NTP_UPSTREAM is the server's own source and opens nothing here.
    CHP_WS_NTP4/6 are still defined (the server; nothing over IPv6) so a table file from before this change loads and
    allows the same."""
    ip = server_of(hosts).ip
    a = ipaddress.ip_address(str(ip))
    if a.version != 4 or a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local:
        raise SiteError(f"the server address {ip} cannot be the workstation's egress destination")
    return (f"define CHP_WS_SERVER_IP = {a}\ndefine CHP_WS_RESOLVER_IP = {a}\n"
            f"define CHP_WS_NTP4 = {{ {a} }}\ndefine CHP_WS_NTP6 = {{ ::/128 }}\n")


def _write(path, text, mode):
    """Write atomically, only when content or mode differ. Returns True when written."""
    if path.exists() and not path.is_symlink() and path.read_text() == text and stat.S_IMODE(path.stat().st_mode) == mode:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".chp-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def render_egress(root, site, hosts):
    return _write(_p(root, EGRESS_ADDR), egress_defines(site, hosts), 0o644)


def egress_render(root, load, run=subprocess.run, now=time.time):
    """`chp-site onlyoffice egress-render` (chp-workstation-egress.service's ExecStartPre, "-": never fatal). A
    failure is ONE stderr line, "EGRESS RENDER FAILED: ..." (journal tag chp-workstation-egress: Wazuh 100632,
    level 7), and the last good file is left as it is (nft then loads it). The file is relabelled on every render,
    written or not (temp + rename leaves the temp file's label: carry 10; O5, lab 11c). P3-D7: a failure is also
    kept on disk (its first time and latest cause) and, after the next good render, reported by egress-recovered."""
    try:
        site, hosts = load()
        changed = render_egress(root, site, hosts)
    except Exception as e:                                # noqa: BLE001 - any cause: one line, the unit carries on
        why = " ".join(str(e).split())[:300] or type(e).__name__
        print(f"EGRESS RENDER FAILED: {why}; the last good address file /{EGRESS_ADDR} is loaded if there is one "
              "(stale if the server or resolver moved; none: the unit fails and the workstation locks down)",
              file=sys.stderr)
        _note(root, "render-failed", why, now)
        return 1
    if _p(root, EGRESS_ADDR).exists():
        _restorecon(run, _p(root, EGRESS_ADDR))
    _render_ok(root, now)
    print(f"/{EGRESS_ADDR}: {'written' if changed else 'unchanged'}")
    return 0


# ---------- P3-D7: say after the link is back what happened while it was down ----------

def _state(root):
    return _p(root, STATE_DIR)


def _read_state(root, name):
    try:
        d = json.loads((_state(root) / f"{name}.json").read_text())
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def _write_state(root, name, d):
    """Best effort (never gates the egress unit): a root-only folder, one small JSON file per state."""
    try:
        sd = _state(root)
        sd.mkdir(parents=True, exist_ok=True)
        os.chmod(sd, 0o700)
        _write(sd / f"{name}.json", json.dumps(d, sort_keys=True) + "\n", 0o600)
    except OSError:
        pass


def _drop_state(root, name):
    try:
        (_state(root) / f"{name}.json").unlink()
    except OSError:
        pass


def _ts(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _note(root, name, why, now):
    """A failure: its FIRST time is kept (when it began), its cause is the latest one."""
    old = _read_state(root, name) or {}
    _write_state(root, name, {"since": old.get("since") or int(now()), "why": why[:300]})


def _render_ok(root, now):
    """A good render after failed ones: the failure has ended; egress-recovered reports it (once)."""
    f = _read_state(root, "render-failed")
    if f is not None:
        old = _read_state(root, "render-recovered") or {}       # one not reported yet: keep the earliest start
        since = min([x for x in (f.get("since"), old.get("since")) if isinstance(x, int)] or [int(now())])
        _write_state(root, "render-recovered", {"since": since, "why": f.get("why"), "ended": int(now())})
        _drop_state(root, "render-failed")


def egress_lockdown(root, now=time.time):
    """`chp-site onlyoffice egress-lockdown` (the lock-down unit's first ExecStartPre, "-"): when it began and why
    (a failed render's cause, a missing address file, or nft refusing the table)."""
    if _read_state(root, "lockdown") is not None:
        return 0                                          # a second failure in the same lock-down: the first time stays
    f = _read_state(root, "render-failed")
    if not _p(root, EGRESS_ADDR).exists():
        why = (f"the address file /{EGRESS_ADDR} was missing"
               + (f" and the egress addresses could not be rendered ({f.get('why')})" if f else ""))
    elif f is not None:
        why = f"the egress table did not load; the egress addresses could not be rendered ({f.get('why')})"
    else:
        why = f"nft refused the egress table (journalctl -u {EGRESS_UNIT} for that boot)"
    _write_state(root, "lockdown", {"since": int(now()), "why": why[:400]})
    return 0


def _agent_connected(root):
    """None: no Wazuh agent state file (nothing to wait for); else whether wazuh-agentd says it is connected."""
    try:
        text = _p(root, AGENT_STATE).read_text()
    except OSError:
        return None
    return re.search(r"^status='connected'\s*$", text, re.M) is not None


def egress_recovered(root, run=subprocess.run, now=time.time):
    """`chp-site onlyoffice egress-recovered` (the egress unit's ExecStartPost, "-", and monitor check 83): for a
    lock-down that has ended (the egress table loaded, no lock-down table) and a render failure followed by a good
    render, ONE journal line each under the tag chp-egress-recovered, naming when it began and why. Not before the
    Wazuh agent says it is connected (lines sent into a dead link were lost: P3-D7); a line logger could not write
    (early boot) stays for the next run. Prints OK lines (check 83 ignores them)."""
    lock, rend = _read_state(root, "lockdown"), _read_state(root, "render-recovered")
    if lock is None and rend is None:
        print("OK egress: no ended lock-down or render failure to report")
        return 0
    if lock is not None:
        loaded = run(["nft", "list", "table", "inet", EGRESS_TABLE], capture_output=True, text=True).returncode == 0
        locked = run(["nft", "list", "table", "inet", LOCKDOWN_TABLE], capture_output=True, text=True).returncode == 0
        if not loaded or locked:
            lock = None                                   # still locked down: nothing has ended yet
    todo = []
    if lock is not None:
        todo.append(("lockdown", "auth.crit",
                     f"EGRESS RECOVERED after LOCKDOWN: the egress lock-down that began at {_ts(lock['since'])} "
                     f"({lock.get('why')}) has ended by {_ts(now())}; the egress table is loaded again (lines "
                     "written during the lock-down may never have reached the manager)"))
    if rend is not None:
        todo.append(("render-recovered", "auth.warning",
                     f"EGRESS RECOVERED after RENDER FAILED: the egress addresses could not be rendered from "
                     f"{_ts(rend['since'])} until {_ts(rend.get('ended') or now())} ({rend.get('why')}); the last "
                     "good address file was in use meanwhile"))
    if not todo:
        print("OK egress: still in lock-down; nothing to report yet")
        return 0
    if _agent_connected(root) is False:
        print("OK egress: recovered; the report waits until the Wazuh agent is connected (check 83 retries)")
        return 0
    for name, prio, line in todo:
        try:
            ok = run(["logger", "-p", prio, "-t", RECOVERED_TAG, line], capture_output=True, text=True).returncode == 0
        except OSError:
            ok = False
        if ok:
            _drop_state(root, name)
            print(f"OK egress: reported: {line}")
        else:
            print("OK egress: recovered; the report could not be logged yet (retried at the next run)")
    return 0


def hosts_text(text):
    """/etc/hosts with exactly one chp-onlyoffice block (the vendor names to 0.0.0.0) at its end. A block without its
    end line is refused (dropping "the rest of the block" would drop the rest of the file)."""
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        if lines[i] == HOSTS_BEGIN:
            if HOSTS_END not in lines[i + 1:]:
                raise SiteError(f"/etc/hosts has the chp-onlyoffice block start without its end line ({HOSTS_END}): "
                                "fix the file by hand, then re-run chp-site onlyoffice enable")
            i = lines.index(HOSTS_END, i + 1) + 1
            continue
        out.append(lines[i])
        i += 1
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out + [HOSTS_BEGIN, "0.0.0.0 " + " ".join(VENDOR_NAMES), HOSTS_END]) + "\n"


# ---------- G2: the sweep ----------

def _as_user(uid, gid, fn):
    """fn() in a child process that runs as uid:gid (root drops to the user first; anyone else may only be itself).
    fn returns a list of [kind, text] pairs; an exception in the child becomes [["error", text]], never a removal."""
    if os.geteuid() != 0 and uid != os.geteuid():
        raise SiteError(f"the sweep must run as root to act for uid {uid}")
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:                                           # the child: never returns
        code = 1
        try:
            os.close(r)
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
            if os.getuid() != uid or os.geteuid() != uid:
                raise OSError("could not drop to the user")
            data, code = json.dumps(fn()), 0
        except BaseException as e:                         # noqa: BLE001 - reported to the parent
            data = json.dumps([["error", f"{type(e).__name__}: {e}"]])
        try:
            with os.fdopen(w, "w") as f:
                f.write(data)
        finally:
            os._exit(code)
    os.close(w)
    with os.fdopen(r) as f:
        data = f.read()
    os.waitpid(pid, 0)
    try:
        return json.loads(data or "[]")
    except ValueError:
        return [["error", "the sweep child returned nothing readable"]]


def _newest(d, depth=4):
    """The newest mtime in a recovery folder (the folder itself and everything below, links not followed)."""
    best = os.lstat(d).st_mtime
    if depth:
        with os.scandir(d) as it:
            for e in it:
                st = e.stat(follow_symlinks=False)
                best = max(best, st.st_mtime)
                if stat.S_ISDIR(st.st_mode):
                    best = max(best, _newest(e.path, depth - 1))
    return best


def _editor_live(uid):
    return bool(processes().get(uid, set()) & set(DOC.EDITOR_PROCESSES))


def _sweep_home(home, now, hours, live=lambda: False):
    """As the user: remove the recovery folders untouched for `hours`, and the recents entries only they name.
    `live()` is asked again just before removing (an editor may have started since the parent's snapshot). Every
    removal is recorded as it is done, so an error part-way still returns what was already removed."""
    notes = []
    say = lambda m: notes.append(["note", m])            # noqa: E731
    cut = now - hours * 3600
    old, young = [], []
    for d in DOC._recover_dirs(home, say):
        try:
            (old if _newest(d) < cut else young).append(d)
        except OSError:
            young.append(d)                                # unreadable: never removed on a guess
    if not old:
        return notes
    if live():
        return notes + [["note", "kept: ONLYOFFICE started since the sweep looked; its recovery copies are in use"]]
    removed = []
    on = lambda x: removed.append(["removed", x])        # noqa: E731
    try:
        old_names = set().union(*(DOC._recover_names(d) for d in old))
        young_names = set().union(*(DOC._recover_names(d) for d in young)) if young else set()
        DOC.remove_editor_copies(home, lambda n: n in old_names and n not in young_names, say=say, on_removed=on)
        for d in old:                                      # a folder that names no file (Editor.bin only) is CUI too
            if os.path.lexists(d) and not os.path.islink(d) and os.path.isdir(d):
                shutil.rmtree(d)
                on(str(d))
    except Exception as e:                                 # noqa: BLE001 - reported with what was already removed
        return notes + removed + [["error", f"{type(e).__name__}: {e}"]]
    return notes + removed


def _homes(home_root, min_uid):
    try:
        names = sorted(os.listdir(home_root))
    except OSError:
        return
    for n in names:
        h = Path(home_root) / n
        try:
            st = os.lstat(h)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid < min_uid or st.st_uid == 65534:
            continue
        yield h, st.st_uid, st.st_gid


def _name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid {uid}"


def linger_off(run, linger_dir=LINGER_DIR, say=print):
    """loginctl disable-linger for everyone who has linger on (ruling F3: no user manager outlives the last session,
    so the sign-in tokens in $XDG_RUNTIME_DIR die at logout). Returns the names."""
    try:
        names = sorted(os.listdir(linger_dir))
    except OSError:
        return []
    off = []
    for n in names:
        r = run(["loginctl", "disable-linger", n], capture_output=True, text=True)
        if r.returncode != 0 or os.path.lexists(os.path.join(linger_dir, n)):
            why = (getattr(r, "stderr", "") or "").strip()[:200]
            say(f"could not turn linger off for {n} (loginctl exit {r.returncode}"
                + (f": {why}" if why else "") + "; still on)")
            continue
        off.append(n)
        say(f"linger turned off for {n} (ruling F3: no lingering user manager keeps sign-in tokens after logout)")
    return off


def sweep(*, run, home_root="/home", now=None, procs=None, as_user=_as_user, say=print, hours=SWEEP_HOURS,
          min_uid=MIN_UID, linger_dir=LINGER_DIR, recheck=_editor_live):
    """G2 (see the module text). Returns the removed paths and entries."""
    now = time.time() if now is None else now
    procs = processes() if procs is None else procs
    linger_off(run, linger_dir, say)
    removed, users = [], 0
    for home, uid, gid in _homes(home_root, min_uid):
        if not os.path.lexists(home / DOC.RECOVER):
            continue
        users += 1
        who = f"user {_name(uid)}, uid {uid}"
        comms = procs.get(uid, set())
        if comms & set(DOC.EDITOR_PROCESSES):
            say(f"kept {home}: ONLYOFFICE is running ({who}); its recovery copies are in use")
            continue
        if comms:
            say(f"kept {home}: a live session ({who}); swept after the user's last process ends")
            continue
        for kind, text in as_user(uid, gid, lambda: _sweep_home(home, now, hours, lambda: recheck(uid))):
            if kind == "removed":
                removed.append(text)
                say(f"removed {text} ({who}; no live session; older than {hours} h)")
            elif kind == "error":
                say(f"could not sweep {home} ({who}): {text}")
            else:
                say(f"{home}: {text}")
    say(f"swept {users} user(s): {len(removed)} item(s) removed")
    return removed


# ---------- enable (the workstation) ----------

def _restorecon(run, path):
    """restorecon on a file just replaced by rename (it carries the temp file's label); skipped where SELinux tools
    are absent (a test root, a Mac)."""
    try:
        run(["restorecon", str(path)], capture_output=True, text=True)
    except FileNotFoundError:
        pass


def _ok(run, argv):
    return run(argv, capture_output=True, text=True).returncode == 0


def enable(me, site, hosts, *, run, root=Path("/"), record=None, sleep=time.sleep):
    from . import audit
    from . import documents
    record = record or audit.record
    if site.get("DOCUMENTS") != "yes":
        raise SiteError("DOCUMENTS is not yes in site.conf: the editor belongs to sites with the document server")
    if me.role != "client":
        raise SiteError(f"{me.hostname} is the {me.role}: chp-site onlyoffice enable is for a workstation (client role)")
    done = []
    record("onlyoffice-enable", {"host": me.hostname, "step": "start"})
    if not _ok(run, ["rpm", "-q", PACKAGE]):
        run(["dnf", "--enablerepo=chp", "install", "-y", PACKAGE], check=True)
        done.append("installed chp-onlyoffice (ONLYOFFICE Desktop Editors 10.0.0, re-signed; poppler-utils; "
                    "chp-templates)")
    if not _ok(run, ["rpm", "-q", TEMPLATES_PACKAGE]):    # P3-D2: an editor installed before it Required them
        run(["dnf", "--enablerepo=chp", "install", "-y", TEMPLATES_PACKAGE], check=True)
        done.append("installed chp-templates (doc new's marked templates)")
    if os.path.lexists(_p(root, AI_PLUGIN)):
        raise SiteError(f"ONLYOFFICE's AI Tools plugin is still installed ({AI_PLUGIN}): run "
                        "/usr/libexec/chp/onlyoffice-ai-off (chp-onlyoffice), then re-run chp-site onlyoffice enable")
    done.append("AI Tools plugin absent")
    # G1: a package transaction can leave fapolicyd dead (spike limit 7); a dead one gets the proven restart
    if run(["systemctl", "is-active", "fapolicyd"], capture_output=True, text=True).stdout.strip() != "active":
        try:
            n, denied, _ = documents._fapolicyd_restart(run, sleep)
        except SiteError as e:                             # the same proof as documents enable; this host's words
            raise SiteError(str(e).replace("on this server", "on this host")
                            .replace("chp-site documents enable", "chp-site onlyoffice enable")) from None
        done.append(f"fapolicyd was not running: restarted ({n} time(s)); Denied accesses: {denied}")
    else:
        done.append("fapolicyd active")
    srv = server_of(hosts).ip
    hp = _p(root, "etc/hosts")
    for path, changed in ((_p(root, EGRESS_ADDR), render_egress(root, site, hosts) or True),   # O5: always
                          (hp, _write(hp, hosts_text(hp.read_text() if hp.exists() else ""), 0o644))):
        if changed:
            _restorecon(run, path)                         # temp + rename: give the file its policy label
    done.append(f"/etc/hosts: {len(VENDOR_NAMES)} ONLYOFFICE vendor names -> 0.0.0.0")
    failed = []
    names = linger_off(run, str(_p(root, LINGER_DIR)), say=lambda m: failed.append(m) if m.startswith("could") else None)
    if failed:
        raise SiteError("; ".join(failed) + ": turn it off (loginctl disable-linger NAME), then re-run chp-site "
                        "onlyoffice enable")
    done.append("linger off" + (f" (was on for {', '.join(names)})" if names else " (nobody had it)"))
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", "--now", EGRESS_UNIT, SWEEP_TIMER], check=True)
    run(["systemctl", "restart", EGRESS_UNIT], check=True)
    if not _ok(run, ["nft", "list", "table", "inet", EGRESS_TABLE]):
        raise SiteError(f"the egress table inet {EGRESS_TABLE} is not loaded after starting {EGRESS_UNIT}: "
                        f"see journalctl -u {EGRESS_UNIT}")
    done.append(f"egress table inet {EGRESS_TABLE}: only the site server {srv} (and its resolver); DoT/DoH refused")
    done.append(f"sweep timer {SWEEP_TIMER}: recovery copies older than {SWEEP_HOURS} h of users with no session")
    done.append("logind KillUserProcesses=yes takes effect at the next boot")
    record("onlyoffice-enable", {"host": me.hostname, "step": "done", "server": srv}, after=True)
    return done
