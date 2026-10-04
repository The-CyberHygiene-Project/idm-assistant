"""Allow-listed repairs: precheck -> approval -> backup -> apply -> verify (fresh report) -> undo if still faulty.
Nothing is applied without approval. A repair only runs on a host of its declared role."""
import base64 as _b64
import binascii as _binascii
import hashlib as _hashlib
import re as _re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from engine.findings import FAP_PATH, LOCKOUT_CAUSES, PINNED_SIGNERS, evaluate

ROOT = Path(__file__).resolve().parents[1]
STAGE = "idm-lab/srv1"                      # relative to the admin user's home on srv1, mode 0700


def valid_user(name):
    return bool(_re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name or ""))


def stage(ctx):
    ctx.remote.push(ctx.host, f"{ROOT}/lab/srv1/", f"{STAGE}/")


@dataclass
class Ctx:
    host: str                        # admin SSH alias of the target host
    role: str                        # "server" | "client" (from the report)
    case: object                     # engine.case.Case
    collect: Callable[[], dict]      # fresh read-only report of the target host
    params: dict = field(default_factory=dict)
    remote: Optional[object] = None  # engine.remote (injected; fakes in tests)
    sleep: Callable[[float], None] = time.sleep
    peer: Optional[Callable[[], dict]] = None   # the server's fresh report, for cross-host rules during verify
    verify_tries: int = 6            # a restarted service may need a few seconds before a fresh report shows it
    approver: str = ""                # who typed yes (set by run_repair)


def target_role(report, host):
    """The role a repair may assume on HOST, taken from HOST's own report. A report from another host is refused."""
    if report.get("host") != host:
        raise ValueError(f"report is from {report.get('host')!r}, not {host!r}")
    return report["role"]


class Repair:
    id = ""
    host_role = ""
    verify_absent: set = set()       # findings that must be ABSENT in a fresh report after apply

    def verify_present(self, report):  # -> None if the fresh report POSITIVELY shows the fix, else a reason
        return None

    def describe(self, ctx):
        return self.id

    def precheck(self, ctx):         # -> None if OK, else a reason string
        return None

    def backup(self, ctx):
        return {}

    def apply(self, ctx):
        raise NotImplementedError

    def undo(self, ctx, backup):
        pass

    def wait_for_user(self, ctx):    # guided repairs: the human completes a step (e.g. uses a reset token)
        pass


def _prompt(repair_id, r, ctx):
    """The decision form when the repair's runbook is in the approved shape; else the one-line prompt."""
    from engine import form, runbooks
    rb = runbooks.for_repair(repair_id, r.verify_absent)
    if rb is None or not rb.complete:
        return f"Repair {repair_id} on {ctx.host}: {r.describe(ctx)}. Type yes to approve"
    try:
        found = evaluate(ctx.collect())
    except Exception as e:                       # the form still stands on the runbook; say why evidence is missing
        ctx.case.log(f"form: could not re-read the host for evidence ({type(e).__name__})")
        found = []
    return form.render(ctx.host, rb, found, repair_id)


def run_repair(repair_id, ctx, approve, registry):
    case = ctx.case
    r = registry.get(repair_id)
    if r is None:
        case.log(f"REFUSED: {repair_id!r} is not on the allow-list"); case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    if r.host_role != ctx.role:
        case.log(f"REFUSED: {repair_id} runs on {r.host_role} hosts, {ctx.host} is {ctx.role}")
        case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    with case.step(f"{repair_id}:precheck"):
        why = r.precheck(ctx)
    if why:
        case.log(f"PRECHECK FAILED: {why}"); case.write("status.txt", "PRECHECK-FAILED\n")
        return "PRECHECK-FAILED"
    prompt = _prompt(repair_id, r, ctx)
    with case.step(f"{repair_id}:approval"):
        ok = bool(approve(prompt))
    ctx.approver = getattr(approve, "who", "unknown")
    case.write(f"approval-{repair_id}.json", {
        "repair": repair_id, "host": ctx.host, "prompt": prompt, "approved": ok,
        "by": getattr(approve, "who", "unknown"), "test_mode": bool(getattr(approve, "test_mode", False)),
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    if not ok:
        case.log("REFUSED: not approved"); case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    try:
        with case.step(f"{repair_id}:backup"):
            saved = r.backup(ctx)
    except Exception as e:          # nothing has been applied: stop, and say so (class only; text may hold output)
        case.log(f"BACKUP FAILED for {repair_id}: {type(e).__name__}; nothing applied")
        case.write("status.txt", "BACKUP-FAILED\n")
        return "BACKUP-FAILED"
    case.log(f"backup: {sorted(saved)}")
    try:
        with case.step(f"{repair_id}:apply"):
            r.apply(ctx)
        case.log("applied")
        with case.step(f"{repair_id}:user"):
            r.wait_for_user(ctx)
        with case.step(f"{repair_id}:verify"):
            why, after = _verify(r, ctx)
        case.write(f"report-after-{repair_id}.json", after)
    except Exception as e:          # the exception text may carry command output, so only its class is recorded
        case.log(f"ERROR during {repair_id}: {type(e).__name__}")
        return _undo(r, ctx, saved, repair_id, "ERROR-UNDONE")
    if why:
        case.log(f"VERIFY FAILED ({why})")
        return _undo(r, ctx, saved, repair_id, "FAILED-UNDONE")
    case.log("verified"); case.write("status.txt", "OK\n")
    return "OK"


def _verify(r, ctx):
    """Fresh reports only: the fault's findings must be gone, the fix must be positively visible, and the collector
    must have reported no errors (a missing section is not evidence of health). Retries while services restart."""
    why, after = None, {}
    for n in range(ctx.verify_tries):
        if n:
            ctx.sleep(5)
        after = ctx.collect()
        still = sorted({f.id for f in evaluate(after, ctx.peer() if ctx.peer else None)} & set(r.verify_absent))
        why = (f"still present: {still}" if still else r.verify_present(after)
               or (f"collector errors: {after['errors']}" if after.get("errors") else None))
        if not why:
            break
    return why, after


def _undo(r, ctx, saved, repair_id, status):
    case = ctx.case
    try:
        with case.step(f"{repair_id}:undo"):
            r.undo(ctx, saved)
        case.log("undone")
    except Exception as e:
        case.log(f"UNDO FAILED: {type(e).__name__}; restore by hand from the backup {sorted(saved)}")
        status = status.replace("UNDONE", "UNDO-FAILED")
    case.write("status.txt", status + "\n")
    return status


# --- allow-listed repairs -----------------------------------------------------------------------------------------
CERT_DIR = "/etc/pki/kanidm"
TIMER = "cert-renew-kanidm.timer"


def _sh(ctx, script):
    """Run a fixed root script on the target host (script text is a constant in this module, never model output)."""
    return ctx.remote.run(ctx.host, ["sudo", "bash", "-c", script]).stdout


class KanidmCertRenew(Repair):
    id = "kanidm-cert-renew"
    host_role = "server"
    verify_absent = {"TLS_CERT_EXPIRED(kanidm)"}

    def verify_present(self, report):
        v = ((report.get("tls") or {}).get("kanidm") or {}).get("verify")
        return None if v == "ok" else f"Kanidm certificate verify is {v!r}, not 'ok'"

    def describe(self, ctx):
        return ("back up the Kanidm TLS chain/key, issue a fresh certificate over ACME (step-ca refuses to renew an "
                "expired one), restart kanidmd")

    def precheck(self, ctx):
        out = _sh(ctx, "STEPPATH=/root/.step step-cli ca health 2>&1 || true")
        return None if out.strip().endswith("ok") else f"step-ca not healthy: {out.strip()[:120]}"

    def backup(self, ctx):
        d = f"/root/idm-backup/{ctx.case.dir.name}"
        _sh(ctx, f"install -d -m 0700 {d} && cp -p {CERT_DIR}/chain.pem {CERT_DIR}/key.pem {d}/")
        return {"dir": d}

    def apply(self, ctx):
        _sh(ctx, "set -e; export STEPPATH=/root/.step; firewall-cmd -q --add-service=http; "
                 "trap 'firewall-cmd -q --remove-service=http' EXIT; "
                 f"step-cli ca certificate idm.kanidm.lab.test {CERT_DIR}/chain.pem {CERT_DIR}/key.pem "
                 "--provisioner acme --kty EC --crv P-384 --force >/dev/null 2>&1; "
                 f"chmod 600 {CERT_DIR}/*.pem; systemctl try-restart kanidmd")

    def undo(self, ctx, backup):
        _sh(ctx, f"cp -p {backup['dir']}/chain.pem {backup['dir']}/key.pem {CERT_DIR}/ && systemctl try-restart kanidmd")


class AcmeTimerRestore(Repair):
    id = "acme-timer-restore"
    host_role = "server"
    verify_absent = {"ACME_RENEWAL_STOPPED"}

    def verify_present(self, report):
        st = (report.get("services") or {}).get(TIMER)
        return None if st == "active" else f"{TIMER} is {st!r}"

    def describe(self, ctx):
        return f"re-enable and start {TIMER} (checks the Kanidm certificate every 15 minutes)"

    def backup(self, ctx):
        en = _sh(ctx, f"systemctl is-enabled {TIMER} 2>/dev/null || true").strip()
        ac = _sh(ctx, f"systemctl is-active {TIMER} 2>/dev/null || true").strip()
        return {"enabled": en, "active": ac}

    def apply(self, ctx):
        _sh(ctx, f"systemctl enable --now {TIMER}")

    def undo(self, ctx, backup):
        if backup.get("active") != "active":
            _sh(ctx, f"systemctl stop {TIMER}")
        if backup.get("enabled") != "enabled":
            _sh(ctx, f"systemctl disable {TIMER}")


REGISTRY = {r.id: r for r in (KanidmCertRenew(), AcmeTimerRestore())}


# --- guided: credential reset token (the tool never sets a password) ------------------------------------------------
from engine import labsecrets


def admin_login(ctx):
    pw = labsecrets.read_json("idm_admin.json")["password"]
    ctx.remote.run(ctx.host, ["expect", f"{STAGE}/kanidm-login.exp", "idm_admin"], stdin=pw + "\n")


class KanidmCredResetToken(Repair):
    id = "kanidm-cred-reset-token"
    host_role = "server"
    verify_absent = {"POSIX_PW_MISSING"}

    def verify_present(self, report):
        u = report.get("kanidm_user") or {}
        return None if u.get("exists") and u.get("unix_password") is True else "no unix (POSIX) password in the report"

    def describe(self, ctx):
        return (f"issue a credential-reset token (1 h) for {ctx.params['user']}; the USER sets their own POSIX password "
                "with it. No password is set by this tool")

    def precheck(self, ctx):
        if not valid_user(ctx.params.get("user")):
            return f"refusing: {ctx.params.get('user')!r} is not a valid user name"
        if "POSIX_PW_MISSING" not in {f.id for f in evaluate(ctx.collect())}:
            return f"{ctx.params['user']} does not lack a POSIX password; nothing to repair"
        return None

    def apply(self, ctx):
        u = ctx.params["user"]
        if not valid_user(u):
            raise ValueError("invalid user name")
        stage(ctx)
        admin_login(ctx)
        out = ctx.remote.run(ctx.host, ["kanidm", "person", "credential", "create-reset-token", u, "--ttl", "3600",
                                      "-D", "idm_admin"]).stdout
        m = _re.search(r"use-reset-token ([a-z0-9-]+)", out)
        if not m:
            raise RuntimeError("no reset token in the CLI output")
        p = labsecrets.write(f"{u}.reset-token", m.group(1) + "\n")
        ctx.case.log(f"reset token issued for {u}; stored in {p.name} (value not recorded). Tell the user: run "
                     "`kanidm person credential use-reset-token <token>`, choose unix-password, then commit.")

    def wait_for_user(self, ctx):
        u = ctx.params["user"]
        if not ctx.params.get("lab_standin"):
            input(f"Press Enter when {u} has used the reset token: ")
            return
        # LAB STAND-IN for the user: complete the reset with a new POSIX password (stored for the user in the lab).
        tok = labsecrets.path(f"{u}.reset-token").read_text().strip()
        upw = labsecrets.new_password()
        ctx.remote.run(ctx.host, ["expect", f"{STAGE}/enrol-user.exp"],
                       stdin=f"{tok}\nunused\n{upw}\nposix-only\n")
        d = labsecrets.read_json(f"{u}.json"); d["posix_password"] = upw
        labsecrets.write_json(f"{u}.json", d)
        labsecrets.path(f"{u}.reset-token").unlink()
        ctx.case.log(f"lab stand-in: {u} completed the reset (unix password set); token file removed")


REGISTRY[KanidmCredResetToken.id] = KanidmCredResetToken()


# --- client repairs ---------------------------------------------------------------------------------------------------
AUTHSELECT_PROFILE = "custom/kanidm"
AUTHSELECT_FEATURES = ("with-faillock", "without-nullok")     # the golden client's feature set (CUI profile)


class NsswitchRestore(Repair):
    id = "nsswitch-restore"
    host_role = "client"
    verify_absent = {"NSS_ORDER_WRONG"}

    def describe(self, ctx):
        return (f"re-select authselect profile {AUTHSELECT_PROFILE} with {', '.join(AUTHSELECT_FEATURES)} (--force); "
                "the current files are saved first and restored if verification fails")

    def precheck(self, ctx):
        feats = _sh(ctx, f"authselect list-features {AUTHSELECT_PROFILE} 2>/dev/null || true").split()
        missing = [f for f in AUTHSELECT_FEATURES if f not in feats]
        if missing:
            return f"profile {AUTHSELECT_PROFILE} lacks {missing}"
        # Only restore the pinned state onto a host that is SUPPOSED to be in it: a host with its own profile or extra
        # features is not a hand-edit victim, and --force would silently drop its settings.
        cur = _sh(ctx, "authselect current 2>/dev/null || true")
        prof = next((ln.split(":", 1)[1].strip() for ln in cur.splitlines() if ln.startswith("Profile ID:")), None)
        have = sorted(ln[2:].strip() for ln in cur.splitlines() if ln.startswith("- "))
        if prof != AUTHSELECT_PROFILE or have != sorted(AUTHSELECT_FEATURES):
            return (f"current authselect state ({prof}, {have}) does not match the pinned {AUTHSELECT_PROFILE} "
                    f"{sorted(AUTHSELECT_FEATURES)}: not restoring over a host's own configuration")
        return None

    def backup(self, ctx):
        d = f"/root/idm-backup/{ctx.case.dir.name}"
        _sh(ctx, f"install -d -m 0700 {d} && tar -C /etc -cpf {d}/authselect.tar authselect nsswitch.conf pam.d")
        return {"dir": d}

    def apply(self, ctx):
        name = "idm-" + _re.sub(r"[^A-Za-z0-9-]", "-", ctx.case.dir.name)[-40:]
        _sh(ctx, f"authselect select {AUTHSELECT_PROFILE} {' '.join(AUTHSELECT_FEATURES)} --force --backup={name}")

    def undo(self, ctx, backup):
        _sh(ctx, f"tar -C /etc -xpf {backup['dir']}/authselect.tar")

    def verify_present(self, report):
        nss, a = report.get("nss") or {}, report.get("authselect") or {}
        if any((nss.get(m) or "").split()[:1] != ["kanidm"] for m in ("passwd", "group", "initgroups")):
            return f"nss still wrong: {nss}"
        if not a.get("valid") or a.get("profile") != AUTHSELECT_PROFILE:
            return f"authselect not clean: {a}"
        return None


REGISTRY[NsswitchRestore.id] = NsswitchRestore()


class UnixdRefresh(Repair):
    id = "unixd-refresh"
    host_role = "client"
    verify_absent = {"UNIXD_CACHE_STALE", "UNIXD_OFFLINE"}

    def describe(self, ctx):
        return ("invalidate the kanidm-unixd cache (content kept, marked stale) and re-fetch the user, so server-side "
                "changes are visible now instead of at cache expiry")

    def precheck(self, ctx):
        if ctx.params.get("user") and not valid_user(ctx.params["user"]):
            return f"refusing: {ctx.params['user']!r} is not a valid user name"
        if {f.id for f in evaluate(ctx.collect())} & {"KANIDM_UNREACHABLE", "DNS_LOOKUP_FAILED", "DNS_WRONG_ADDRESS"}:
            # the DNS findings suppress KANIDM_UNREACHABLE, so they must block the refresh too
            return "Kanidm is unreachable from this host: refreshing the cache cannot help; fix the network first"
        return None

    def apply(self, ctx):
        _sh(ctx, "kanidm-unix cache-invalidate")
        if ctx.params.get("user"):
            _sh(ctx, f"id -Gn {ctx.params['user']} >/dev/null")      # user name validated in precheck

    def verify_present(self, report):
        u = report.get("user_nss")
        if report.get("user") and not (u and u.get("found")):
            return f"user lookup for {report['user']} failed after refresh: {u}"
        return None


REGISTRY[UnixdRefresh.id] = UnixdRefresh()


class FaillockReset(Repair):
    """ISSO row 44: clear a workstation lockout only with approval, and never while a cause is found."""
    id = "faillock-reset"
    host_role = "client"
    verify_absent = {"ACCOUNT_LOCKED"}
    TALLY = "/var/run/faillock"

    def describe(self, ctx):
        return (f"clear the failed-login count of {ctx.params.get('user')} on {ctx.host} (faillock --reset) and "
                "record who approved it in the host's log")

    def precheck(self, ctx):
        u = ctx.params.get("user")
        if not valid_user(u):
            return f"refusing: {u!r} is not a valid user name"
        rep = ctx.collect()
        if rep.get("user") != u:                         # the lock seen must be the lock of the user being reset
            return f"refusing: the report is for {rep.get('user')!r}, not {u!r}"
        ids = {f.id for f in evaluate(rep)}
        causes = sorted(i for i in ids if i.split("(")[0] in LOCKOUT_CAUSES)
        if causes:
            return (f"refusing: {', '.join(causes)} found on {ctx.host}; fix that first (runbook "
                    f"{causes[0].split('(')[0]}), then unlock (ISSO row 44)")
        if "ACCOUNT_LOCKED" not in ids:
            return f"{u} is not locked out on {ctx.host}; nothing to repair"
        return None

    def backup(self, ctx):
        d, u = f"/root/idm-backup/{ctx.case.dir.name}", ctx.params["user"]
        st = _sh(ctx, f"install -d -m 0700 {d}; if [ -e {self.TALLY}/{u} ]; then cp -p {self.TALLY}/{u} "
                      f"{d}/faillock-{u} && echo present; else echo absent; fi").strip()
        return {"dir": d, "tally": st}

    def apply(self, ctx):
        u = ctx.params["user"]
        if not valid_user(u):
            raise ValueError("invalid user name")
        note = f"faillock reset for {u}, approved by {ctx.approver or 'unknown'}, case {ctx.case.dir.name}"
        _sh(ctx, f"faillock --user {u} --reset && logger -p authpriv.notice -t idm-assistant {shlex.quote(note)}")

    def undo(self, ctx, backup):
        u = ctx.params["user"]
        if backup.get("tally") == "present" and valid_user(u):
            _sh(ctx, f"cp -p {backup['dir']}/faillock-{u} {self.TALLY}/{u}")


REGISTRY[FaillockReset.id] = FaillockReset()


class FapolicydTrustRefresh(Repair):
    """ISSO row 46: refresh fapolicyd's trust from the package database; never trusts an unpackaged program.
    fapolicyd-cli --update reloads the WHOLE package database and the trust files, so the precheck refuses unless
    everything it would newly trust is a package signed by a pinned key (final review C1)."""
    id = "fapolicyd-trust-refresh"
    host_role = "client"
    verify_absent = {"FAPOLICYD_TRUST_STALE"}

    def describe(self, ctx):
        return "refresh fapolicyd's trust list from the package database (fapolicyd-cli --update) and log who approved it"

    @staticmethod
    def _stale_paths(report):
        fk = report.get("fapolicyd") or {}
        return [d["path"] for d in fk.get("denials") or []
                if isinstance(d.get("path"), str) and FAP_PATH.fullmatch(d["path"]) and d.get("exists") is True
                and d.get("in_trust") is not True and d.get("package") and d.get("signer") in PINNED_SIGNERS]

    def precheck(self, ctx):
        rep = ctx.collect()
        ids = {f.id for f in evaluate(rep)}
        if "FAPOLICYD_PERMISSIVE" in ids:
            return "refusing: fapolicyd is not enforcing; a refresh proves nothing (row 46: that is the ISSO's)"
        if "FAPOLICYD_DENIED_UNPACKAGED" in ids:
            return "refusing: an unpackaged program is also being denied on this host (row 46: the ISSO decides first)"
        if "FAPOLICYD_TRUST_STALE" not in ids:
            return "nothing stale: no denied program from a signed package is waiting"
        fk = rep.get("fapolicyd") or {}
        pend = fk.get("pending")
        if not isinstance(pend, dict) or pend.get("truncated") or not isinstance(pend.get("packages"), list):
            return "refusing: cannot tell what a refresh would newly trust (row 46)"
        unvetted = sorted(str(x.get("name")) for x in pend["packages"] if x.get("signer") not in PINNED_SIGNERS)
        if unvetted:
            return (f"refusing: a refresh would also trust {', '.join(unvetted[:5])} (unsigned or not a pinned key); "
                    "the ISSO decides (row 46)")
        if fk.get("file_trust_pending") != 0:
            return "refusing: file-trust entries are waiting to be loaded; the ISSO decides (row 46)"
        return None

    def apply(self, ctx):
        paths = self._stale_paths(ctx.collect())
        note = f"fapolicyd trust refresh approved by {ctx.approver or 'unknown'}, case {ctx.case.dir.name}"
        _sh(ctx, f"fapolicyd-cli --update && logger -p authpriv.notice -t idm-assistant {shlex.quote(note)}")
        # positive proof, not an aged-out denial (final review I3): every stale path is in the trust list now
        for _ in range(10):
            trusted = {ln.split()[1] for ln in _sh(ctx, "fapolicyd-cli -D").splitlines() if len(ln.split()) > 1}
            missing = [p for p in paths if p not in trusted]
            if not missing:
                return
            time.sleep(1)
        raise RuntimeError(f"refresh ran but {missing} is still not in fapolicyd's trust list")


REGISTRY[FapolicydTrustRefresh.id] = FapolicydTrustRefresh()


class TimeResync(Repair):
    id = "time-resync"
    host_role = "client"
    verify_absent = {"TOTP_TIME_SKEW", "TIME_UNVERIFIED"}

    def describe(self, ctx):
        return ("restart the time service and step the clock to the time source (chronyc makestep). Not reversible, "
                "and not meant to be: the old time was wrong")

    def precheck(self, ctx):
        src = _sh(ctx, "systemctl is-active chronyd >/dev/null && chronyc -n sources 2>/dev/null || true")
        live = [ln for ln in src.splitlines() if ln.startswith("^") and len(ln.split()) > 4 and ln.split()[4] != "0"]
        return None if live else "no reachable time source (chronyd down or reach 0): a step would use nothing"

    def apply(self, ctx):
        # Row 18: restarting chronyd clears the restored sample history (the CUI 'makestep 1.0 3' then steps on the
        # first updates); makestep alone does nothing while the source is rejected as too variable (spike 2026-10-04).
        _sh(ctx, "systemctl restart chronyd; chronyc waitsync 30 0.5 >/dev/null 2>&1; chronyc makestep >/dev/null; "
                 "chronyc burst 4/4 >/dev/null; chronyc waitsync 6 1.0 >/dev/null 2>&1 || true")

    def verify_present(self, report):
        t = report.get("time") or {}
        if not t.get("synced") or t.get("offset_s") is None or abs(t["offset_s"]) >= 1:
            return f"clock not synced within 1 s: {t}"
        if "source_state" in t:          # a stale 'synchronized' is what made the old check pass after a restore
            src = t.get("source_offset_s")
            if t.get("source_state") != "*" or src is None or abs(src) >= 1:
                return f"time source not in use or still off: state {t.get('source_state')!r}, sample {src} s"
        return None


REGISTRY[TimeResync.id] = TimeResync()


PINNED_ROOT = (ROOT / "lab" / "trust" / "kanidm-lab-root.sha256").read_text().strip()


def first_cert(pem):
    """The first BEGIN..END CERTIFICATE block, exactly (raises ValueError if there is none)."""
    lines = pem.splitlines()
    i = lines.index("-----BEGIN CERTIFICATE-----")
    j = lines.index("-----END CERTIFICATE-----", i)
    return "\n".join(lines[i:j + 1]) + "\n"


def fingerprint(pem):
    """Colon-separated upper-case SHA-256 of the first certificate's DER (what `openssl x509 -fingerprint` prints)."""
    lines = pem.splitlines()
    i = lines.index("-----BEGIN CERTIFICATE-----")
    j = lines.index("-----END CERTIFICATE-----", i)
    h = _hashlib.sha256(_b64.b64decode("".join(lines[i + 1:j]), validate=True)).hexdigest().upper()
    return ":".join(h[k:k + 2] for k in range(0, len(h), 2))


class ClientCaTrust(Repair):
    id = "client-ca-trust"
    host_role = "client"
    verify_absent = {"CLIENT_MISSING_CA_ROOT", "TLS_CERT_UNTRUSTED(kanidm)"}
    CA_HOST = "srv1"                                   # where the step-ca root lives (NOT the target host)
    ROOT_PATH = "/root/.step/certs/root_ca.crt"
    ANCHOR = "/etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt"

    def describe(self, ctx):
        return (f"install the step-ca root (SHA-256 {PINNED_ROOT[:23]}..., pinned) as {self.ANCHOR}, update the trust "
                "store, restart kanidm-unixd")

    def _root(self, ctx):
        out = ctx.remote.run(self.CA_HOST, ["sudo", "cat", self.ROOT_PATH]).stdout
        try:
            pem = first_cert(out)          # only the verified block is ever installed, never the rest of the file
            fp = fingerprint(pem)
        except (ValueError, _binascii.Error):
            return None, "the CA host returned no readable certificate"
        return (pem, None) if fp == PINNED_ROOT else (None, f"root fingerprint {fp} does not match the pinned value")

    def precheck(self, ctx):
        return self._root(ctx)[1]

    def backup(self, ctx):
        d = f"/root/idm-backup/{ctx.case.dir.name}"
        st = _sh(ctx, f"install -d -m 0700 {d}; if [ -e {self.ANCHOR} ]; then cp -p {self.ANCHOR} {d}/; "
                      "echo present; else echo absent; fi").strip()
        return {"dir": d, "anchor": st}

    def apply(self, ctx):
        pem, why = self._root(ctx)
        if why:
            raise RuntimeError(why)
        ctx.remote.run(ctx.host, ["sudo", "sh", "-c",
                                  f"umask 022; cat > {self.ANCHOR}.new && install -m 0644 {self.ANCHOR}.new {self.ANCHOR} && "
                                  f"rm -f {self.ANCHOR}.new && restorecon {self.ANCHOR} && update-ca-trust extract && "
                                  "systemctl restart kanidm-unixd"], stdin=pem)

    def undo(self, ctx, backup):
        if backup.get("anchor") == "present":
            _sh(ctx, f"cp -p {backup['dir']}/kanidm-lab-root.crt {self.ANCHOR}")
        else:
            _sh(ctx, f"rm -f {self.ANCHOR}")
        _sh(ctx, "update-ca-trust extract && systemctl restart kanidm-unixd")

    def verify_present(self, report):
        if not (report.get("trust") or {}).get("kanidm_root_in_store"):
            return "root not in the trust store"
        v = ((report.get("tls") or {}).get("kanidm") or {}).get("verify")
        return None if v == "ok" else f"Kanidm certificate verify is {v!r}"


REGISTRY[ClientCaTrust.id] = ClientCaTrust()


class SelinuxRestorecon(Repair):
    """Put back policy-defined SELinux labels, only on the fixed identity paths the collector checks (never a path from
    anywhere else). The previous labels are recorded so undo can put them back with chcon."""
    id = "selinux-restorecon"
    host_role = "client"
    PATHS = ("/run/kanidm-unixd", "/var/cache/kanidm-unixd", "/var/lib/kanidm-unixd", "/etc/kanidm",
             "/etc/ssh/trusted_user_ca_keys", "/etc/pki/ca-trust/source/anchors")

    def describe(self, ctx):
        return "restore the SELinux labels the policy defines (restorecon) on the identity paths that differ"

    def _targets(self, report):
        return [x.get("path") for x in (report.get("selinux") or {}).get("relabel") or []]

    def _allowed(self, p):
        return (isinstance(p, str) and _re.fullmatch(r"/[A-Za-z0-9_./-]+", p) and "/../" not in p + "/"
                and any(p == a or p.startswith(a + "/") for a in self.PATHS))

    def precheck(self, ctx):
        t = self._targets(ctx.collect())
        if not t:
            return "no identity path has a wrong label; nothing to repair"
        bad = [p for p in t if not self._allowed(p)]
        return f"refusing: {bad} outside the identity path list" if bad else None

    def backup(self, ctx):
        t = [p for p in self._targets(ctx.collect()) if self._allowed(p)]
        out = _sh(ctx, "ls -dZ -- " + " ".join(t))
        labels = dict(reversed(ln.split(None, 1)) for ln in out.splitlines() if ln.strip())
        return {"labels": {p: c for p, c in labels.items() if p in t}}

    def apply(self, ctx):
        t = [p for p in self._targets(ctx.collect()) if self._allowed(p)]
        if t:
            _sh(ctx, "restorecon -v -- " + " ".join(t))

    def undo(self, ctx, backup):
        for p, c in backup.get("labels", {}).items():
            if self._allowed(p) and _re.fullmatch(r"[a-z_]+:[a-z_]+:[a-z0-9_]+:s0(:c[0-9.,]+)?", c):
                _sh(ctx, f"chcon {c} -- {p}")

    def verify_present(self, report):
        t = self._targets(report)
        return None if not t else f"labels still differ: {t}"

    # verify_absent is dynamic (one finding per path); the positive check above covers every path


REGISTRY[SelinuxRestorecon.id] = SelinuxRestorecon()


SSH_REALM = "idm.kanidm.lab.test"


def sign_user_cert(remote, host, user, validity):
    """Sign the user's REGISTERED public key (/var/lib/ssh-ca/keys/<user>.pub) on the CA host, record the certificate
    (public) as the newest issued one, and return it. No key material is sent from here."""
    if not valid_user(user) or not _re.fullmatch(r"[-+0-9a-zA-Z:]+", validity):
        raise ValueError("invalid user name or validity")
    script = (f"set -e; T=$(mktemp -d); trap 'rm -rf \"$T\"' EXIT; cp /var/lib/ssh-ca/keys/{user}.pub \"$T/k.pub\"; "
              f"ssh-keygen -q -s /etc/ssh-ca/user_ca -I {user}-cert -n {user},{user}@{SSH_REALM} -V {validity} "
              f"\"$T/k.pub\"; install -m 0644 \"$T/k-cert.pub\" /var/lib/ssh-ca/issued/{user}-cert.pub; "
              f"cat \"$T/k-cert.pub\"")
    return remote.run(host, ["sudo", "sh", "-c", script]).stdout


class SshUserCertReissue(Repair):
    id = "ssh-user-cert-reissue"
    host_role = "server"
    verify_absent = {"SSH_USER_CERT_EXPIRED"}
    VALIDITY = "+1h"

    def describe(self, ctx):
        return (f"sign {ctx.params.get('user')}'s registered public key again (principals user and user@realm, "
                f"valid {self.VALIDITY}) and hand the new certificate to the user; no private key moves")

    def precheck(self, ctx):
        u = ctx.params.get("user")
        if not valid_user(u):
            return f"refusing: {u!r} is not a valid user name"
        if _sh(ctx, f"test -r /var/lib/ssh-ca/keys/{u}.pub && echo yes || true").strip() != "yes":
            return f"{u} has no registered public key on the CA; register it first (never sign a key from a report)"
        return None

    def backup(self, ctx):
        u = ctx.params["user"]
        return {"record": _sh(ctx, f"cat /var/lib/ssh-ca/issued/{u}-cert.pub 2>/dev/null || true")}

    def apply(self, ctx):
        ctx.params["_cert"] = sign_user_cert(ctx.remote, ctx.host, ctx.params["user"], self.VALIDITY)

    def wait_for_user(self, ctx):
        u = ctx.params["user"]
        if not ctx.params.get("lab_standin"):
            input(f"Give {u} the new certificate (public; in the case log dir as needed), press Enter when done: ")
            return
        labsecrets.write(f"{u}_ecdsa-cert.pub", ctx.params["_cert"])     # LAB STAND-IN: the user's machine
        ctx.case.log(f"lab stand-in: new certificate delivered to {u} (public)")

    def undo(self, ctx, backup):
        # The newly issued certificate is public and short-lived; undo restores the CA's record of the previous one.
        if backup.get("record"):
            ctx.remote.run(ctx.host, ["sudo", "sh", "-c",
                                      f"cat > /var/lib/ssh-ca/issued/{ctx.params['user']}-cert.pub"],
                           stdin=backup["record"])

    def verify_present(self, report):
        iss = (report.get("ssh_ca") or {}).get("issued") or {}
        vt = iss.get("valid_to")
        if vt == "forever" or (vt and datetime.fromisoformat(vt.replace("Z", "+00:00"))
                               > datetime.fromisoformat(report["collected_at"].replace("Z", "+00:00"))):
            return None
        return f"no currently valid certificate recorded: {iss}"


REGISTRY[SshUserCertReissue.id] = SshUserCertReissue()


PINNED_SSH_CA = (ROOT / "lab" / "trust" / "ssh-user-ca.sha256").read_text().strip()


def ssh_fingerprint(publine):
    """OpenSSH SHA256 fingerprint of a public-key line (what `ssh-keygen -lf` prints)."""
    blob = _b64.b64decode(publine.split()[1], validate=True)
    return "SHA256:" + _b64.b64encode(_hashlib.sha256(blob).digest()).decode().rstrip("=")


class SshCaTrustRestore(Repair):
    id = "ssh-ca-trust-restore"
    host_role = "client"
    verify_absent = {"SSH_CA_NOT_TRUSTED"}
    CA_HOST = "srv1"                                    # where the SSH user CA lives (NOT the target host)
    CA_PUB = "/etc/ssh-ca/user_ca.pub"
    DROPIN = "/etc/ssh/sshd_config.d/10-kanidm.conf"
    KEYS = "/etc/ssh/trusted_user_ca_keys"

    def describe(self, ctx):
        return (f"trust the lab SSH user CA again ({PINNED_SSH_CA[:19]}..., pinned): write {self.KEYS}, restore "
                f"TrustedUserCAKeys in {self.DROPIN}, check sshd -t, reload sshd")

    def _ca(self, ctx):
        line = ctx.remote.run(self.CA_HOST, ["sudo", "cat", self.CA_PUB]).stdout.strip().splitlines()
        try:
            fp = ssh_fingerprint(line[-1])
        except (IndexError, ValueError, _binascii.Error):
            return None, "the CA host returned no readable public key"
        return (line[-1] + "\n", None) if fp == PINNED_SSH_CA else (None, f"CA fingerprint {fp} does not match the pin")

    def precheck(self, ctx):
        return self._ca(ctx)[1]

    def backup(self, ctx):
        # Either file may be missing (that is one way SSH_CA_NOT_TRUSTED happens): record which ones existed.
        d = f"/root/idm-backup/{ctx.case.dir.name}"
        out = _sh(ctx, f"install -d -m 0700 {d}; for f in {self.DROPIN} {self.KEYS}; do "
                       f"[ -e \"$f\" ] && cp -p \"$f\" {d}/ && echo \"$f\"; done; true")
        return {"dir": d, "existed": [ln.strip() for ln in out.splitlines() if ln.strip() in (self.DROPIN, self.KEYS)]}

    def apply(self, ctx):
        key, why = self._ca(ctx)
        if why:
            raise RuntimeError(why)
        ctx.remote.run(ctx.host, ["sudo", "sh", "-c",
                                  f"set -e; cat > {self.KEYS}.new; install -m 0644 {self.KEYS}.new {self.KEYS}; "
                                  f"rm -f {self.KEYS}.new; restorecon {self.KEYS}; "
                                  f"grep -q '^TrustedUserCAKeys ' {self.DROPIN} || "
                                  f"echo 'TrustedUserCAKeys {self.KEYS}' >> {self.DROPIN}; "
                                  "sshd -t; systemctl reload sshd"], stdin=key)

    def undo(self, ctx, backup):
        d, existed = backup["dir"], backup.get("existed", [self.DROPIN, self.KEYS])
        steps = [f"cp -p {d}/{f.rsplit('/', 1)[1]} {f}" if f in existed else f"rm -f {f}"
                 for f in (self.DROPIN, self.KEYS)]
        _sh(ctx, " && ".join(steps) + " && sshd -t && systemctl reload sshd")

    def verify_present(self, report):
        d = report.get("sshd") or {}
        return None if PINNED_SSH_CA in (d.get("trusted_ca_fingerprints") or []) else f"pinned CA not trusted: {d}"


REGISTRY[SshCaTrustRestore.id] = SshCaTrustRestore()
