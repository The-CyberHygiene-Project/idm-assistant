"""Allow-listed repairs: precheck -> approval -> backup -> apply -> verify (fresh report) -> undo if still faulty.
Nothing is applied without approval. A repair only runs on a host of its declared role."""
import base64 as _b64
import binascii as _binascii
import hashlib as _hashlib
import re as _re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from engine.findings import evaluate

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
    prompt = f"Repair {repair_id} on {ctx.host}: {r.describe(ctx)}. Type yes to approve"
    with case.step(f"{repair_id}:approval"):
        ok = bool(approve(prompt))
    case.write(f"approval-{repair_id}.json", {
        "repair": repair_id, "host": ctx.host, "prompt": prompt, "approved": ok,
        "by": getattr(approve, "who", "unknown"), "test_mode": bool(getattr(approve, "test_mode", False)),
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    if not ok:
        case.log("REFUSED: not approved"); case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    with case.step(f"{repair_id}:backup"):
        saved = r.backup(ctx)
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
        return f"profile {AUTHSELECT_PROFILE} lacks {missing}" if missing else None

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
        if "KANIDM_UNREACHABLE" in {f.id for f in evaluate(ctx.collect())}:
            return "Kanidm is unreachable from this host: refreshing the cache cannot help; fix the network first"
        return None

    def apply(self, ctx):
        _sh(ctx, "kanidm-unix cache-invalidate")
        if ctx.params.get("user"):
            _sh(ctx, f"id -Gn {ctx.params['user']} >/dev/null")      # user name validated in precheck

    def verify_present(self, report):
        u = report.get("user_nss")
        return None if u is None or u.get("found") else f"user lookup failed after refresh: {u}"


REGISTRY[UnixdRefresh.id] = UnixdRefresh()


class TimeResync(Repair):
    id = "time-resync"
    host_role = "client"
    verify_absent = {"TOTP_TIME_SKEW", "TIME_UNVERIFIED"}

    def describe(self, ctx):
        return ("step the clock to the lab time source now (chronyc makestep). Not reversible, and not meant to be: "
                "the old time was wrong")

    def precheck(self, ctx):
        src = _sh(ctx, "systemctl is-active chronyd >/dev/null && chronyc -n sources 2>/dev/null || true")
        live = [ln for ln in src.splitlines() if ln.startswith("^") and len(ln.split()) > 4 and ln.split()[4] != "0"]
        return None if live else "no reachable time source (chronyd down or reach 0): a step would use nothing"

    def apply(self, ctx):
        # burst = fresh samples at once, so the evidence is not a pre-step sample; waitsync bounded to ~60 s
        _sh(ctx, "chronyc makestep >/dev/null && chronyc burst 4/4 >/dev/null; chronyc waitsync 6 1.0 >/dev/null 2>&1 || true")

    def verify_present(self, report):
        t = report.get("time") or {}
        if not t.get("synced") or t.get("offset_s") is None or abs(t["offset_s"]) >= 1:
            return f"clock not synced within 1 s: {t}"
        return None


REGISTRY[TimeResync.id] = TimeResync()


PINNED_ROOT = (ROOT / "lab" / "trust" / "kanidm-lab-root.sha256").read_text().strip()


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
        pem = ctx.remote.run(self.CA_HOST, ["sudo", "cat", self.ROOT_PATH]).stdout
        try:
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
