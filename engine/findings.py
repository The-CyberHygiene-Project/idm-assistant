"""Deterministic findings over an idm-report/1. Pure functions, no I/O. The model (Plan 6) only ever sees these."""
from dataclasses import dataclass
from datetime import datetime

SKEW_S = 30          # TOTP window: beyond this, codes and TLS validity checks on this host are unreliable
RENEW_TIMER = "cert-renew-kanidm.timer"


@dataclass(frozen=True)
class Finding:
    id: str
    component: str
    evidence: tuple
    severity: str = "error"


def _t(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _skewed(r):
    off = (r.get("time") or {}).get("offset_s")
    return off is not None and abs(off) > SKEW_S


def _clock_unknown(r):
    t = r.get("time") or {}
    return t.get("offset_s") is None or t.get("synced") is False


def time_unverified(r):
    if _clock_unknown(r):
        t = r.get("time") or {}
        return Finding("TIME_UNVERIFIED", "time", (f"offset {t.get('offset_s')} s, synced {t.get('synced')}",
                                                    "clock not confirmed by NTP; certificate-expiry verdicts suppressed"),
                       "warning")


def time_skew(r):
    if _skewed(r):
        return Finding("TOTP_TIME_SKEW", "time", (f"offset {r['time']['offset_s']} s vs {r['time'].get('source')}",
                                                   f"threshold {SKEW_S} s"))


def tls_expired(r):
    k = (r.get("tls") or {}).get("kanidm")
    if not k or _skewed(r) or _clock_unknown(r):   # a wrong or unknown clock makes any expiry verdict unreliable
        return None
    if k.get("verify") == "expired" or ("not_after" in k and _t(k["not_after"]) <= _t(r["collected_at"])):
        return Finding("TLS_CERT_EXPIRED(kanidm)", "tls", (f"notAfter {k.get('not_after')}",
                                                           f"collected {r['collected_at']}", f"verify {k.get('verify')}"))


def renewal_stopped(r):
    st = (r.get("services") or {}).get(RENEW_TIMER)
    if r.get("role") == "server" and st is not None and st != "active":
        return Finding("ACME_RENEWAL_STOPPED", "tls", (f"{RENEW_TIMER} is {st}",))


def unixd_offline(r):
    st = (r.get("unixd") or {}).get("status")
    if r.get("role") == "client" and st == "offline":
        return Finding("UNIXD_OFFLINE", "unixd", ("kanidm-unix status: Kanidm offline",))


def posix_pw_missing(r):
    u = r.get("kanidm_user")
    if u and u.get("exists") and u.get("posix") and u.get("primary_credential") and u.get("unix_password") is False:
        return Finding("POSIX_PW_MISSING", "kanidm", (f"user {u['name']}: POSIX account, primary credential set, "
                                                      "no unix (POSIX) password",))


def ca_root_missing(r):
    if (r.get("trust") or {}).get("kanidm_root_in_store") is False:
        return Finding("CLIENT_MISSING_CA_ROOT", "trust", ("lab step-ca root not in the system trust store",))


def services_down(r):
    out = []
    for unit, st in sorted((r.get("services") or {}).items()):
        if unit != RENEW_TIMER and st not in ("active", None):
            out.append(Finding(f"SERVICE_DOWN({unit})", "service", (f"{unit} is {st}",)))
    return out


RULES = (time_unverified, time_skew, tls_expired, renewal_stopped, unixd_offline, posix_pw_missing, ca_root_missing)


def evaluate(report, peer=None):
    found = [f for rule in RULES if (f := rule(report))]
    found += services_down(report)
    return sorted(found, key=lambda f: f.id)
