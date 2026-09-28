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
    t = r.get("time") or {}
    return any(v is not None and abs(v) > SKEW_S for v in (t.get("offset_s"), t.get("source_offset_s")))


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
        t = r["time"]
        return Finding("TOTP_TIME_SKEW", "time", (f"offset {t.get('offset_s')} s, last source sample "
                                                   f"{t.get('source_offset_s')} s vs {t.get('source')}",
                                                   f"threshold {SKEW_S} s"))


def tls_expired(r):
    k = (r.get("tls") or {}).get("kanidm")
    if not k or _skewed(r) or _clock_unknown(r):   # a wrong or unknown clock makes any expiry verdict unreliable
        return None
    if k.get("verify") == "expired" or ("not_after" in k and _t(k["not_after"]) <= _t(r["collected_at"])):
        return Finding("TLS_CERT_EXPIRED(kanidm)", "tls", (f"notAfter {k.get('not_after')}",
                                                           f"collected {r['collected_at']}", f"verify {k.get('verify')}"))


def tls_untrusted(r):
    k = (r.get("tls") or {}).get("kanidm")
    if k and k.get("verify") == "untrusted" and not _skewed(r) and not _clock_unknown(r):
        return Finding("TLS_CERT_UNTRUSTED(kanidm)", "tls", ("verify: chain does not reach a root this host trusts",))


def kanidm_unreachable(r):
    if (r.get("tls") or {}).get("kanidm") is None and any(
            e.startswith("tls: could not fetch") for e in r.get("errors") or []):
        return Finding("KANIDM_UNREACHABLE", "network", ("TLS handshake with idm.kanidm.lab.test failed from this host",))


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


def nss_order_wrong(r):
    nss = r.get("nss")
    if r.get("role") != "client" or not nss:
        return None
    bad = [f"{m}: {nss.get(m)!r}" for m in ("passwd", "group", "initgroups")
           if (nss.get(m) or "").split()[:1] != ["kanidm"]]
    if bad:
        ok = (r.get("authselect") or {}).get("valid")
        return Finding("NSS_ORDER_WRONG", "nss", tuple(bad) + (
            f"authselect check: {'valid' if ok else 'MODIFIED outside authselect'}",))


def cache_stale(server, client):
    """Cross-host: groups the client still grants from cache that the server no longer lists (revocation lag).
    Only Kanidm groups (name@realm) count; the user's private group (the user's own SPN) is skipped."""
    su, cu = server.get("kanidm_user") or {}, client.get("user_nss") or {}
    if not (su.get("exists") and cu.get("found") and "memberof" in su):
        return None
    have = set(su["memberof"])
    extra = sorted(g for g in cu.get("groups", []) if "@" in g and g.split("@")[0] != su["name"] and g not in have)
    if extra:
        return Finding("UNIXD_CACHE_STALE", "unixd", (f"{cu['name']} on {client.get('host')} still has {extra}",
                                                      "the server no longer lists them (change not yet visible)"))


def services_down(r):
    out = []
    for unit, st in sorted((r.get("services") or {}).items()):
        if unit != RENEW_TIMER and st not in ("active", None):
            out.append(Finding(f"SERVICE_DOWN({unit})", "service", (f"{unit} is {st}",)))
    return out


RULES = (time_unverified, time_skew, tls_expired, tls_untrusted, kanidm_unreachable, renewal_stopped, unixd_offline,
         posix_pw_missing, ca_root_missing, nss_order_wrong)


def evaluate(report, peer=None):
    found = [f for rule in RULES if (f := rule(report))]
    found += services_down(report)
    if peer and report.get("role") == "client" and peer.get("role") == "server":
        found += [f for f in (cache_stale(peer, report),) if f]
    return sorted(found, key=lambda f: f.id)
