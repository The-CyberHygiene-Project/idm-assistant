"""Deterministic findings over an idm-report/1. Pure functions, no I/O. The model (Plan 6) only ever sees these."""
import re
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
    """chrony's tracking offset is authoritative once synchronised. The last source sample only counts while chrony
    is NOT synchronised (right after a jump, tracking says 0.0 for ~2 min); once synced it can be a stale pre-step
    sample for a whole poll interval (measured 2026-09-28)."""
    t = r.get("time") or {}
    off, src = t.get("offset_s"), t.get("source_offset_s")
    if off is not None and abs(off) > SKEW_S:
        return True
    return t.get("synced") is False and src is not None and abs(src) > SKEW_S


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


def _conf_errors(r):
    return [e for e in r.get("errors") or [] if e.startswith("collect.conf:")]


def collect_conf_invalid(r):
    errs = _conf_errors(r)
    if errs:
        return Finding("COLLECT_CONF_INVALID", "collector", tuple(errs))


_IP = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]*")


def _ips(xs):
    """Only address-shaped strings: whatever else a report holds never reaches evidence or the model."""
    return [x for x in xs or [] if isinstance(x, str) and _IP.fullmatch(x)]


def _name(r):
    n = r.get("name")
    return n if isinstance(n, dict) else {}


def dns_lookup_failed(r):
    n = _name(r)
    if r.get("role") != "client" or not n or _ips(n.get("addresses")) or n.get("resolver_state") not in ("answers", "refused"):
        return None
    res = (_ips(n.get("resolvers")) or ["(none)"])[0]
    ev = [f"{n.get('host')} does not resolve on this host; DNS server {res}"]
    if n.get("resolver_state") == "refused":
        ev.append(f"DNS server {res} is up but no DNS service answers (connection refused)")
    return Finding("DNS_LOOKUP_FAILED", "dns", tuple(ev))


def dns_wrong_address(server, client):
    n, own = _name(client), _ips(server.get("own_addresses"))
    addrs = _ips(n.get("addresses"))
    if not own or not addrs or set(addrs) & set(own):
        return None
    src = {"files": "from the hosts file", "dns": "from DNS"}.get(n.get("source"), "source unknown")
    return Finding("DNS_WRONG_ADDRESS", "dns", (f"{n.get('host')} resolves to {', '.join(addrs)} ({src}); "
                                                f"the identity server is at {', '.join(own)}",))


def kanidm_unreachable(r):
    if _conf_errors(r):
        return None                      # no usable URL: the config is the fault, not the network
    if (r.get("tls") or {}).get("kanidm") is None and any(
            e.startswith("tls: could not fetch") for e in r.get("errors") or []):
        n = _name(r)
        addrs, res = _ips(n.get("addresses")), (_ips(n.get("resolvers")) or ["(none)"])[0]
        if addrs:
            ev = f"name resolves to {', '.join(addrs)}; the connection failed: check the route, firewall or the server"
        elif n.get("resolver_state") == "unreachable":
            ev = f"the DNS server {res} cannot be reached either: check the route or firewall"
        else:
            ev = "TLS handshake with idm.kanidm.lab.test failed from this host"
        return Finding("KANIDM_UNREACHABLE", "network", (ev,))


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
    if any(e.startswith("collect.conf: CA_ANCHOR") for e in _conf_errors(r)):
        return None                      # no configured anchor: nothing was checked
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
    if not (su.get("exists") and cu.get("found") and isinstance(su.get("memberof"), list)):
        return None                        # unknown server membership is no evidence of anything
    if su.get("name") != cu.get("name"):
        return None
    have = set(su["memberof"])
    extra = sorted(g for g in cu.get("groups", []) if "@" in g and g.split("@")[0] != su["name"] and g not in have)
    if extra:
        return Finding("UNIXD_CACHE_STALE", "unixd", (f"{cu['name']} on {client.get('host')} still has {extra}",
                                                      "the server no longer lists them (change not yet visible)"))


def _time_suspect(r):
    return _skewed(r) or _clock_unknown(r)


def account_expired(r):
    u = r.get("kanidm_user") or {}
    exp = u.get("account_expire")
    if r.get("role") == "server" and u.get("exists") and exp and not _time_suspect(r) \
            and _t(exp) <= _t(r["collected_at"]):
        return Finding("ACCOUNT_EXPIRED", "kanidm", (f"user {u['name']}: account expired at {exp}",))


def account_not_yet_valid(r):
    u = r.get("kanidm_user") or {}
    vf = u.get("valid_from")
    if r.get("role") == "server" and u.get("exists") and vf and not _time_suspect(r) \
            and _t(vf) > _t(r["collected_at"]):
        return Finding("ACCOUNT_NOT_YET_VALID", "kanidm", (f"user {u['name']}: account valid only from {vf}",))


def ssh_cert_expired(r):
    iss = (r.get("ssh_ca") or {}).get("issued")
    if r.get("role") == "server" and iss and iss.get("valid_to") not in (None, "", "forever") and not _time_suspect(r) \
            and _t(iss["valid_to"]) <= _t(r["collected_at"]):
        return Finding("SSH_USER_CERT_EXPIRED", "ssh-ca", (f"newest certificate issued to {iss.get('user')} expired "
                                                           f"{iss['valid_to']}", f"principals {iss.get('principals')}"))


def ssh_ca_not_trusted(r):
    d = r.get("sshd")
    if r.get("role") == "client" and d and (d.get("trusted_ca_path") in (None, "none")
                                            or not d.get("trusted_ca_fingerprints")):
        return Finding("SSH_CA_NOT_TRUSTED", "sshd", (f"sshd TrustedUserCAKeys: {d.get('trusted_ca_path')}",
                                                      "no SSH user CA is trusted: certificate logins fail"))


def ssh_ca_not_trusted_cross(server, client):
    fp, d = (server.get("ssh_ca") or {}).get("fingerprint"), client.get("sshd")
    if fp and d and d.get("trusted_ca_fingerprints") and fp not in d["trusted_ca_fingerprints"]:
        return Finding("SSH_CA_NOT_TRUSTED", "sshd", (f"client trusts {d['trusted_ca_fingerprints']}",
                                                      f"the lab SSH CA is {fp}"))


def labels_wrong(r):
    return [Finding(f"SELINUX_LABEL_WRONG({x.get('path')})", "selinux",
                    (f"{x.get('path')}: {x.get('have')} (policy says {x.get('want')})",))
            for x in (r.get("selinux") or {}).get("relabel") or []]


def services_down(r):
    out = []
    for unit, st in sorted((r.get("services") or {}).items()):
        if unit != RENEW_TIMER and st not in ("active", None):
            out.append(Finding(f"SERVICE_DOWN({unit})", "service", (f"{unit} is {st}",)))
    return out


LOCKOUT_CAUSES = ("TOTP_TIME_SKEW", "TIME_UNVERIFIED", "SELINUX_LABEL_WRONG")
_SOURCE_OK = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]*|[a-z0-9][a-z0-9.-]{0,252}"
                        r"|tty[A-Za-z0-9]*|pts/[0-9]+|:[0-9]+")
_KIND = {"RHOST": "remote", "TTY": "console", "SVC": "service"}


def safe_source(s):
    """Only an address, a host name or a terminal is shown: anything an outsider could have planted as text is not."""
    return s if s and _SOURCE_OK.fullmatch(s) else "unrecognized source"


def account_locked(r, found_ids):
    """pam_faillock: faillock(8) marks the failures that count (V = within fail_interval). The account is locked when
    they reach deny, until unlock_time has passed since the last one; unlock_time 0 (the CUI profile) or never means
    it stays locked until someone clears it."""
    fk = r.get("faillock")
    if not isinstance(fk, dict):
        return None
    deny, ut = fk.get("deny") or 3, fk.get("unlock_time_s")
    now = _t(r["collected_at"])
    recent = []
    for x in fk.get("failures") or []:
        if not x.get("valid") or not x.get("when"):
            continue
        try:
            recent.append((_t(x["when"]), x))
        except ValueError:
            continue
    expires = bool(ut)                                   # 0 or None: the lock does not expire by itself
    if len(recent) < deny:
        return None
    recent.sort(key=lambda p: p[0])
    if expires and (now - recent[-1][0]).total_seconds() > ut:
        return None
    mins = max(1, round((recent[-1][0] - recent[0][0]).total_seconds() / 60))
    srcs = sorted({f"{safe_source(x.get('source'))} ({_KIND.get(x.get('type'), 'other')})" for _, x in recent})
    ev = [f"{len(recent)} failed logins for {r.get('user')} in {mins} min; last at "
          f"{recent[-1][0].strftime('%H:%MZ')}; from {', '.join(srcs)}"
          + ("" if expires else "; stays locked until cleared")]
    causes = sorted(i for i in found_ids if i.split("(")[0] in LOCKOUT_CAUSES)
    if causes:
        ev.append("likely caused by: " + ", ".join(causes))
    return Finding("ACCOUNT_LOCKED", "faillock", tuple(ev))


PINNED_SIGNERS = {"702d426d350d275d": "Rocky Linux 9", "8a3872bf3228467c": "EPEL 9",
                  "521276f43c908f8e": "The CyberHygiene Project"}
_PATH = re.compile(r"/[A-Za-z0-9._/+-]+")
_PKG = re.compile(r"[A-Za-z0-9._+-]+")


def fapolicyd_findings(r):
    """Row 46. Only denials whose program still exists and is not trusted now count."""
    fk = r.get("fapolicyd")
    if not isinstance(fk, dict):
        return []
    out = []
    if fk.get("permissive") is True:
        out.append(Finding("FAPOLICYD_PERMISSIVE", "fapolicyd", ("fapolicyd is in permissive mode",)))
    elif fk.get("active") not in ("active", None):
        out.append(Finding("FAPOLICYD_PERMISSIVE", "fapolicyd", (f"fapolicyd is {fk.get('active')}",)))
    stale, unpk = [], []
    for d in fk.get("denials") or []:
        p = d.get("path")
        if not (isinstance(p, str) and _PATH.fullmatch(p)) or d.get("exists") is not True or d.get("in_trust") is True:
            continue
        pkg, sg, n = d.get("package"), d.get("signer"), d.get("count") or 1
        pkg = pkg if isinstance(pkg, str) and _PKG.fullmatch(pkg) else None
        sg = sg if isinstance(sg, str) and re.fullmatch(r"[0-9a-f]{16}", sg) else None
        if pkg and sg in PINNED_SIGNERS:
            stale.append(f"fapolicyd blocked {p} (package {pkg}, signed {PINNED_SIGNERS[sg]}), {n} time(s) in the last 10 minutes")
        elif not pkg:
            unpk.append(f"fapolicyd blocked {p} (no package owns it)")
        elif not sg:
            unpk.append(f"fapolicyd blocked {p} (package {pkg} is unsigned)")
        else:
            unpk.append(f"fapolicyd blocked {p} (package {pkg} signed by unknown key {sg})")
    if stale:
        out.append(Finding("FAPOLICYD_TRUST_STALE", "fapolicyd", tuple(stale)))
    if unpk:
        out.append(Finding("FAPOLICYD_DENIED_UNPACKAGED", "fapolicyd", tuple(unpk)))
    return out


RULES = (collect_conf_invalid, time_unverified, time_skew, dns_lookup_failed, tls_expired, tls_untrusted, kanidm_unreachable, renewal_stopped, unixd_offline,
         posix_pw_missing, ca_root_missing, nss_order_wrong, account_expired, account_not_yet_valid, ssh_cert_expired,
         ssh_ca_not_trusted)


def evaluate(report, peer=None):
    found = [f for rule in RULES if (f := rule(report))]
    found += services_down(report) + labels_wrong(report) + fapolicyd_findings(report)
    lk = account_locked(report, {f.id for f in found})
    if lk:
        found.append(lk)
    if peer and report.get("role") == "client" and peer.get("role") == "server":
        found += [f for f in (cache_stale(peer, report), ssh_ca_not_trusted_cross(peer, report),
                              dns_wrong_address(peer, report)) if f]
        found = list({f.id: f for f in found}.values())           # one SSH_CA_NOT_TRUSTED even if both rules fire
        st = (peer.get("services") or {}).get("named")
        if st not in (None, "active"):
            found = [Finding(f.id, f.component, f.evidence + (f"likely caused by: named is {st} on {peer.get('host')}",),
                             f.severity) if f.id == "DNS_LOOKUP_FAILED" else f for f in found]
    if any(f.id.startswith("DNS_") for f in found):
        found = [f for f in found if f.id != "KANIDM_UNREACHABLE"]   # the name is the fault, not the path
    return sorted(found, key=lambda f: f.id)
