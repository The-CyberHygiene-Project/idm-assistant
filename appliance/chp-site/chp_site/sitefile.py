# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Strict KEY=value reader and site.conf validation. Nothing here is ever evaluated by a shell."""
import base64
import ipaddress
import re
import struct

LABEL_RE = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


class SiteError(ValueError):
    """A problem in the site files; str() is the message shown at the install console."""


def read_file(path, what):
    """Read a site file as UTF-8. A missing, unreadable or non-UTF-8 file is a SiteError with a readable message
    (files saved on Windows as ANSI or UTF-16 used to end in a Python traceback at the install console)."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SiteError(f"the site stick has no {what} ({path.name})") from None
    except UnicodeDecodeError:
        raise SiteError(f"{path.name} is not UTF-8 text (saved as ANSI or UTF-16?); save it as UTF-8") from None
    except (IsADirectoryError, PermissionError) as e:
        raise SiteError(f"cannot read {path.name}: {e.strerror}") from None


def read_kv(text, name, lines=None):
    """KEY=value lines; blank lines and '#' comments ignored. A UTF-8 BOM, CRLF and surrounding spaces are tolerated
    (files edited on Windows/macOS). A line without '=', a key that is not UPPER_CASE, or a repeated key is an error."""
    if text.startswith("﻿"):
        text = text[1:]
    out = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SiteError(f"{name} line {n}: expected KEY=value, got {raw.strip()!r}")
        k, v = (p.strip() for p in line.split("=", 1))
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", k):
            raise SiteError(f"{name} line {n}: bad key {k!r} (keys are UPPER_CASE)")
        if k in out:
            raise SiteError(f"{name} line {n}: {k} is set twice")
        if re.search(r"\s#", v):
            raise SiteError(f"{name} line {n}: {k}: inline comments are not allowed (put the comment on its own line)")
        out[k] = v
        if lines is not None:
            lines[k] = n
    return out


def _plain(k, v, n):
    if re.search(r"[\"'“”‘’`$\\;|&<>]", v):
        raise SiteError(f"site.conf line {n}: {k}: quotes and shell characters are not allowed in values ({v!r})")
    return v


def domain(v):
    if len(v) > 253 or not re.fullmatch(rf"{LABEL_RE}(?:\.{LABEL_RE})+", v):
        raise SiteError(f"DOMAIN: {v!r} is not a lower-case DNS domain with at least two labels")
    return v


def _ip(k, v):
    try:
        return ipaddress.IPv4Address(v)
    except ValueError:
        raise SiteError(f"{k}: {v!r} is not an IPv4 address") from None


def _list(v):
    return [x for x in re.split(r"[,\s]+", v) if x]


def _host_or_ip(k, v):
    try:
        ipaddress.IPv4Address(v)
        return v
    except ValueError:
        if re.fullmatch(rf"{LABEL_RE}(?:\.{LABEL_RE})*", v):
            return v
        raise SiteError(f"{k}: {v!r} is neither an IPv4 address nor a host name") from None


def ssh_pubkey(v):
    """An OpenSSH public key usable on a FIPS host: ECDSA nistp256/384/521 or RSA >= 3072 bits. Returns 'type base64'."""
    f = v.split()
    if len(f) < 2:
        raise SiteError("ADMIN_SSH_PUBKEY: expected '<type> <base64> [comment]'")
    typ, b64 = f[0], f[1]
    if typ == "ssh-ed25519":
        raise SiteError("ADMIN_SSH_PUBKEY: ssh-ed25519 keys cannot be used on a FIPS host; "
                        "make an ECDSA key: ssh-keygen -t ecdsa -b 384")
    if typ not in ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"):
        raise SiteError(f"ADMIN_SSH_PUBKEY: key type {typ!r} is not usable (want ECDSA or RSA >= 3072)")
    try:
        blob = base64.b64decode(b64, validate=True)
        parts, i = [], 0
        while i < len(blob):
            (n,) = struct.unpack(">I", blob[i:i + 4])
            parts.append(blob[i + 4:i + 4 + n])
            i += 4 + n
    except Exception:
        raise SiteError("ADMIN_SSH_PUBKEY: the key data is not valid base64/OpenSSH") from None
    if not parts or parts[0].decode(errors="replace") != typ:
        raise SiteError(f"ADMIN_SSH_PUBKEY: declared type {typ} does not match the key data")
    if typ == "ssh-rsa":
        bits = (len(parts[2].lstrip(b"\x00")) * 8) if len(parts) >= 3 else 0
        if bits < 3072:
            raise SiteError(f"ADMIN_SSH_PUBKEY: RSA key is {bits} bits; at least 3072 are required")
    return f"{typ} {b64}"


_TZ = r"UTC|[A-Z][A-Za-z_]+(?:/[A-Za-z0-9_+-]+){1,2}"
_PATH = r"(?:/[A-Za-z0-9._-]+)+"
_NAME = r"[^\x00-\x1f=,]{1,64}"


_MARK = r"[^\x00-\x1f\x7f]{1,128}"


def _doc_keys(raw, s):
    """ISO 0.7.0 Plan 3 (optional, additive): who approves controlled documents (Kanidm account names; enable checks
    that each exists in Kanidm) and the CUI marking values (Task 5 reads them through sitevars). Empty = not set."""
    from .kanidm import NAME_RE                       # here: kanidm imports this module
    isso = raw.get("DOC_ISSO_ACCOUNT", "").strip()
    if isso and not re.fullmatch(NAME_RE, isso):
        raise SiteError(f"DOC_ISSO_ACCOUNT: {isso!r} is not a Kanidm account name (lower-case letters, digits, _; "
                        "starts with a letter; max 32)")
    appr = []
    for a in (x.strip() for x in raw.get("DOC_APPROVER_ACCOUNTS", "").split(",")):
        if not a:
            continue
        if not re.fullmatch(NAME_RE, a):
            raise SiteError(f"DOC_APPROVER_ACCOUNTS: {a!r} is not a Kanidm account name (lower-case letters, digits, "
                            "_; starts with a letter; max 32)")
        if a in appr:
            raise SiteError(f"DOC_APPROVER_ACCOUNTS: {a} is listed twice")
        appr.append(a)
    if isso and isso in appr:
        raise SiteError(f"DOC_ISSO_ACCOUNT {isso} is also in DOC_APPROVER_ACCOUNTS: the ISSO overrides, the approvers "
                        "approve; name the ISSO in DOC_ISSO_ACCOUNT only")
    s["DOC_ISSO_ACCOUNT"], s["DOC_APPROVER_ACCOUNTS"] = isso, appr
    for k in ("CUI_CONTROLLED_BY", "CUI_CATEGORY", "CUI_POC"):
        v = raw.get(k, "").strip()
        if v and not re.fullmatch(_MARK, v):
            raise SiteError(f"{k}: 1-128 printable characters (it is printed in the CUI marking)")
        s[k] = v


def parse_site(text):
    where = {}
    raw = read_kv(text, "site.conf", where)
    for k, v in raw.items():
        _plain(k, v, where[k])
    known = {"DOMAIN", "SUBNET", "GATEWAY", "DNS_FORWARDERS", "NTP_UPSTREAM", "TIMEZONE", "ISSO_NAME",
             "UNEXPIRE_DELEGATES", "COLLECTOR_IP", "ACCESSIBILITY", "ALERT_HOOK", "ADMIN_SSH_PUBKEY",
             "COLLECTOR_SSH_PUBKEY", "BASELINE_DELEGATES", "SECURITY_ADDONS", "SECURITY_ALERT_LEVEL",
             "REVIEW_DELEGATES", "DOCUMENTS", "DOCUMENTS_BACKUP_DAYS", "DOC_ISSO_ACCOUNT", "DOC_APPROVER_ACCOUNTS",
             "CUI_CONTROLLED_BY", "CUI_CATEGORY", "CUI_POC"}
    for k in raw:
        if k not in known:
            raise SiteError(f"site.conf: unknown key {k}")
    for k in ("DOMAIN", "SUBNET", "GATEWAY", "NTP_UPSTREAM", "TIMEZONE", "ISSO_NAME", "ADMIN_SSH_PUBKEY"):
        if not raw.get(k):
            raise SiteError(f"site.conf: {k} is required")
    s = {"DOMAIN": domain(raw["DOMAIN"])}
    try:
        s["SUBNET"] = ipaddress.IPv4Network(raw["SUBNET"], strict=True)
    except ValueError:
        raise SiteError(f"SUBNET: {raw['SUBNET']!r} is not a network in CIDR form (host bits must be zero)") from None
    if not 8 <= s["SUBNET"].prefixlen <= 30:
        raise SiteError("SUBNET: prefix must be /8 to /30")
    s["GATEWAY"] = _ip("GATEWAY", raw["GATEWAY"])
    if s["GATEWAY"] not in s["SUBNET"]:
        raise SiteError(f"GATEWAY: {s['GATEWAY']} is outside SUBNET {s['SUBNET']}")
    s["DNS_FORWARDERS"] = [str(_ip("DNS_FORWARDERS", x)) for x in _list(raw.get("DNS_FORWARDERS", ""))]
    s["NTP_UPSTREAM"] = [_host_or_ip("NTP_UPSTREAM", x) for x in _list(raw["NTP_UPSTREAM"])]
    if not re.fullmatch(_TZ, raw["TIMEZONE"]):
        raise SiteError(f"TIMEZONE: {raw['TIMEZONE']!r} is not a zone name like America/Denver or UTC")
    try:
        import zoneinfo  # noqa: PLC0415  (3.9 stdlib; the database may be absent, e.g. on a minimal image)
        zones = zoneinfo.available_timezones()
    except Exception:
        zones = set()
    if zones and raw["TIMEZONE"] not in zones:
        raise SiteError(f"TIMEZONE: {raw['TIMEZONE']!r} is not a known time zone (Anaconda would silently use its default)")
    s["TIMEZONE"] = raw["TIMEZONE"]
    if not re.fullmatch(_NAME, raw["ISSO_NAME"]):
        raise SiteError("ISSO_NAME: 1-64 printable characters, no '=' or ','")
    s["ISSO_NAME"] = raw["ISSO_NAME"]
    dels = [x.strip() for x in raw.get("UNEXPIRE_DELEGATES", "").split(",") if x.strip()]
    for d in dels:
        if not re.fullmatch(_NAME, d):
            raise SiteError(f"UNEXPIRE_DELEGATES: bad name {d!r}")
    s["UNEXPIRE_DELEGATES"] = dels
    bdels = [x.strip() for x in raw.get("BASELINE_DELEGATES", "").split(",") if x.strip()]
    for d in bdels:
        if not re.fullmatch(_NAME, d):
            raise SiteError(f"BASELINE_DELEGATES: bad name {d!r}")
    s["BASELINE_DELEGATES"] = bdels
    rdels = [x.strip() for x in raw.get("REVIEW_DELEGATES", "").split(",") if x.strip()]   # review spec §5 (separate list)
    for d in rdels:
        if not re.fullmatch(_NAME, d):
            raise SiteError(f"REVIEW_DELEGATES: bad name {d!r}")
    s["REVIEW_DELEGATES"] = rdels
    c = raw.get("COLLECTOR_IP", "")
    if c and _ip("COLLECTOR_IP", c) not in s["SUBNET"]:
        raise SiteError(f"COLLECTOR_IP: {c} is outside SUBNET {s['SUBNET']}")
    s["COLLECTOR_IP"] = c
    a = raw.get("ACCESSIBILITY", "off") or "off"
    if a not in ("on", "off"):
        raise SiteError("ACCESSIBILITY: on or off")
    s["ACCESSIBILITY"] = a
    h = raw.get("ALERT_HOOK", "")
    if h and not re.fullmatch(_PATH, h):
        raise SiteError(f"ALERT_HOOK: {h!r} is not an absolute path")
    s["ALERT_HOOK"] = h
    sa = raw.get("SECURITY_ADDONS", "no") or "no"        # security bundle (0.3.0): additive, default off
    if sa not in ("yes", "no"):
        raise SiteError("SECURITY_ADDONS: yes or no")
    s["SECURITY_ADDONS"] = sa
    dc = raw.get("DOCUMENTS", "no") or "no"               # ISO 0.7.0 document server: additive, default off
    if dc not in ("yes", "no"):
        raise SiteError("DOCUMENTS: yes or no")
    if dc == "yes" and sa != "yes":
        raise SiteError("DOCUMENTS=yes needs SECURITY_ADDONS=yes (the document server is monitored by the security add-on)")
    s["DOCUMENTS"] = dc
    bd = raw.get("DOCUMENTS_BACKUP_DAYS", "14") or "14"
    if not (bd.isdigit() and 1 <= int(bd) <= 365):
        raise SiteError("DOCUMENTS_BACKUP_DAYS: a number of days from 1 to 365 (default 14)")
    s["DOCUMENTS_BACKUP_DAYS"] = int(bd)
    _doc_keys(raw, s)
    lv = raw.get("SECURITY_ALERT_LEVEL", "10") or "10"
    if not (lv.isdigit() and 3 <= int(lv) <= 15):
        raise SiteError("SECURITY_ALERT_LEVEL: a number from 3 to 15 (Wazuh rule level; default 10)")
    s["SECURITY_ALERT_LEVEL"] = int(lv)
    s["ADMIN_SSH_PUBKEY"] = ssh_pubkey(raw["ADMIN_SSH_PUBKEY"])
    ck = raw.get("COLLECTOR_SSH_PUBKEY", "")
    if ck:
        if not s["COLLECTOR_IP"]:
            raise SiteError("COLLECTOR_SSH_PUBKEY needs COLLECTOR_IP (the diag key is pinned to the collector's address)")
        try:
            ck = ssh_pubkey(ck)
        except SiteError as e:
            raise SiteError(str(e).replace("ADMIN_SSH_PUBKEY", "COLLECTOR_SSH_PUBKEY")) from None
    s["COLLECTOR_SSH_PUBKEY"] = ck
    return s
