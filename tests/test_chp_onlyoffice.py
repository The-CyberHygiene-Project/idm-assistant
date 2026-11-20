"""ISO 0.7.0 Plan 3 Task 8: chp-onlyoffice and the workstation gates of the editor spike.
G2: the autosave sweep (chp_site.onlyoffice.sweep, reusing doc.remove_editor_copies).
G3: the workstation egress table (nft/chp-workstation-egress.nft, judged here by a small evaluator of the rule forms the
    file uses, against the addresses chp-site renders from the site files).
G4: packaging (the AI Tools removal, the preseed, the pinned vendor RPM, the Rocky extras).
Made-up site values only."""
import ipaddress
import os
import re
import subprocess
from pathlib import Path

import pytest

from chp_site import cli, doc as DOC, onlyoffice as OO
from chp_site import wazuh as w
from chp_site.hosts import parse_hosts
from chp_site.sitefile import SiteError, parse_site
from tests.test_chp_site_sitefile import ECDSA
from tests.test_chp_site_wazuh import _level

TOP = Path(__file__).resolve().parents[1]
D = TOP / "appliance" / "rpm" / "chp-onlyoffice"
R = TOP / "appliance" / "release"
SPEC = ((D / "chp-onlyoffice.spec").read_text() if (D / "chp-onlyoffice.spec").exists() else "") \
    .replace("%{_sysconfdir}", "/etc").replace("%{_libexecdir}", "/usr/libexec")
HOUR = 3600
NOW = 1_800_000_000.0


def t(n):
    return (D / n).read_text()


# ---------- the site (made-up values) ----------

def _site(**kw):
    conf = {"DOMAIN": "example.test", "SUBNET": "192.0.2.0/24", "GATEWAY": "192.0.2.1", "NTP_UPSTREAM": "192.0.2.123",
            "TIMEZONE": "UTC", "ISSO_NAME": "A. Example", "SECURITY_ADDONS": "yes", "DOCUMENTS": "yes",
            "DNS_FORWARDERS": "", "ADMIN_SSH_PUBKEY": f"{ECDSA} admin@example"}
    conf.update(kw)
    site = parse_site("".join(f"{k}={v}\n" for k, v in conf.items()))
    hosts = parse_hosts("52:54:00:00:00:10 srv1 192.0.2.10 server\n52:54:00:00:00:21 cli1 192.0.2.21 client\n", site)
    return site, hosts


# ---------- G2: the autosave sweep ----------

def _home(root, name, uid=None):
    h = root / name
    (h / DOC.RECOVER).mkdir(parents=True)
    return h


def _copy(home, dirname, doc_path, age_h, extra=()):
    """One ONLYOFFICE recovery folder: a copy of the document, Editor.bin, asc_name.info naming the original."""
    d = home / DOC.RECOVER / dirname
    d.mkdir()
    (d / Path(doc_path).name).write_bytes(b"CUI copy")
    (d / "Editor.bin").write_bytes(b"editor state")
    (d / "asc_name.info").write_text(doc_path)
    for e in extra:
        (d / e).parent.mkdir(parents=True, exist_ok=True)
        (d / e).write_text("{}")
    when = NOW - age_h * HOUR
    for p in [*d.rglob("*"), d]:
        os.utime(p, (when, when), follow_symlinks=False)
    return d


def _recents(home, *paths):
    p = home / DOC.RECENTS[0]
    p.write_text('<?xml version="1.0" encoding="utf-8"?><recents>'
                 + "".join(f'<file path="{x}" type="65" date="" url="" parent="" />' for x in paths) + "</recents>")
    return p


def _sweep(tmp_path, procs, as_user=None, **kw):
    out = []
    calls = []

    def inline(uid, gid, fn):
        calls.append((uid, gid))
        return fn()
    kw.setdefault("run", lambda argv, **k: subprocess.CompletedProcess(argv, 0, "", ""))
    kw.setdefault("linger_dir", tmp_path / "linger")
    res = OO.sweep(home_root=tmp_path / "home", now=NOW, procs=procs, as_user=as_user or inline, say=out.append,
                   min_uid=os.getuid(), **kw)
    return out, calls, res


def test_sweep_skips_live_session(tmp_path):
    home = tmp_path / "home"
    me = os.getuid()
    a = _home(home, "alice")
    old = _copy(a, "DE__aaaaaa", str(a / "Documents/CHP-Working/CUI_SSP_v1.1-DRAFT.docx"), 30)
    # a live ONLYOFFICE session of this user: nothing of hers is touched (recover/ is the editor's crash recovery)
    out, calls, _ = _sweep(tmp_path, {me: {"DesktopEditors", "bash"}})
    assert old.exists() and calls == []
    assert any("ONLYOFFICE is running" in ln and "kept" in ln for ln in out)
    # the helper alone counts too
    out, calls, _ = _sweep(tmp_path, {me: {"editors_helper"}})
    assert old.exists() and calls == []
    # logged in without the editor (any process of hers): a live user session, kept as well
    out, calls, _ = _sweep(tmp_path, {me: {"gnome-shell"}})
    assert old.exists() and calls == []
    assert any("live session" in ln for ln in out)
    # another user's processes do not protect hers
    out, calls, _ = _sweep(tmp_path, {me + 1: {"DesktopEditors"}})
    assert not old.exists() and calls == [(me, os.getgid())]


def test_sweep_only_older_than_n_hours(tmp_path):
    assert OO.SWEEP_HOURS == 12
    a = _home(tmp_path / "home", "alice")
    w_ = a / "Documents/CHP-Working"
    old = _copy(a, "DE__old111", str(w_ / "CUI_SSP_v1.1-DRAFT.docx"), 13, extra=("changes/changes0.json",))
    young = _copy(a, "DE__new222", str(w_ / "CUI_POAM_v2.0-DRAFT.xlsx"), 11)
    edge = _copy(a, "DE__edge33", str(w_ / "CUI_Plan_v0.1-DRAFT.docx"), 12.5)
    # an old folder whose newest file is fresh (the editor wrote it 1 h ago) is NOT old
    touched = _copy(a, "DE__touch4", str(w_ / "CUI_IR_v1.0-DRAFT.docx"), 40)
    os.utime(touched / "Editor.bin", (NOW - HOUR, NOW - HOUR))
    # the same document in an old and a young folder: the young one (and the recents entry) stay
    both = str(w_ / "CUI_Policy_v3.0-DRAFT.docx")
    old_dup = _copy(a, "DE__dup555", both, 20)
    young_dup = _copy(a, "DE__dup666", both, 2)
    rec = _recents(a, str(w_ / "CUI_SSP_v1.1-DRAFT.docx"), str(w_ / "CUI_POAM_v2.0-DRAFT.xlsx"), both)
    out, _, res = _sweep(tmp_path, {})
    assert not old.exists() and not edge.exists() and not old_dup.exists()
    assert young.exists() and touched.exists() and young_dup.exists()
    r = rec.read_text()
    assert "CUI_SSP_v1.1-DRAFT.docx" not in r                 # only in an old (removed) copy
    assert "CUI_POAM_v2.0-DRAFT.xlsx" in r and both in r       # a young copy still refers to them
    # nothing in a folder of only Editor.bin escapes: an old one is removed whole
    bare = a / DOC.RECOVER / "DE__bare77"
    bare.mkdir()
    (bare / "Editor.bin").write_bytes(b"x")
    for p in (bare / "Editor.bin", bare):
        os.utime(p, (NOW - 20 * HOUR, NOW - 20 * HOUR))
    _sweep(tmp_path, {})
    assert not bare.exists() and young.exists()


def test_sweep_logs_removals(tmp_path):
    a = _home(tmp_path / "home", "alice")
    old = _copy(a, "DE__aaaaaa", str(a / "Documents/CHP-Working/CUI_SSP_v1.1-DRAFT.docx"), 30)
    _recents(a, str(a / "Documents/CHP-Working/CUI_SSP_v1.1-DRAFT.docx"))
    out, _, res = _sweep(tmp_path, {})
    lines = [ln for ln in out if ln.startswith("removed ")]
    assert any(str(old) in ln for ln in lines) and any("recents.xml" in ln for ln in lines)
    assert all("older than 12 h" in ln and "uid" in ln for ln in lines)
    assert len(res) == len(lines)
    # the journal tag is the unit's SyslogIdentifier; the manager's rule stores every removal at level 3
    u = t("chp-onlyoffice-sweep.service")
    assert f"SyslogIdentifier={OO.SWEEP_TAG}" in u and OO.SWEEP_TAG == "chp-doc-sweep"
    assert "ExecStart=/usr/bin/chp-site onlyoffice sweep" in u
    ev = {"decoder": "x", "location": "journald", "program_name": "chp-doc-sweep", "log": lines[0]}
    assert _level(w.NEXTCLOUD_RULES, ev) == (w.DOC_SWEEP_RULE, 3)
    for quiet in ("kept /home/x: ONLYOFFICE is running", "swept 0 users"):
        assert _level(w.NEXTCLOUD_RULES, {**ev, "log": quiet})[0] is None
    assert _level(w.NEXTCLOUD_RULES, {**ev, "program_name": "bash"})[0] is None
    # not a NextCloud rule for the daily review (like the Kanidm rule in the same file)
    assert w.DOC_SWEEP_RULE not in w.NEXTCLOUD_RULE_IDS
    tm = t("chp-onlyoffice-sweep.timer")
    assert "OnUnitActiveSec=1h" in tm and "WantedBy=timers.target" in tm


def test_sweep_removes_as_the_owner_and_skips_symlinks_and_system_uids(tmp_path):
    home = tmp_path / "home"
    a = _home(home, "alice")
    _copy(a, "DE__aaaaaa", str(a / "x/CUI_A_v1.0-DRAFT.docx"), 30)
    (home / "alias").symlink_to(a)                             # Kanidm's home alias: the real folder only, once
    out, calls, _ = _sweep(tmp_path, {})
    assert calls == [(os.getuid(), os.getgid())]
    # below min_uid: never touched (system accounts)
    b = _home(home, "bob")
    kept = _copy(b, "DE__bbbbbb", str(b / "x/CUI_B_v1.0-DRAFT.docx"), 30)
    out = []
    OO.sweep(home_root=home, now=NOW, procs={}, as_user=lambda u, g, fn: fn(), say=out.append,
             min_uid=os.getuid() + 1, run=lambda *a, **k: None, linger_dir=tmp_path / "none")
    assert kept.exists()
    # the default runner drops to the owner first: as a non-root caller it runs only as itself
    assert OO._as_user(os.getuid(), os.getgid(), lambda: [["note", f"uid {os.getuid()}"]]) == [["note", f"uid {os.getuid()}"]]
    if os.getuid() != 0:
        with pytest.raises(SiteError):
            OO._as_user(os.getuid() + 1, os.getgid(), lambda: [])
    # a failure inside the child is reported, never a removal
    assert OO._as_user(os.getuid(), os.getgid(), lambda: 1 / 0)[0][0] == "error"


def test_sweep_turns_linger_off(tmp_path):
    (tmp_path / "home").mkdir()
    ld = tmp_path / "linger"
    ld.mkdir()
    (ld / "alice").write_text("")
    seen = []

    def loginctl(argv, **k):                                # the real loginctl removes the linger file
        seen.append(argv)
        (ld / argv[-1]).unlink()
        return subprocess.CompletedProcess(argv, 0, "", "")
    out, _, _ = _sweep(tmp_path, {}, run=loginctl)
    assert ["loginctl", "disable-linger", "alice"] in seen
    assert any(ln.startswith("linger turned off for alice") for ln in out)
    ev = {"decoder": "x", "location": "journald", "program_name": "chp-doc-sweep",
          "log": next(ln for ln in out if ln.startswith("linger"))}
    assert _level(w.NEXTCLOUD_RULES, ev) == (w.DOC_SWEEP_RULE, 3)


def test_editor_running_uses_the_shared_process_table(tmp_path):
    # doc close and the sweep read /proc the same way
    proc = tmp_path / "proc"
    for pid, comm in (("101", "DesktopEditors"), ("102", "bash")):
        (proc / pid).mkdir(parents=True)
        (proc / pid / "comm").write_text(comm + "\n")
    tab = OO.processes(proc)
    assert tab[os.getuid()] == {"DesktopEditors", "bash"}
    assert DOC.EDITOR_PROCESSES == ("DesktopEditors", "editors_helper")


# ---------- G3: the workstation egress table ----------

def _defines(text):
    return dict(re.findall(r"^define (\w+) = (.+)$", text, re.M))


def _tokens(s):
    return re.findall(r'\{[^}]*\}|"[^"]*"|\S+', s)


def _rules(site_kw=None, name="nft/chp-workstation-egress.nft"):
    """The output chain of the shipped table: (policy, [rule token lists]); $VARS replaced from chp-site's rendering."""
    site, hosts = _site(**(site_kw or {}))
    defs = _defines(OO.egress_defines(site, hosts))
    n = re.sub(r"#.*", "", t(name))
    body = re.search(r"chain output \{(.*?)\n\s*\}", n, re.S).group(1)
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    head = lines[0]
    assert head.startswith("type filter hook output priority filter;")
    policy = re.search(r"policy (\w+);", head).group(1)
    for k, v in defs.items():
        lines = [ln.replace(f"${k}", v) for ln in lines]
    return policy, [_tokens(ln) for ln in lines[1:]]


def _set(tok):
    return [x.strip() for x in tok.strip("{}").split(",")] if tok.startswith("{") else [tok]


def _in(addr, tok):
    a = ipaddress.ip_address(addr)
    return any(a in ipaddress.ip_network(x, strict=False) for x in _set(tok) if ":" in x or "." in x
               if (":" in x) == (a.version == 6))


def verdict(daddr, proto, dport=None, oif="eth0", skuid="alice", icmp=None, site_kw=None,
            name="nft/chp-workstation-egress.nft"):
    """What the table does with the FIRST packet of a new flow (no conntrack state)."""
    policy, rules = _rules(site_kw, name)
    fam = ipaddress.ip_address(daddr).version
    for toks in rules:
        i, ok, v = 0, True, None
        while i < len(toks) and ok:
            k = toks[i]
            if k == "oifname":
                ok, i = toks[i + 1].strip('"') == oif, i + 2
            elif k == "ct":                                     # ct state established,related: never a new flow
                ok, i = False, i + 3
            elif k in ("ip", "ip6") and toks[i + 1] == "daddr":
                ok, i = (fam == (4 if k == "ip" else 6)) and _in(daddr, toks[i + 2]), i + 3
            elif k == "meta" and toks[i + 1] == "l4proto":
                ok, i = proto in _set(toks[i + 2]), i + 3
            elif k == "meta" and toks[i + 1] == "skuid":
                ok, i = toks[i + 2].strip('"') == skuid, i + 3
            elif k in ("tcp", "udp", "th") and toks[i + 1] == "dport":
                ok = (k == "th" or k == proto) and dport is not None and str(dport) in _set(toks[i + 2])
                i += 3
            elif k in ("icmp", "icmpv6") and toks[i + 1] == "type":
                ok = proto == k and icmp in _set(toks[i + 2])
                i += 3
            elif k == "limit":                                  # limit rate N/unit [burst N packets]: under the limit
                i += 3
                if i < len(toks) and toks[i] == "burst":
                    i += 3
            elif k == "log":
                i += 1
                while i < len(toks) and toks[i] in ("prefix", "level", "flags"):
                    i += 2
            elif k == "counter":
                i += 1
            elif k in ("accept", "drop"):
                v, i = k, i + 1
            elif k == "reject":
                v, i = "reject", len(toks)
            else:
                raise AssertionError(f"evaluator does not know {k!r} in {' '.join(toks)}")
        if ok and v:
            return v
    return policy


def test_egress_rules_default_drop_except_server():
    policy, rules = _rules()
    assert policy == "drop"
    srv = "192.0.2.10"
    for port in (443, 8443, 1514, 9000, 22):                  # Kanidm, NextCloud, Wazuh agent, step-ca, ssh
        assert verdict(srv, "tcp", port) == "accept", port
    assert verdict("127.0.0.1", "tcp", 631, oif="lo") == "accept"
    assert verdict("::1", "tcp", 80, oif="lo") == "accept"
    assert verdict(srv, "icmp", icmp="echo-request") == "accept"
    for dst, proto, port in ((srv, "tcp", 5432), (srv, "udp", 1514), ("192.0.2.21", "tcp", 22),
                             ("192.0.2.1", "tcp", 80), ("203.0.113.5", "tcp", 443), ("203.0.113.5", "tcp", 80),
                             ("2001:db8::5", "tcp", 443), ("203.0.113.5", "udp", 4500)):
        assert verdict(dst, proto, port) in ("drop", "reject"), (dst, proto, port)
    # time: only chronyd speaks NTP (its servers may be names, resolved through the site resolver)
    assert verdict("192.0.2.123", "udp", 123, skuid="chrony") == "accept"     # NTP_UPSTREAM=192.0.2.123
    assert verdict("203.0.113.123", "udp", 123, skuid="chrony") == "reject"   # not an upstream (fix round 1, m1)
    assert verdict("192.0.2.123", "udp", 123, skuid="alice") in ("drop", "reject")
    # IPv6 neighbour discovery (no payload) works; multicast goes nowhere
    assert verdict("ff02::1:ff00:5", "icmpv6", icmp="nd-neighbor-solicit") == "accept"
    assert verdict("224.0.0.251", "udp", 5353) == "drop" and verdict("ff02::fb", "udp", 5353) == "drop"
    n = t("nft/chp-workstation-egress.nft")
    # site-independent: every address comes from the rendered include, none is written in the file
    assert 'include "/etc/chp/workstation-egress-addr.nft"' in n
    code = re.sub(r"#.*", "", n)
    assert not re.search(r"\b\d+\.\d+\.\d+\.\d+\b", code.replace("224.0.0.0", "").replace("255.255.255.255", ""))
    # a separate table, replaced atomically on reload (firewalld's own table is left alone)
    assert re.search(r"^table inet chp_workstation_egress\ndelete table inet chp_workstation_egress\n", code, re.M)
    assert re.search(r'log prefix "CHP-WS-EGRESS " level warn flags skuid', n)


def test_dns_only_site_resolver_v4_v6():
    site, hosts = _site()
    d = _defines(OO.egress_defines(site, hosts))
    # clients resolve through the server (render.net_ks): the resolver is the server's address, from the site files
    assert d == {"CHP_WS_SERVER_IP": "192.0.2.10", "CHP_WS_RESOLVER_IP": "192.0.2.10",
                 "CHP_WS_NTP4": "{ 192.0.2.123 }", "CHP_WS_NTP6": "{ ::/128 }"}
    for proto in ("udp", "tcp"):
        assert verdict("192.0.2.10", proto, 53) == "accept"
        for other in ("192.0.2.1", "8.8.8.8", "203.0.113.53", "2001:4860:4860::8888", "2606:4700:4700::1111", "fe80::1"):
            assert verdict(other, proto, 53) == "reject", (other, proto)
    # a re-IP of the server moves both, nothing else
    site2, hosts2 = _site()
    hosts2 = parse_hosts("52:54:00:00:00:10 srv1 192.0.2.40 server\n52:54:00:00:00:21 cli1 192.0.2.21 client\n", site2)
    assert _defines(OO.egress_defines(site2, hosts2))["CHP_WS_RESOLVER_IP"] == "192.0.2.40"
    assert re.search(r'th dport 53 limit rate \S+ log prefix "CHP-WS-EGRESS-DNS "', t("nft/chp-workstation-egress.nft"))


def test_dot_doh_ports_blocked():
    # DoT (853/tcp) and DNS over QUIC (853/udp): to nobody, not even the site resolver
    for dst in ("192.0.2.10", "1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"):
        for proto in ("tcp", "udp"):
            assert verdict(dst, proto, 853) == "reject", (dst, proto)
    # DoH is HTTPS: 443 (tcp and QUIC) to anything but the server is refused by the default rule
    for dst in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111", "2001:4860:4860::8888"):
        for proto in ("tcp", "udp"):
            assert verdict(dst, proto, 443) in ("drop", "reject"), (dst, proto)
    assert verdict("192.0.2.10", "udp", 443) in ("drop", "reject")   # no QUIC even to the server
    # 853 has its own rule (logged as DNS) BEFORE anything is accepted, so a later accept can never let it out
    n = re.sub(r"#.*", "", t("nft/chp-workstation-egress.nft"))
    i853 = n.index("th dport 853 reject")
    assert i853 < n.index(" accept", n.index("ct state established,related accept") + 40)
    assert re.search(r'th dport 853 limit rate \S+ log prefix "CHP-WS-EGRESS-DNS "', n)


def test_egress_defines_refuse_a_bad_server_address(tmp_path):
    site, hosts = _site()
    srv = hosts[0]._replace(ip="0.0.0.0")
    with pytest.raises(SiteError):
        OO.egress_defines(site, [srv, hosts[1]])
    OO.render_egress(tmp_path, site, hosts)
    p = tmp_path / OO.EGRESS_ADDR
    assert p.read_text() == OO.egress_defines(site, hosts) and (p.stat().st_mode & 0o777) == 0o644


def test_egress_unit_renders_at_start_and_fails_closed_on_stop():
    u = t("chp-workstation-egress.service")
    assert "ExecStartPre=-/usr/bin/chp-site onlyoffice egress-render" in u      # fix round 1: never fatal
    assert "OnFailure=chp-workstation-egress-lockdown.service" in u
    assert "ExecStart=/usr/sbin/nft -f /etc/nftables/chp-workstation-egress.nft" in u
    assert "Before=network-pre.target" in u and "Wants=network-pre.target" in u
    assert "After=" in u and "firewalld.service" in u and "nftables.service" in u
    assert "ExecStop=" not in u                                # stopping the unit never opens the workstation
    assert "nft delete table inet chp_workstation_egress" in SPEC   # only removing the package does


def test_egress_wazuh_rule_is_a_child_of_the_firewall_rule():
    line = ("Nov 19 10:00:00 cli1 kernel: CHP-WS-EGRESS IN= OUT=enp1s0 SRC=192.0.2.21 DST=203.0.113.5 LEN=60 "
            "PROTO=TCP SPT=40512 DPT=443 UID=1001 GID=1001")
    ev = {"decoder": "iptables", "location": "journald", "program_name": "kernel", "log": line, "pre_fired": {"4100"}}
    assert _level(w.NEXTCLOUD_RULES, ev) == (w.WS_EGRESS_RULE, 7)
    assert _level(w.NEXTCLOUD_RULES, {**ev, "log": line.replace("CHP-WS-EGRESS", "CHP-WS-EGRESS-DNS")}) \
        == (w.WS_EGRESS_RULE, 7)
    assert w.WS_EGRESS_RULE not in w.NEXTCLOUD_RULE_IDS


# ---------- linger (ruling F3) ----------

def test_linger_policy():
    lg = t("logind-chp-docs.conf")
    assert "[Login]" in lg and re.search(r"^KillUserProcesses=yes$", lg, re.M)
    pk = t("50-chp-no-linger.rules")
    for a in ("org.freedesktop.login1.set-self-linger", "org.freedesktop.login1.set-user-linger"):
        assert a in pk
    assert "polkit.Result.NO" in pk
    assert "/etc/systemd/logind.conf.d/50-chp-docs.conf" in SPEC and "/etc/polkit-1/rules.d/50-chp-no-linger.rules" in SPEC


# ---------- enable (workstation role, DOCUMENTS=yes) ----------

class Run:
    def __init__(self, missing=("chp-onlyoffice",), active=True, linger_dir=None, linger_rc=0):
        self.calls, self.missing, self.active = [], set(missing), active
        self.linger_dir, self.linger_rc = linger_dir, linger_rc

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        out, rc = "", 0
        if argv[:2] == ["loginctl", "disable-linger"]:
            rc = self.linger_rc
            if rc == 0 and self.linger_dir:
                (Path(self.linger_dir) / argv[-1]).unlink(missing_ok=True)
        if argv[:2] == ["rpm", "-q"]:
            rc = 1 if argv[-1] in self.missing else 0
        if argv[:3] == ["dnf", "--enablerepo=chp", "install"]:
            self.missing.clear()
        if argv[:2] == ["systemctl", "is-active"]:
            out = "active\n" if self.active else "failed\n"
        if argv[:2] == ["fapolicyd-cli", "--check-status"]:
            out = "Denied accesses: 0\n"
        return subprocess.CompletedProcess(argv, rc, out, "")


def _enable(tmp_path, run, **kw):
    site, hosts = _site(**kw)
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc/hosts").write_text("127.0.0.1 localhost\n")
    me = next(h for h in hosts if h.role == "client")
    recs = []
    return OO.enable(me, site, hosts, run=run, root=tmp_path, record=lambda *a, **k: recs.append(a),
                     sleep=lambda s: None), recs


def test_enable_installs_renders_and_starts(tmp_path):
    run = Run(linger_dir=tmp_path / "var/lib/systemd/linger")
    (tmp_path / "var/lib/systemd/linger").mkdir(parents=True)
    (tmp_path / "var/lib/systemd/linger/alice").write_text("")
    done, recs = _enable(tmp_path, run)
    assert ["dnf", "--enablerepo=chp", "install", "-y", "chp-onlyoffice"] in run.calls
    assert ["loginctl", "disable-linger", "alice"] in run.calls
    assert any(c[:3] == ["systemctl", "enable", "--now"] and "chp-workstation-egress.service" in c
               and "chp-onlyoffice-sweep.timer" in c for c in run.calls)
    assert ["nft", "list", "table", "inet", "chp_workstation_egress"] in run.calls
    assert (tmp_path / OO.EGRESS_ADDR).read_text() == "define CHP_WS_SERVER_IP = 192.0.2.10\n" \
                                                      "define CHP_WS_RESOLVER_IP = 192.0.2.10\n" \
                                                      "define CHP_WS_NTP4 = { 192.0.2.123 }\n" \
                                                      "define CHP_WS_NTP6 = { ::/128 }\n"
    # m6: the files replaced by rename get their SELinux label back
    assert ["restorecon", str(tmp_path / "etc/hosts")] in run.calls
    assert ["restorecon", str(tmp_path / OO.EGRESS_ADDR)] in run.calls
    h = (tmp_path / "etc/hosts").read_text()
    assert h.startswith("127.0.0.1 localhost\n")
    for name in OO.VENDOR_NAMES:
        assert re.search(rf"^0\.0\.0\.0 .*\b{re.escape(name)}\b", h, re.M), name
    # idempotent: a second run keeps one block and installs nothing
    run2 = Run(missing=())
    _enable2 = OO.enable(next(x for x in _site()[1] if x.role == "client"), *_site(), run=run2, root=tmp_path,
                         record=lambda *a, **k: None, sleep=lambda s: None)
    assert (tmp_path / "etc/hosts").read_text().count(OO.HOSTS_BEGIN) == 1
    assert not any(c[:2] == ["dnf", "--enablerepo=chp"] for c in run2.calls)
    assert recs and recs[0][0] == "onlyoffice-enable"


def test_enable_refuses_off_role_or_without_documents(tmp_path):
    with pytest.raises(SiteError, match="DOCUMENTS"):
        _enable(tmp_path, Run(), DOCUMENTS="no")
    site, hosts = _site()
    with pytest.raises(SiteError, match="workstation"):
        OO.enable(hosts[0], site, hosts, run=Run(), root=tmp_path, record=lambda *a, **k: None, sleep=lambda s: None)


def test_enable_refuses_when_ai_tools_are_still_there(tmp_path):
    plug = tmp_path / OO.AI_PLUGIN.lstrip("/")
    plug.mkdir(parents=True)
    with pytest.raises(SiteError, match="AI Tools"):
        _enable(tmp_path, Run())


def test_enable_restarts_a_dead_fapolicyd_with_proof(tmp_path):
    run = Run(active=False)
    with pytest.raises(SiteError, match="fapolicyd"):       # never comes back in this fake: refused loudly
        _enable(tmp_path, run)
    assert ["systemctl", "restart", "fapolicyd"] in [c[:3] for c in run.calls]


def test_cli_has_onlyoffice_commands():
    for action in ("enable", "sweep", "egress-render"):
        with pytest.raises(SystemExit) as e:
            cli.main(["onlyoffice", action, "--help"])
        assert e.value.code == 0


def test_client_enrolment_enables_the_editor_when_documents_is_yes():
    s = (TOP / "appliance/rpm/chp-identity-client/client-enrol.sh").read_text()
    m = re.search(r"do_docs\(\) \{(.*?)\n\}", s, re.S)
    assert m and '[ "$ROLE" = client ] || return 0' in m.group(1)
    assert '[ "$(chp-site get DOCUMENTS)" = yes ] || return 0' in m.group(1)
    assert "chp-site onlyoffice enable" in m.group(1)
    assert s.index("step security do_security") < s.index("step docs do_docs")


# ---------- G4: packaging ----------

def test_ai_tools_removed_postinstall(tmp_path):
    base = tmp_path / "opt/onlyoffice/desktopeditors/editors/sdkjs-plugins"
    ai = base / "{9DC93CDB-B576-4F0C-B55E-FCC9C48DD007}"
    other = base / "{AA2EA9B6-9EC2-415F-9762-634EE8D9A95E}"
    for p in (ai / "scripts", other):
        p.mkdir(parents=True)
    (ai / "config.json").write_text("{}")
    env = dict(os.environ, CHP_OO_ROOT=str(tmp_path), CHP_OO_NOLOG="1")
    sh = D / "onlyoffice-ai-off.sh"
    for _ in range(2):                                        # idempotent; a second run (nothing left) is fine
        r = subprocess.run(["bash", str(sh)], env=env, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
    assert not ai.exists() and other.exists()
    # a symlink in its place is removed as a link, never followed
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep").write_text("x")
    ai.symlink_to(victim)
    assert subprocess.run(["bash", str(sh)], env=env).returncode == 0
    assert not os.path.lexists(ai) and (victim / "keep").exists()
    assert OO.AI_PLUGIN == "/opt/onlyoffice/desktopeditors/editors/sdkjs-plugins/{9DC93CDB-B576-4F0C-B55E-FCC9C48DD007}"
    # run after our install, at the end of every transaction, and whenever the vendor package is installed/upgraded
    for sect in ("%post", "%posttrans", "%triggerin -- onlyoffice-desktopeditors"):
        m = re.search(rf"^{re.escape(sect)}\n(.*?)(?=\n\n|\Z)", SPEC, re.S | re.M)
        assert m and "/usr/libexec/chp/onlyoffice-ai-off" in m.group(1), sect
    # preseeded settings (system-wide fallback under /etc/xdg): no update check, portals locked, plugins and AI off
    c = t("DesktopEditors.conf")
    for kv in ("autoUpdateMode=disabled", "lockPortals=true", "pluginsDisabled=true", "useai=false"):
        assert re.search(rf"^{kv}$", c, re.M), kv
    assert "/etc/xdg/onlyoffice/DesktopEditors.conf" in SPEC


def test_vendor_rpm_sha_pinned(tmp_path):
    v = (R / "VENDOR.txt").read_text()
    rows = [ln.split() for ln in v.splitlines() if ln.strip() and not ln.startswith("#")]
    assert rows == [["onlyoffice-desktopeditors", "10.0.0-169.el7",
                     "2e63445620f8df8449e5c485754861bdfc662482b711024e2d38f2ec545c2df9",
                     "64189290d93e8e85debbd276e3c0cb2c236bed54c3267dc54e67af4cce5dc785",
                     "E09CA29F6E178040EF22B4098320CA65CB2DE8E5",
                     "https://download.onlyoffice.com/repo/centos/main/noarch/onlyoffice-desktopeditors-10.0.0.x86_64.rpm"]]
    key = R / "vendor-keys" / "RPM-GPG-KEY-ONLYOFFICE"
    assert key.read_text().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    # the vendor key is for checking the vendor's signature BEFORE re-signing only: the repo never carries it
    assert "E09CA29F6E178040EF22B4098320CA65CB2DE8E5" not in (R / "trusted-keys.txt").read_text()
    s = (R / "stage-vendor.sh").read_text()
    for need in ("VENDOR.txt", "--delsign", "SHA256HEADER", "gpg", "NOKEY", "refusing"):
        assert need in s, need
    # a file that is not the pinned one is refused before anything is copied (no rpm tools needed for that)
    bad = tmp_path / "onlyoffice-desktopeditors.x86_64.rpm"
    bad.write_bytes(b"not the vendor rpm")
    out = tmp_path / "third"
    out.mkdir()
    r = subprocess.run(["bash", str(R / "stage-vendor.sh"), str(bad), str(key), str(out)], capture_output=True, text=True)
    assert r.returncode != 0 and "refusing" in r.stdout + r.stderr and not any(out.iterdir())
    # sign-repo signs an unsigned non-CHP RPM only when VENDOR.txt pins its header
    sr = (R / "sign-repo.sh").read_text()
    assert "VENDOR.txt" in sr and "SHA256HEADER" in sr and "REFUSED" in sr
    # the repo carries it (third-party dir, label onlyoffice), our package and the Rocky packages it needs
    p = (R / "PACKAGES.txt").read_text().splitlines()
    for n in ("chp-onlyoffice ours", "onlyoffice-desktopeditors onlyoffice", "boost-filesystem rocky",
              "boost-system rocky", "libXScrnSaver rocky", "liberation-narrow-fonts rocky", "xcb-util-image rocky",
              "xcb-util-keysyms rocky", "xcb-util-renderutil rocky", "xcb-util-wm rocky", "poppler-utils rocky"):
        assert n in p, n


def test_spec_requires_and_pins():
    for r in ("onlyoffice-desktopeditors = 10.0.0", "poppler-utils", "chp-site >= 0.14.0-6", "nftables", "chp-base"):
        assert re.search(rf"^Requires:.*{re.escape(r)}", SPEC, re.M), r
    cs = (TOP / "appliance/chp-site/chp-site.spec").read_text()
    assert re.search(r"^Release:\s+6\.chp", cs, re.M) and "0.14.0-6.chp" in cs
    assert "Vendor:         The CyberHygiene Project" in SPEC and re.search(r"^Release:\s+\d+\.chp%\{\?dist\}", SPEC, re.M)
    b = t("build-rpm.sh")
    for f in ("chp-onlyoffice.spec", "onlyoffice-ai-off.sh", "DesktopEditors.conf", "nft/chp-workstation-egress.nft",
              "chp-workstation-egress.service", "chp-onlyoffice-sweep.service", "chp-onlyoffice-sweep.timer",
              "logind-chp-docs.conf", "50-chp-no-linger.rules", "README.md"):
        assert f in b, f
    for src in re.findall(r"^Source\d+:\s+(\S+)", SPEC, re.M):
        assert src == "LICENSE" or (D / src).exists() or any((D / d / src).exists() for d in ("nft", "monitor.d")), src


def test_readme_records_the_poam_items():
    r = t("README.md")
    for s in ("POA&M", "BoringSSL", "not FIPS", "--no-sandbox", "rpm -V", "AI Tools", "chp-doc-sweep", "12 h",
              "Task 11"):
        assert s in r, s


def test_hosts_block_is_replaced_and_a_broken_block_refused():
    once = OO.hosts_text("127.0.0.1 localhost\n192.0.2.9 printer\n")
    again = OO.hosts_text(once + "192.0.2.8 later\n")
    assert again.count(OO.HOSTS_BEGIN) == 1 and "192.0.2.8 later\n" in again and "192.0.2.9 printer\n" in again
    assert again.endswith(OO.HOSTS_END + "\n")
    with pytest.raises(SiteError, match="end line"):
        OO.hosts_text("127.0.0.1 localhost\n" + OO.HOSTS_BEGIN + "\n0.0.0.0 x\n192.0.2.9 printer\n")


def test_dead_fapolicyd_message_names_this_command(tmp_path):
    with pytest.raises(SiteError) as e:
        _enable(tmp_path, Run(active=False))
    assert "chp-site onlyoffice enable" in str(e.value) and "documents enable" not in str(e.value)


# ---------- fix round 1 ----------

def _unit(text):
    """(ExecStartPre lines, ExecStart lines, OnFailure) of a unit file."""
    k = lambda key: [ln.split("=", 1)[1] for ln in text.splitlines() if ln.startswith(key + "=")]  # noqa: E731
    return k("ExecStartPre"), k("ExecStart"), (k("OnFailure") or [None])[0]


class Host:
    """systemd + nft, as far as these units use them: '-' makes a command's failure non-fatal; a failed unit starts
    its OnFailure= unit; `nft -f` refuses a file whose include is missing, and loading a file applies its
    `table`/`delete table` lines and its tables; chp-site egress-render is the real render_egress."""
    def __init__(self, root, site, hosts, logger_fails=False):
        self.root, self.site, self.hosts, self.tables, self.log = root, site, hosts, set(), []
        self.logger_fails, self.active = logger_fails, set()

    def cmd(self, line):
        argv = line.split()
        if argv[0] == "/usr/bin/chp-site":
            OO.render_egress(self.root, self.site, self.hosts)
        elif argv[0] == "/usr/sbin/nft":
            text = (D / "nft" / Path(argv[-1]).name).read_text()
            for inc in re.findall(r'^include "([^"]+)"', text, re.M):
                if not (self.root / inc.lstrip("/")).exists():
                    raise FileNotFoundError(inc)
            for verb, name in re.findall(r"^(table|delete table) inet (\w+)$", text, re.M):
                (self.tables.add if verb == "table" else self.tables.discard)(name)
            self.tables.update(re.findall(r"^table inet (\w+) \{", text, re.M))
        elif argv[0] == "/usr/bin/logger":
            if self.logger_fails:                              # /dev/log unreachable at early boot: exit 1
                raise OSError("logger: socket /dev/log: No such file or directory")
            self.log.append(line)
        else:
            raise AssertionError(line)

    def start(self, unit, restart=False):
        """systemctl start (a no-op for an active RemainAfterExit=yes unit) or restart; then ExecStartPost."""
        text = t(unit)
        remain = re.search(r"^RemainAfterExit=yes$", text, re.M) is not None
        if unit in self.active and remain and not restart:
            return "active"
        self.active.discard(unit)
        pre, start, onf = _unit(text)
        post = [ln.split("=", 1)[1] for ln in text.splitlines() if ln.startswith("ExecStartPost=")]
        try:
            for c in pre + start:
                try:
                    self.cmd(c.lstrip("-"))
                except Exception:
                    if not c.startswith("-"):
                        raise
        except Exception:
            if onf:
                self.start(onf)
            return "failed"
        for c in post:
            try:
                self.cmd(c.lstrip("-"))
            except Exception:
                if not c.startswith("-"):
                    return "failed"
        if remain:
            self.active.add(unit)
        return "active"


def test_egress_render_failure_loads_the_last_good_file(tmp_path):
    site, hosts = _site()
    h = Host(tmp_path, site, hosts)
    assert h.start("chp-workstation-egress.service") == "active" and h.tables == {"chp_workstation_egress"}
    good = (tmp_path / OO.EGRESS_ADDR).read_text()
    # the next boot: the site files are damaged (here: a server address that cannot be one)
    h2 = Host(tmp_path, site, [hosts[0]._replace(ip="0.0.0.0"), hosts[1]])
    assert h2.start("chp-workstation-egress.service") == "active"
    assert h2.tables == {"chp_workstation_egress"} and (tmp_path / OO.EGRESS_ADDR).read_text() == good
    assert h2.log == []


def test_egress_without_any_file_or_load_fails_closed(tmp_path):
    site, hosts = _site()
    h = Host(tmp_path, site, [hosts[0]._replace(ip="0.0.0.0"), hosts[1]])   # bad site files, no last good file
    assert h.start("chp-workstation-egress.service") == "failed"
    assert h.tables == {"chp_workstation_lockdown"} and any("EGRESS LOCKDOWN" in ln for ln in h.log)
    # the lock-down table lets only loopback out
    for dst, proto, port in (("192.0.2.10", "tcp", 443), ("192.0.2.10", "udp", 53), ("192.0.2.10", "tcp", 1514),
                             ("203.0.113.5", "tcp", 443), ("2001:db8::1", "udp", 53)):
        assert verdict(dst, proto, port, name="nft/chp-workstation-lockdown.nft") == "drop", (dst, port)
    assert verdict("127.0.0.1", "tcp", 631, oif="lo", name="nft/chp-workstation-lockdown.nft") == "accept"
    # fixed site files: a restart loads the egress table and removes the lock-down table
    h.hosts = hosts
    assert h.start("chp-workstation-egress.service") == "active" and h.tables == {"chp_workstation_egress"}
    # a load failure (nft refuses the table) with a good address file also locks down
    h3 = Host(tmp_path, site, hosts)
    h3.cmd = (lambda orig: lambda line: (_ for _ in ()).throw(OSError("nft: syntax"))
              if line.startswith("/usr/sbin/nft -f /etc/nftables/chp-workstation-egress") else orig(line))(h3.cmd)
    assert h3.start("chp-workstation-egress.service") == "failed" and "chp_workstation_lockdown" in h3.tables
    # shipped and alerted at once
    assert "/etc/nftables/chp-workstation-lockdown.nft" in SPEC and "chp-workstation-egress-lockdown.service" in SPEC
    lk = t("chp-workstation-egress-lockdown.service")
    line = re.search(r'"(EGRESS LOCKDOWN[^"]*)"', lk).group(1)
    ev = {"decoder": "x", "location": "journald", "program_name": "chp-egress-lockdown", "log": line}
    assert _level(w.NEXTCLOUD_RULES, ev) == (w.WS_LOCKDOWN_RULE, 12)
    assert w.WS_LOCKDOWN_RULE not in w.NEXTCLOUD_RULE_IDS
    for f in ("nft/chp-workstation-lockdown.nft", "chp-workstation-egress-lockdown.service"):
        assert f in t("build-rpm.sh"), f


def test_ntp_only_to_the_upstream_addresses_or_any_for_names():
    two = {"NTP_UPSTREAM": "192.0.2.123, 192.0.2.124"}
    assert verdict("192.0.2.124", "udp", 123, skuid="chrony", site_kw=two) == "accept"
    assert verdict("198.51.100.7", "udp", 123, skuid="chrony", site_kw=two) == "reject"
    assert verdict("2001:db8::123", "udp", 123, skuid="chrony", site_kw=two) == "reject"
    names = {"NTP_UPSTREAM": "time.example.test, 192.0.2.123"}       # a name: chrony resolves it, any address
    assert verdict("198.51.100.7", "udp", 123, skuid="chrony", site_kw=names) == "accept"
    assert verdict("2001:db8::123", "udp", 123, skuid="chrony", site_kw=names) == "accept"
    assert verdict("198.51.100.7", "udp", 123, skuid="alice", site_kw=names) == "reject"


def test_sweep_reports_removals_done_before_an_error(tmp_path, monkeypatch):
    a = _home(tmp_path / "home", "alice")
    first = _copy(a, "DE__aaaaaa", str(a / "x/CUI_A_v1.0-DRAFT.docx"), 30)
    second = _copy(a, "DE__bbbbbb", str(a / "x/CUI_B_v1.0-DRAFT.docx"), 30)
    real = DOC.shutil.rmtree

    def flaky(p, *k, **kw):
        if Path(p) == second:
            raise PermissionError("disk said no")
        return real(p, *k, **kw)
    monkeypatch.setattr(DOC.shutil, "rmtree", flaky)
    out, _, res = _sweep(tmp_path, {})
    assert not first.exists() and second.exists()
    assert any(ln.startswith(f"removed {first} ") for ln in out) and res == [str(first)]
    assert any("could not sweep" in ln and "disk said no" in ln for ln in out)


def test_sweep_rechecks_the_editor_just_before_removing(tmp_path):
    a = _home(tmp_path / "home", "alice")
    old = _copy(a, "DE__aaaaaa", str(a / "x/CUI_A_v1.0-DRAFT.docx"), 30)
    asked = []
    out, calls, res = _sweep(tmp_path, {}, recheck=lambda uid: asked.append(uid) or True)   # started after the snapshot
    assert old.exists() and res == [] and asked == [os.getuid()] and calls
    assert any("ONLYOFFICE started since" in ln for ln in out)
    # and the real check reads the process table for that uid
    assert OO._editor_live(-12345) is False


def test_linger_off_checks_loginctl(tmp_path):
    ld = tmp_path / "linger"
    ld.mkdir()
    (ld / "alice").write_text("")
    out = []
    bad = lambda argv, **k: subprocess.CompletedProcess(argv, 1, "", "Access denied")   # noqa: E731
    assert OO.linger_off(bad, str(ld), out.append) == []
    assert out and out[0].startswith("could not turn linger off for alice (loginctl exit 1: Access denied")
    assert not any(ln.startswith("linger turned off") for ln in out)
    # exit 0 but the file is still there: not off either
    out = []
    assert OO.linger_off(lambda argv, **k: subprocess.CompletedProcess(argv, 0, "", ""), str(ld), out.append) == []
    assert out[0].startswith("could not turn linger off")
    # enable refuses rather than claiming linger is off
    (tmp_path / "var/lib/systemd/linger").mkdir(parents=True)
    (tmp_path / "var/lib/systemd/linger/alice").write_text("")
    with pytest.raises(SiteError, match="linger"):
        _enable(tmp_path, Run(linger_dir=tmp_path / "var/lib/systemd/linger", linger_rc=1))


def test_restorecon_absent_is_tolerated(tmp_path):
    def norestorecon(argv, **k):
        if argv[0] == "restorecon":
            raise FileNotFoundError("restorecon")
        return Run()(argv, **k)
    OO._restorecon(norestorecon, tmp_path / "x")                   # no exception


# ---------- fix round 2 ----------

def test_lockdown_loads_even_when_logger_fails(tmp_path):
    site, hosts = _site()
    h = Host(tmp_path, site, [hosts[0]._replace(ip="0.0.0.0"), hosts[1]], logger_fails=True)
    assert h.start("chp-workstation-egress.service") == "failed"
    assert h.tables == {"chp_workstation_lockdown"}            # logging never gates the load (N1)
    lk = t("chp-workstation-egress-lockdown.service")
    ex = [ln for ln in lk.splitlines() if ln.startswith("Exec") and "logger" in ln]
    assert ex and all(ln.startswith("ExecStartPre=-") for ln in ex)


def test_lockdown_is_ordered_before_the_network():
    lk = t("chp-workstation-egress-lockdown.service")
    assert re.search(r"^Wants=network-pre\.target$", lk, re.M)
    assert re.search(r"^Before=.*\bnetwork-pre\.target\b", lk, re.M)                    # N2
    assert "DefaultDependencies=no" in lk


def test_a_second_failure_in_the_same_boot_locks_down_again(tmp_path):
    site, hosts = _site()
    bad = [hosts[0]._replace(ip="0.0.0.0"), hosts[1]]
    h = Host(tmp_path, site, bad)
    assert h.start("chp-workstation-egress.service") == "failed" and h.tables == {"chp_workstation_lockdown"}
    h.hosts = hosts                                            # fixed; restart: the egress table, no lock-down
    assert h.start("chp-workstation-egress.service", restart=True) == "active"
    assert h.tables == {"chp_workstation_egress"}
    # later the same boot nft refuses the table (e.g. a damaged shipped file): the lock-down must load again (N3)
    orig = h.cmd
    h.cmd = lambda line: (_ for _ in ()).throw(OSError("nft: syntax")) \
        if line.startswith("/usr/sbin/nft -f /etc/nftables/chp-workstation-egress") else orig(line)
    assert h.start("chp-workstation-egress.service", restart=True) == "failed"
    assert "chp_workstation_lockdown" in h.tables


# ---------- Plan 3 Task 9: monitor check 83 on the workstation (carry 9) ----------
LIVE = ("table inet chp_workstation_egress {\n\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n"
        "\t\toifname \"lo\" accept\n\t\tlimit rate 6/minute log prefix \"CHP-WS-EGRESS \" counter packets %d bytes %d\n"
        "\t\treject with icmpx admin-prohibited\n\t}\n}\n")


def run83(tmp, *, addr=True, enabled="enabled", unit="active", timer="active", live=LIVE % (3, 99),
          expected=LIVE % (0, 0), lockdown=False, installed=True):
    b = tmp / "bin"; b.mkdir(exist_ok=True)
    (b / "rpm").write_text("#!/bin/bash\n" + ('[ "$1 $2" = "-q chp-onlyoffice" ] && exit 0\n' if installed else "")
                           + "exit 1\n")
    (b / "systemctl").write_text("#!/bin/bash\n"
                                 f'[ "$1 $2" = "is-enabled chp-workstation-egress.service" ] && {{ echo {enabled}; exit 0; }}\n'
                                 f'[ "$1 $2" = "is-active chp-workstation-egress.service" ] && {{ echo {unit}; exit 0; }}\n'
                                 f'[ "$1 $2" = "is-active chp-onlyoffice-sweep.timer" ] && {{ echo {timer}; exit 0; }}\n'
                                 "exit 3\n")
    nft = "#!/bin/bash\n"
    nft += ('[ "$4" = chp_workstation_lockdown ] && { echo "table inet chp_workstation_lockdown {}"; exit 0; }\n'
            if lockdown else '[ "$4" = chp_workstation_lockdown ] && exit 1\n')
    nft += (f"cat <<'EOF'\n{live}EOF\n" if live is not None else "exit 1\n")
    (b / "nft").write_text(nft)
    (b / "unshare").write_text("#!/bin/bash\n" + (f"cat <<'EOF'\n{expected}EOF\n" if expected is not None
                                                 else "echo 'nft: syntax error' >&2; exit 1\n"))
    for x in b.iterdir():
        x.chmod(0o755)
    a = tmp / "addr.nft"
    if addr:
        a.write_text("define CHP_WS_SERVER_IP = 192.0.2.10\n")
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_WS_ADDR=str(a), CHP_WS_NFT="/unused")
    r = subprocess.run(["bash", str(D / "monitor.d/83-workstation-editor.sh")], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_check83_ok_when_the_gates_hold(tmp_path):
    out = run83(tmp_path)
    assert out.startswith("OK workstation editor") and "ALERT" not in out


def test_check83_silent_where_the_editor_is_not_installed(tmp_path):
    out = run83(tmp_path, addr=False, enabled="disabled", unit="inactive", timer="inactive", live=None,
                installed=False)
    assert out.startswith("OK chp-onlyoffice not installed") and "ALERT" not in out


def test_check83_installed_without_address_file_alerts(tmp_path):        # Task 9 review M3
    out = run83(tmp_path, addr=False, enabled="disabled", unit="inactive", timer="inactive", live=None)
    assert "address file" in out and "is disabled, not enabled" in out and not out.startswith("OK")
    out = run83(fresh83(tmp_path), addr=False)                             # all else fine, the file gone
    assert [x for x in out.splitlines() if x.startswith("ALERT")] and "address file" in out


def fresh83(tmp_path, n=[0]):
    n[0] += 1
    d = tmp_path / f"r{n[0]}"; d.mkdir(); return d


def test_check83_flags_each_broken_gate(tmp_path):
    cases = [({"unit": "failed"}, "is failed"),
             ({"live": None}, "MISSING"),                                     # nftables.service stop: flush ruleset
             ({"live": LIVE.replace("policy drop", "policy accept") % (0, 0)}, "policy drop"),
             ({"live": LIVE.replace("reject with", "accept\n\t\treject with") % (0, 0)}, "differs from the shipped"),
             ({"expected": None}, "could not be built"),
             ({"lockdown": True}, "EGRESS LOCKDOWN"),
             ({"timer": "inactive"}, "chp-onlyoffice-sweep.timer is inactive")]
    for kw, words in cases:
        out = run83(fresh83(tmp_path), **kw)
        assert "ALERT" in out and words in out and not out.startswith("OK workstation editor"), (kw, out)


def test_check83_counters_moving_is_not_drift(tmp_path):
    assert "ALERT" not in run83(tmp_path, live=LIVE % (12345, 999999))


def test_check83_is_packaged():
    assert re.search(r"^Source\d+:\s+83-workstation-editor\.sh$", SPEC, re.M)
    assert "/usr/lib/chp/monitor.d/83-workstation-editor.sh" in SPEC.replace("%{_prefix}", "/usr")
    assert "monitor.d/83-workstation-editor.sh" in t("build-rpm.sh")
    assert (D / "monitor.d/83-workstation-editor.sh").stat().st_mode & 0o111


# ---------- Plan 3 Task 9: egress-render at start says when it failed (carry 3) and labels the file (carry 10) -----

def test_egress_render_failure_is_one_alertable_line(tmp_path, capsys):
    site, hosts = _site()
    calls = []
    run = lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "", "")
    assert OO.egress_render(tmp_path, lambda: (site, hosts), run=run) == 0
    assert calls == [["restorecon", str(tmp_path / OO.EGRESS_ADDR)]]             # replaced by rename: relabelled
    good = (tmp_path / OO.EGRESS_ADDR).read_text()
    calls.clear()
    assert OO.egress_render(tmp_path, lambda: (site, hosts), run=run) == 0 and calls == []   # unchanged: untouched
    bad = lambda: (site, [hosts[0]._replace(ip="0.0.0.0"), hosts[1]])

    def broken():
        raise SiteError("/etc/chp/site.conf: SERVER line unreadable")
    for load in (bad, broken):
        capsys.readouterr()
        assert OO.egress_render(tmp_path, load, run=run) == 1
        err = capsys.readouterr().err.strip().splitlines()
        assert len(err) == 1 and err[0].startswith("EGRESS RENDER FAILED: ") and "last good" in err[0]
        assert (tmp_path / OO.EGRESS_ADDR).read_text() == good and calls == []
    ev = {"decoder": "x", "location": "journald", "program_name": "chp-workstation-egress", "log": err[0]}
    assert _level(w.NEXTCLOUD_RULES, ev) == (w.WS_RENDER_RULE, 7)


def test_egress_unit_logs_under_the_rules_program_name():
    u = t("chp-workstation-egress.service")
    assert re.search(r"^SyslogIdentifier=chp-workstation-egress$", u, re.M)
