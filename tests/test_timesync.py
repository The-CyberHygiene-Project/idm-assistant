"""Task 12 (owner decision 2026-11-20): workstations take time from the CHP server only. chp-site time-sync edits
chrony.conf for the host's role (the server serves the site subnet only; a client uses the server only) and, on the
server, opens 123/udp to the site subnet only in firewalld. Made-up values only."""
import re

import pytest

from chp_site import timesync as T
from chp_site.hosts import parse_hosts
from chp_site.sitefile import SiteError, parse_site
from tests.test_chp_site_sitefile import GOOD

SITE = parse_site(GOOD)                                    # SUBNET 192.168.100.0/24, NTP_UPSTREAM 192.168.100.1
HOSTS = parse_hosts("52:54:00:00:00:30 srv1 192.168.100.30 server\n52:54:00:00:00:31 cli1 192.168.100.31 client\n",
                    SITE)
# /etc/chrony.conf as Anaconda (timesource) and the CUI profile's remediation leave it (shape of Rocky 9's file)
HARDENED = """# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (https://www.pool.ntp.org/join.html).
server 192.168.100.1 iburst maxpoll 16

# Use NTP servers from DHCP.
sourcedir /run/chrony-dhcp

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3

# Allow NTP client access from local network.
#allow 192.168.0.0/16

keyfile /etc/chrony.keys
ntsdumpdir /var/lib/chrony
leapsectz right/UTC
logdir /var/log/chrony
port 0
cmdport 0
"""
RULE = 'rule family="ipv4" source address="192.168.100.0/24" port port="123" protocol="udp" accept'


def live(text):
    return [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]


def test_server_serves_the_site_subnet_only():
    out = T.chrony_text(HARDENED, "server", SITE, HOSTS)
    got = live(out)
    assert "server 192.168.100.1 iburst maxpoll 16" in got           # its own source stays NTP_UPSTREAM
    assert [x for x in got if x.split()[0] == "allow"] == ["allow 192.168.100.0/24"]
    assert "port 0" not in got and "cmdport 0" in got                # it must listen on 123; chronyc stays local
    assert "local stratum 10" in got                                 # the LAN keeps one clock if the upstream fails
    assert T.chrony_text(out, "server", SITE, HOSTS) == out          # idempotent


@pytest.mark.parametrize("bad", ["allow", "allow all", "allow 0.0.0.0/0", "allow 0/0", "allow ::/0",
                                 "allow 10.0.0.0/8", "deny all\nallow"])
def test_server_never_allows_beyond_the_subnet(bad):
    out = T.chrony_text(HARDENED + bad + "\n", "server", SITE, HOSTS)
    assert [x for x in live(out) if x.split()[0] == "allow"] == ["allow 192.168.100.0/24"], out


def test_client_uses_the_server_only():
    out = T.chrony_text(HARDENED, "client", SITE, HOSTS)
    got = live(out)
    sources = [x for x in got if x.split()[0] in ("server", "pool", "peer", "sourcedir", "refclock")]
    assert sources == ["server 192.168.100.30 iburst maxpoll 16"]   # the server; the options the CUI profile set
    assert "port 0" in got and "cmdport 0" in got                    # still client-only
    assert not any(x.split()[0] in ("allow", "local") for x in got)
    assert T.chrony_text(out, "client", SITE, HOSTS) == out
    # pool lines, peers, DHCP sources and other servers are all switched off
    many = "pool 2.rocky.pool.ntp.org iburst\nserver time.example.test\npeer 192.168.100.9\nallow 192.168.100.0/24\n"
    out = T.chrony_text(many + HARDENED, "client", SITE, HOSTS)
    got = live(out)
    assert [x for x in got if x.split()[0] in ("server", "pool", "peer", "sourcedir")] == \
        ["server 192.168.100.30 iburst maxpoll 16"]
    assert not any(x.split()[0] == "allow" for x in got)
    # no server line at all: iburst only
    out = T.chrony_text("driftfile /var/lib/chrony/drift\nport 0\n", "client", SITE, HOSTS)
    assert "server 192.168.100.30 iburst" in live(out)


def test_role_is_checked():
    with pytest.raises(SiteError):
        T.chrony_text(HARDENED, "router", SITE, HOSTS)


class Run:
    def __init__(self, rules=""):
        self.calls, self.rules = [], rules

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)

        class R:
            returncode, stdout, stderr = 0, "", ""
        if argv[:3] == ["firewall-cmd", "--permanent", "--list-rich-rules"]:
            R.stdout = self.rules
        if argv[:2] == ["firewall-cmd", "-q"] and "--add-rich-rule" in argv:
            self.rules += argv[-1] + "\n"
        return R()


def setup(tmp_path, text=HARDENED):
    c = tmp_path / "etc/chrony.conf"
    c.parent.mkdir(parents=True)
    c.write_text(text)
    c.chmod(0o644)
    return c


def test_apply_server_writes_restarts_and_opens_123_to_the_subnet_once(tmp_path):
    c = setup(tmp_path)
    run = Run()
    lines = T.apply(tmp_path, "server", SITE, HOSTS, run=run)
    assert "allow 192.168.100.0/24" in c.read_text() and (c.stat().st_mode & 0o777) == 0o644
    assert ["restorecon", str(c)] in run.calls
    assert ["systemctl", "restart", "chronyd"] in run.calls
    adds = [x for x in run.calls if "--add-rich-rule" in x]
    assert adds == [["firewall-cmd", "-q", "--permanent", "--add-rich-rule", RULE]]
    assert ["firewall-cmd", "-q", "--reload"] in run.calls
    assert not any("--add-service" in x or "--add-port" in x for x in run.calls)   # never the whole world
    assert any("123/udp" in x and "192.168.100.0/24" in x for x in lines)
    # a second run changes nothing and restarts nothing
    run2 = Run(rules=run.rules)
    T.apply(tmp_path, "server", SITE, HOSTS, run=run2)
    assert ["systemctl", "restart", "chronyd"] not in run2.calls
    assert not any("--add-rich-rule" in x for x in run2.calls)


def test_apply_client_points_at_the_server_and_opens_nothing(tmp_path):
    c = setup(tmp_path)
    run = Run()
    T.apply(tmp_path, "client", SITE, HOSTS, run=run)
    assert "server 192.168.100.30 iburst maxpoll 16" in live(c.read_text())
    assert ["systemctl", "restart", "chronyd"] in run.calls
    assert not any(x[0] == "firewall-cmd" for x in run.calls)


def test_cli_time_sync(tmp_path, monkeypatch, capsys):
    from chp_site import cli
    seen = {}
    monkeypatch.setattr(T, "apply", lambda root, role, site, hosts, run=None: seen.update(role=role) or ["ok"])
    monkeypatch.setattr(cli, "_load", lambda d: (SITE, HOSTS))
    monkeypatch.setattr(cli, "_host", lambda: "cli1")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert cli.main(["time-sync", "--role", "client"]) == 0 and seen == {"role": "client"}
    seen.clear()
    assert cli.main(["time-sync", "--role", "server"]) == 2 and not seen        # cli1 is a client in the hosts table
    assert "client in the hosts table" in capsys.readouterr().err
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["time-sync", "--role", "client"]) == 2 and not seen
    with pytest.raises(SystemExit):
        cli.main(["time-sync", "--role", "router"])


def test_guide_and_known_issues_record_the_exception():
    from pathlib import Path
    top = Path(__file__).resolve().parents[1]
    g = (top / "appliance/site-stick-kit/SITE-STICK.md").read_text()
    s = g[g.index("### From 0.7.0 on: time from the CHP server"):g.index("### From 0.7.0 on: controlled documents")]
    flat = " ".join(s.split())
    for need in ("123/udp", "SUBNET", "owner", "exception", "no new network port", "chronyd_client_only",
                 "chp-site time-sync --role server", "chp-site time-sync --role client", "check 20",
                 RULE.replace("192.168.100.0/24", "<SUBNET>")):
        assert need in flat, need
    k = " ".join((top / "docs/release/0.7.0-known-issues.md").read_text().split())
    assert "Time comes from the CHP server" in k and "chronyd_client_only" in k and "123/udp" in k


def test_firstboot_scripts_run_time_sync_for_their_role():
    from pathlib import Path
    top = Path(__file__).resolve().parents[1]
    srv = (top / "appliance/rpm/chp-identity-server/server-firstboot.sh").read_text()
    assert "do_time() { chp-site time-sync --role server; }" in srv
    assert srv.index("step bind do_bind") < srv.index("step time do_time") < srv.index("step self-client do_self_client")
    cli_ = (top / "appliance/rpm/chp-identity-client/client-enrol.sh").read_text()
    m = re.search(r"do_time\(\) \{\n(.*?)\n\}", cli_, re.S)
    assert m and '[ "$ROLE" = client ] || return 0' in m.group(1) and "chp-site time-sync --role client" in m.group(1)
    assert cli_.index("step time do_time") < cli_.index("step trust do_trust")   # the clock first, then TLS
