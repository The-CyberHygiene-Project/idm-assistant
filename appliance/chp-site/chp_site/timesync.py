# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site time-sync --role server|client (root; ISO 0.7.0 Task 12, owner decision 2026-11-20: "workstations sync
with the server, never outside sources"). Idempotent; first boot runs it (server-firstboot's `time` step, client-
enrol's `time` step), and it can be run again at any time.

  server  keeps its own sources (NTP_UPSTREAM, written by Anaconda's timesource), and serves time to the site subnet
          only: `allow <SUBNET>` (every other allow line is switched off, so never 0.0.0.0/0 or a bare `allow`),
          `local stratum 10` (the LAN keeps one clock if the upstream fails; the monitor's clock check still alerts on
          the server's own offset), and the CUI profile's client-only `port 0` switched off (chronyd must listen on
          123). firewalld gets ONE rich rule: 123/udp from the site subnet only. This is the owner-approved exception
          to "no new network port" (0.7.0 guide); OpenSCAP's chronyd_client_only fails on the server by design.
  client  takes time from the CHP server only: every server/pool/peer/sourcedir/refclock line is switched off and one
          `server <SERVER_IP> <options>` is written (the options the CUI profile gave the old server line, e.g.
          `iburst maxpoll 16`); allow and local lines are switched off; `port 0` stays (client only). The workstation
          egress table (chp-onlyoffice) lets chronyd reach the server's 123/udp only.

Switched-off lines stay in the file as `#chp-time-sync# <line>`; the written lines sit between BEGIN/END markers and
are rewritten on every run, so a second run changes nothing. chronyd is restarted only when the file changed."""
import ipaddress
import os
import subprocess
from pathlib import Path

from .hosts import server_of
from .sitefile import SiteError

CONF = "etc/chrony.conf"
OFF = "#chp-time-sync# "
BEGIN = "# BEGIN chp-site time-sync (owner decision 2026-11-20: workstations take time from the CHP server only)"
END = "# END chp-site time-sync"
SOURCES = ("server", "pool", "peer", "sourcedir", "refclock")
LOCAL_STRATUM = "local stratum 10"
ROLES = ("server", "client")


def _cidr(site):
    net = ipaddress.ip_network(str(site["SUBNET"]), strict=True)
    if net.version != 4 or net.prefixlen < 8:
        raise SiteError(f"SUBNET {net} cannot be the time service's client network")
    return str(net)


def rich_rule(site):
    return f'rule family="ipv4" source address="{_cidr(site)}" port port="123" protocol="udp" accept'


def _words(line):
    s = line.split("#", 1)[0].strip()
    return s.split() if s else []


def chrony_text(text, role, site, hosts):
    """chrony.conf for this role (see the module notes)."""
    if role not in ROLES:
        raise SiteError(f"time-sync: the role is server or client, not {role!r}")
    out, opts, kept, inside = [], None, None, False
    for line in text.splitlines():
        if line.strip() == BEGIN:
            inside = True
            continue
        if inside:
            if line.strip() == END:
                inside = False
            w = _words(line)
            if w[:1] == ["server"] and len(w) > 2:
                kept = " ".join(w[2:])                     # a re-run keeps the options it wrote the first time
            continue
        w = _words(line)
        key = w[0].lower() if w else ""
        off = False
        if role == "client" and key in SOURCES:
            if opts is None and key == "server" and len(w) > 2:
                opts = " ".join(w[2:])
            off = True
        elif key == "allow" or (key == "local" and role == "client"):
            off = True                                     # the server's allow is written below; clients serve nobody
        elif role == "server" and key == "port" and w[1:] == ["0"]:
            off = True                                     # the CUI profile's client-only setting: the server serves
        elif role == "server" and key == "local":
            off = True                                     # written below
        out.append(OFF + line if off else line)
    if inside:
        raise SiteError(f"chrony.conf has the time-sync block start without its end line ({END}): fix the file by "
                        "hand, then run chp-site time-sync again")
    while out and not out[-1].strip():
        out.pop()
    if role == "server":
        block = [f"allow {_cidr(site)}", LOCAL_STRATUM]
    else:
        block = [f"server {server_of(hosts).ip} {opts or kept or 'iburst'}"]
    return "\n".join(out + ["", BEGIN] + block + [END]) + "\n"


def _restorecon(run, path):
    run(["restorecon", str(path)], check=False)


def apply(root, role, site, hosts, run=subprocess.run):
    """Write chrony.conf for the role (atomically, keeping its mode and SELinux label), restart chronyd when it
    changed, and on the server add the firewalld rule once. Returns the lines to print."""
    p = Path(root) / CONF
    try:
        old = p.read_text()
    except OSError as e:
        raise SiteError(f"cannot read {p}: {e.strerror or e}") from None
    new = chrony_text(old, role, site, hosts)
    done = []
    if new != old:
        mode = p.stat().st_mode & 0o7777
        tmp = p.with_name(p.name + ".chp-tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(new)
        os.chmod(tmp, mode)
        os.replace(tmp, p)
        _restorecon(run, p)
        run(["systemctl", "restart", "chronyd"], check=True)
        done.append(f"/{CONF}: written for the {role}; chronyd restarted")
    else:
        done.append(f"/{CONF}: unchanged")
    if role == "server":
        rule = rich_rule(site)
        have = run(["firewall-cmd", "--permanent", "--list-rich-rules"], capture_output=True, text=True).stdout or ""
        if rule not in have.splitlines():
            run(["firewall-cmd", "-q", "--permanent", "--add-rich-rule", rule], check=True)
            run(["firewall-cmd", "-q", "--reload"], check=True)
        done.append(f"time service: the site subnet {_cidr(site)} only (123/udp; owner-approved exception)")
    else:
        done.append(f"time source: the CHP server {server_of(hosts).ip} only")
    return done
