# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The hosts table: '<MAC> <hostname> <IP> <server|client> [disk]' per line; lookup by the machine's own MACs."""
import ipaddress
import re
from collections import namedtuple

from .sitefile import LABEL_RE, SiteError

Host = namedtuple("Host", "mac hostname ip role disk")
_DISK = r"(?:sd[a-z]{1,2}|vd[a-z]{1,2}|nvme\d+n\d+|/dev/disk/by-id/[A-Za-z0-9._:+-]+)"


def norm_mac(s):
    h = re.sub(r"[:-]", "", s.strip().lower())
    if not re.fullmatch(r"[0-9a-f]{12}", h) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", s.strip()):
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def parse_hosts(text, site):
    if text.startswith("﻿"):
        text = text[1:]
    net, gw = site["SUBNET"], site["GATEWAY"]
    hosts, seen = [], {"MAC": set(), "hostname": set(), "IP": set()}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        f = line.split()
        if len(f) not in (4, 5):
            raise SiteError(f"hosts line {n}: expected 4 or 5 fields (MAC hostname IP role [disk]), got {len(f)}")
        mac = norm_mac(f[0])
        if not mac:
            raise SiteError(f"hosts line {n}: {f[0]!r} is not a MAC address")
        if not re.fullmatch(LABEL_RE, f[1]):
            raise SiteError(f"hosts line {n}: hostname {f[1]!r} must be one lower-case DNS label")
        try:
            ip = ipaddress.IPv4Address(f[2])
        except ValueError:
            raise SiteError(f"hosts line {n}: {f[2]!r} is not an IPv4 address") from None
        if ip not in net:
            raise SiteError(f"hosts line {n}: {ip} is outside SUBNET {net}")
        if ip == gw:
            raise SiteError(f"hosts line {n}: {ip} is the GATEWAY")
        if ip in (net.network_address, net.broadcast_address):
            raise SiteError(f"hosts line {n}: {ip} is the network or broadcast address")
        if f[3] not in ("server", "client"):
            raise SiteError(f"hosts line {n}: role must be server or client, got {f[3]!r}")
        disk = f[4] if len(f) == 5 else ""
        if disk and not re.fullmatch(_DISK, disk):
            raise SiteError(f"hosts line {n}: disk {disk!r} must be sdX, vdX, nvmeNnM or /dev/disk/by-id/...")
        for what, val in (("MAC", mac), ("hostname", f[1]), ("IP", str(ip))):
            if val in seen[what]:
                raise SiteError(f"hosts line {n}: {what} {val} appears twice")
            seen[what].add(val)
        hosts.append(Host(mac, f[1], str(ip), f[3], disk))
    if sum(h.role == "server" for h in hosts) != 1:
        raise SiteError("hosts: there must be exactly one server")
    return hosts


def server_of(hosts):
    return next(h for h in hosts if h.role == "server")


def lookup(hosts, macs):
    mine = {norm_mac(m) for m in macs} - {None}
    hit = [h for h in hosts if h.mac in mine]
    if not hit:
        raise SiteError("this machine is not in the hosts table (its MACs: " + ", ".join(sorted(mine)) + ")")
    if len(hit) > 1:
        raise SiteError("this machine matches more than one hosts line: " + ", ".join(h.hostname for h in hit))
    return hit[0]
