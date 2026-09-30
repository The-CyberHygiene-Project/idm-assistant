# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site command line: validate | pre | export-client."""
import argparse
import os
import sys
from pathlib import Path

from . import VERSION
from .clientconf import cert_sha256, make_client_conf, parse_client_conf, ssh_fpr
from .hosts import lookup, parse_hosts
from . import render as _render
from .sitevars import values
from .sitefile import SiteError, parse_site, read_file


def _validate(a):
    d = Path(a.site)
    site = parse_site(read_file(d / "site.conf", "site.conf"))
    hosts = parse_hosts(read_file(d / "hosts", "hosts table"), site)
    host = lookup(hosts, a.mac) if a.mac else None
    client = a.role == "client" or (host is not None and host.role == "client")
    if client or (d / "client.conf").exists():         # spec 4.2: a client site needs a valid client.conf
        parse_client_conf(read_file(d / "client.conf", "client.conf (run `chp-site export-client` on the server)"), site)
    msg = f"OK: {site['DOMAIN']}, {len(hosts)} hosts, server {next(h.hostname for h in hosts if h.role == 'server')}"
    if host:
        h = host
        if a.role and h.role != a.role:
            raise SiteError(f"{h.hostname} is a {h.role}, not a {a.role}")
        msg += f"; this machine is {h.hostname} ({h.role}, {h.ip})"
    print(msg)


def _load(site_dir):
    d = Path(site_dir)
    site = parse_site(read_file(d / "site.conf", "site.conf"))
    return site, parse_hosts(read_file(d / "hosts", "hosts table"), site)


def _get(a):
    site, hosts = _load(a.site)
    v = values(site, hosts)
    if a.key not in v:
        raise SiteError(f"unknown key {a.key} (known: {', '.join(sorted(v))})")
    print(v[a.key])


def _render_cmd(a):
    import time
    site, hosts = _load(a.site)
    out = {"zone": lambda: _render.zone(site, hosts, int(time.strftime("%Y%m%d")) * 100 + 1),
           "named-conf": lambda: _render.named_conf(site, hosts),
           "kanidm-server": lambda: _render.kanidm_server_toml(site, hosts),
           "kanidm-config": lambda: _render.kanidm_client_config(site),
           "collect-conf": lambda: _render.collect_conf(site)}
    if a.what not in out:
        raise SiteError(f"unknown render target {a.what} (known: {', '.join(out)})")
    sys.stdout.write(out[a.what]())


def _pre(a):
    from .facts import live
    from .pre import run_pre
    h = run_pre(a.role, Path(a.stick), Path(a.out), a.repo_url, live())
    print(f"CHP: installing {h.hostname} ({h.role}, {h.ip}). Recovery secrets were written to the site stick: "
          "keep it offline from now on.")


def _export(a):
    import subprocess
    import tempfile
    import time
    from .escrow import move_pending
    site = parse_site(read_file(Path(a.site), "site.conf"))
    hosts = parse_hosts(read_file(Path(a.site).parent / "hosts", "hosts table"), site)
    pem, pub = Path(a.root).read_text(), Path(a.ssh_ca).read_text()
    text = make_client_conf(site["DOMAIN"], pem, pub)
    mnt = None
    stick = Path(a.stick) if a.stick else None
    if stick is None:                                   # the site stick, found by its label, mounted just for this
        dev = Path("/dev/disk/by-label/OEMDRV")
        if not dev.exists():
            raise SiteError("no site stick found (a USB volume labelled OEMDRV): plug it in, or pass --stick DIR")
        mnt = tempfile.mkdtemp(prefix="chp-stick-", dir="/run")
        subprocess.run(["mount", str(dev), mnt], check=True)
        stick = Path(mnt)
    try:
        (stick / "client.conf").write_text(text)
        print(f"wrote {stick / 'client.conf'}\nCA root SHA-256: {cert_sha256(pem)}\nSSH CA fingerprint: {ssh_fpr(pub)}\n"
              "Compare both with the server console before installing clients.")
        pending = Path(a.pending)
        moved = move_pending(pending, stick, values(site, hosts)["SERVER_HOSTNAME"],
                             time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())) if pending.is_dir() else []
        print("moved to the stick: " + ", ".join(moved) + " (shredded on this server)" if moved else "no pending server secrets")
    finally:
        if mnt:
            subprocess.run(["sync"]); subprocess.run(["umount", mnt]); os.rmdir(mnt)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="chp-site")
    ap.add_argument("--version", action="version", version=f"chp-site {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate"); v.add_argument("--site", required=True)
    v.add_argument("--role", choices=("server", "client")); v.add_argument("--mac", nargs="*")
    p = sub.add_parser("pre"); p.add_argument("--role", required=True, choices=("server", "client"))
    p.add_argument("--stick", required=True); p.add_argument("--out", required=True)
    p.add_argument("--repo-url", default="file:///run/install/repo/chp")
    g = sub.add_parser("get"); g.add_argument("key"); g.add_argument("--site", default="/etc/chp")
    r = sub.add_parser("render"); r.add_argument("what"); r.add_argument("--site", default="/etc/chp")
    e = sub.add_parser("export-client"); e.add_argument("--stick")
    e.add_argument("--pending", default="/root/chp-escrow-pending")
    e.add_argument("--site", default="/etc/chp/site.conf"); e.add_argument("--root", default="/etc/step-ca/certs/root_ca.crt")
    e.add_argument("--ssh-ca", default="/etc/ssh-ca/user_ca.pub")
    a = ap.parse_args(argv)
    try:
        {"validate": _validate, "pre": _pre, "export-client": _export, "get": _get, "render": _render_cmd}[a.cmd](a)
    except SiteError as err:
        print(f"chp-site: {err}", file=sys.stderr)
        return 2
    except FileNotFoundError as err:
        print(f"chp-site: missing file: {err.filename}", file=sys.stderr)
        return 2
    return 0


def run():
    """zipapp entry point: zipapp's generated __main__ ignores main()'s return value, so exit here."""
    sys.exit(main())


if __name__ == "__main__":
    run()
