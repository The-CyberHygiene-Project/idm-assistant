# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site command line: validate | pre | export-client."""
import argparse
import sys
from pathlib import Path

from . import VERSION
from .clientconf import cert_sha256, make_client_conf, parse_client_conf, ssh_fpr
from .hosts import lookup, parse_hosts
from .sitefile import SiteError, parse_site


def _validate(a):
    d = Path(a.site)
    site = parse_site((d / "site.conf").read_text(encoding="utf-8"))
    hosts = parse_hosts((d / "hosts").read_text(encoding="utf-8"), site)
    if (d / "client.conf").exists():
        parse_client_conf((d / "client.conf").read_text(encoding="utf-8"), site)
    msg = f"OK: {site['DOMAIN']}, {len(hosts)} hosts, server {next(h.hostname for h in hosts if h.role == 'server')}"
    if a.mac:
        h = lookup(hosts, a.mac)
        if a.role and h.role != a.role:
            raise SiteError(f"{h.hostname} is a {h.role}, not a {a.role}")
        msg += f"; this machine is {h.hostname} ({h.role}, {h.ip})"
    print(msg)


def _pre(a):
    from .facts import live
    from .pre import run_pre
    h = run_pre(a.role, Path(a.stick), Path(a.out), a.repo_url, live())
    print(f"CHP: installing {h.hostname} ({h.role}, {h.ip}). Recovery secrets were written to the site stick: "
          "keep it offline from now on.")


def _export(a):
    site = parse_site(Path(a.site).read_text(encoding="utf-8"))
    pem, pub = Path(a.root).read_text(), Path(a.ssh_ca).read_text()
    text = make_client_conf(site["DOMAIN"], pem, pub)
    (Path(a.stick) / "client.conf").write_text(text)
    print(f"wrote {Path(a.stick) / 'client.conf'}\nCA root SHA-256: {cert_sha256(pem)}\nSSH CA fingerprint: {ssh_fpr(pub)}\n"
          "Compare both with the server console before installing clients.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="chp-site")
    ap.add_argument("--version", action="version", version=f"chp-site {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate"); v.add_argument("--site", required=True)
    v.add_argument("--role", choices=("server", "client")); v.add_argument("--mac", nargs="*")
    p = sub.add_parser("pre"); p.add_argument("--role", required=True, choices=("server", "client"))
    p.add_argument("--stick", required=True); p.add_argument("--out", required=True)
    p.add_argument("--repo-url", default="file:///run/install/repo/chp")
    e = sub.add_parser("export-client"); e.add_argument("--stick", required=True)
    e.add_argument("--site", default="/etc/chp/site.conf"); e.add_argument("--root", default="/etc/step-ca/certs/root_ca.crt")
    e.add_argument("--ssh-ca", default="/etc/ssh-ca/user_ca.pub")
    a = ap.parse_args(argv)
    try:
        {"validate": _validate, "pre": _pre, "export-client": _export}[a.cmd](a)
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
