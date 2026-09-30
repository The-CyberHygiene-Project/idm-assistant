# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The %pre gate: validate EVERYTHING, then write the escrow to the stick, then write the kickstart snippets.
Any failure raises SiteError before a disk is touched; the install never proceeds without its recovery secrets."""
import os
import secrets
import subprocess
from pathlib import Path

from .clientconf import parse_client_conf
from .disks import choose_disk
from .facts import Facts  # noqa: F401  (re-exported for callers and tests)
from .hosts import lookup, parse_hosts
from .render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
from .sitefile import SiteError, parse_site


def sha512_crypt(pw):
    """SHA-512 crypt for rootpw --iscrypted. `crypt` exists on EL9's Python 3.9 (it was removed in 3.13); fall back to
    openssl, which is on every EL9 host and in the installer."""
    try:
        import crypt  # noqa: PLC0415
        return crypt.crypt(pw, crypt.mksalt(crypt.METHOD_SHA512))
    except ImportError:
        return subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=pw, capture_output=True, text=True,
                              check=True).stdout.strip()


def _read(p, what):
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SiteError(f"the site stick has no {what} ({p.name})") from None


def run_pre(role, stick, out, repo_url, facts, hasher=sha512_crypt, secret=secrets.token_urlsafe):
    stick, out = Path(stick), Path(out)
    site = parse_site(_read(stick / "site.conf", "site.conf"))
    hosts = parse_hosts(_read(stick / "hosts", "hosts table"), site)
    host = lookup(hosts, facts.macs)
    if host.role != role:
        raise SiteError(f"you booted the {role} installer, but the hosts table says {host.hostname} is a {host.role}")
    if role == "client":
        parse_client_conf(_read(stick / "client.conf", "client.conf (run `chp-site export-client` on the server)"), site)
    disk = choose_disk(facts.disks, host.disk)
    # --- everything is valid: now the secrets, escrow first ---
    luks, rootpw = secret(32), secret(18)
    esc_dir, esc = stick / "escrow", stick / "escrow" / f"{host.hostname}.txt"
    try:
        esc_dir.mkdir(exist_ok=True)
        if esc.exists():
            esc.rename(esc_dir / f"{host.hostname}.txt.{facts.now}.old")
        esc.write_text(f"# {host.hostname}.{site['DOMAIN']}  installed {facts.now}\n"
                       "# KEEP THIS STICK OFFLINE: it now holds this host's recovery secrets.\n"
                       f"LUKS_PASSPHRASE={luks}\nROOT_CONSOLE_PASSWORD={rootpw}\n")
        os.sync()
    except OSError as e:
        raise SiteError(f"cannot write the escrow file to the site stick ({e.strerror}); is the stick read-only "
                        "or full? The install stops: it never proceeds without its recovery secrets") from None
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, text in (("misc", misc_ks(site)), ("net", net_ks(site, host, hosts)), ("users", users_ks(site, hasher(rootpw))),
                       ("disk", disk_ks(disk, luks)), ("repo", repo_ks(repo_url))):
        p = out / f"{name}.ks"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
    return host
