# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""The %pre gate: validate EVERYTHING, then write the escrow to the stick, then write the kickstart snippets.
Any failure raises SiteError before a disk is touched; the install never proceeds without its recovery secrets."""
import os
import re
import secrets
import subprocess
from pathlib import Path

from .clientconf import parse_client_conf
from .disks import choose_disk
from .facts import Facts  # noqa: F401  (re-exported for callers and tests)
from .hosts import lookup, parse_hosts
from .render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
from .sitefile import SiteError, parse_site, read_file

TOKEN_RE = r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"   # a Kanidm API token (JWS)


def sha512_crypt(pw):
    """SHA-512 crypt for rootpw --iscrypted. `crypt` exists on EL9's Python 3.9 (it was removed in 3.13); fall back to
    openssl, which is on every EL9 host and in the installer."""
    try:
        import crypt  # noqa: PLC0415
        return crypt.crypt(pw, crypt.mksalt(crypt.METHOD_SHA512))
    except ImportError:
        return subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=pw, capture_output=True, text=True,
                              check=True).stdout.strip()


def run_pre(role, stick, out, repo_url, facts, hasher=sha512_crypt, secret=secrets.token_urlsafe, stick_id=None):
    stick, out = Path(stick), Path(out)
    site = parse_site(read_file(stick / "site.conf", "site.conf"))
    hosts = parse_hosts(read_file(stick / "hosts", "hosts table"), site)
    host = lookup(hosts, facts.macs)
    if host.role != role:
        raise SiteError(f"you booted the {role} installer, but the hosts table says {host.hostname} is a {host.role}")
    token = None
    if role == "client":
        parse_client_conf(read_file(stick / "client.conf", "client.conf (run `chp-site export-client` on the server)"), site)
        tp = stick / "tokens" / f"{host.hostname}.token"
        if not tp.is_file():
            raise SiteError(f"no unixd token for {host.hostname} on the site stick: on the server run "
                            f"`chp-site client-token {host.hostname}` then `chp-site export-client`")
        token = read_file(tp, f"unixd token for {host.hostname}").strip()
        if not re.fullmatch(TOKEN_RE, token):
            raise SiteError(f"tokens/{host.hostname}.token is not a Kanidm API token")
    disk = choose_disk(facts.disks, host.disk)
    # --- everything is valid: now the secrets, escrow first ---
    luks, rootpw = secret(32), secret(18)
    esc_dir, esc = stick / "escrow", stick / "escrow" / f"{host.hostname}.txt"
    try:
        esc_dir.mkdir(exist_ok=True)
        if esc.exists():
            esc.rename(esc_dir / f"{host.hostname}.txt.{facts.now}.old")
        esc.write_text(f"# {host.hostname}.{site['DOMAIN']}  written at install start {facts.now}\n"
                       "# These secrets are valid only if a line 'INSTALL COMPLETED' follows (added by the installer's\n"
                       "# last step). Without it the install stopped early: the disk still has the secrets in the newest\n"
                       "# *.old file that does say INSTALL COMPLETED.\n"
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
    (out / "escrow-name").write_text(host.hostname)     # not secret: tells %post --nochroot which file to mark
    if stick_id:        # the site stick's USB identity, pinned so only THIS stick is ever allowed post-install
        (out / "site-stick.id").write_text("".join(f"{k}={stick_id.get(k, '')}\n" for k in ("ID", "SERIAL", "NAME")))
    # The passphrase once more, for %post --nochroot only (it adds the one-time TPM-bind key, then shreds this file).
    fd = os.open(out / "luks-pass", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(luks)
    if token is not None:    # this client's OWN unixd token, for %post --nochroot (installs it 0600, then shreds this)
        fd = os.open(out / "unixd.token", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)
    return host
