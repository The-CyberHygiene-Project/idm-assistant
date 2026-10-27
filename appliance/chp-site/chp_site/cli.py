# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site command line: validate | pre | verify-repo | get | render | export-client | onboard | revoke | unexpire |
aide-accept | aide-pin | aide-verify-pin | stick-pin-hash | docs | security | alerts | wazuh-forward."""
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
    from .profilecheck import check
    extra = check(d, None)                                # profile.ini on the stick, when present (chp-templates rules)
    print(msg + (f"\n{extra}" if extra else ""))


def _load(site_dir):
    d = Path(site_dir)
    site = parse_site(read_file(d / "site.conf", "site.conf"))
    return site, parse_hosts(read_file(d / "hosts", "hosts table"), site)


def _get(a):
    site, hosts = _load(a.site)
    cc = Path(a.site) / "client.conf"
    client = parse_client_conf(read_file(cc, "client.conf"), site) if cc.exists() else None
    v = values(site, hosts, client)
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
    from .facts import live, stick_identity
    from .pre import run_pre
    h = run_pre(a.role, Path(a.stick), Path(a.out), a.repo_url, live(), stick_id=stick_identity())
    print(f"CHP: installing {h.hostname} ({h.role}, {h.ip}). Recovery secrets were written to the site stick: "
          "keep it offline from now on.")


def _verify_repo(a):
    from . import reposig
    fpr = reposig.verify(a.url, reposig.bundled_key())
    print(f"REPO SIGNATURE OK: {a.url} (signed by {fpr})")


def _export(a):
    site = parse_site(read_file(Path(a.site), "site.conf"))
    hosts = parse_hosts(read_file(Path(a.site).parent / "hosts", "hosts table"), site)
    pem, pub = Path(a.root).read_text(), Path(a.ssh_ca).read_text()
    text = make_client_conf(site["DOMAIN"], pem, pub, Path(a.cache_key).read_text())
    from .usbstick import site_stick
    with site_stick(a.stick) as s:                      # USBGuard: ONLY the pinned stick, temporarily; always re-blocked
        _export_to(a, site, hosts, text, pem, pub, s)


def _export_to(a, site, hosts, text, pem, pub, stick):
    import time
    from .escrow import move_pending, move_tokens
    (stick / "client.conf").write_text(text)
    print(f"wrote {stick / 'client.conf'}\nCA root SHA-256: {cert_sha256(pem)}\nSSH CA fingerprint: {ssh_fpr(pub)}\n"
          "Compare both with the server console before installing clients.")
    pending = Path(a.pending)
    moved = move_pending(pending, stick, values(site, hosts)["SERVER_HOSTNAME"],
                         time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())) if pending.is_dir() else []
    print("moved to the stick: " + ", ".join(moved) + " (shredded on this server)" if moved else "no pending server secrets")
    toks = move_tokens(pending / "tokens", stick, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())) \
        if (pending / "tokens").is_dir() else []
    print("tokens moved to the stick: " + ", ".join(toks) if toks else "no client tokens pending")
    from . import aide
    base = aide.read_record(aide.STATE / "baseline")
    if base.get("DB_SHA512"):
        p = aide.write_pin(stick, values(site, hosts)["SERVER_HOSTNAME"], base, time.time())
        aide.write_record(aide.STATE / "pinned", {"DB_SHA512": base["DB_SHA512"]}, 0o644)
        print(f"AIDE baseline pinned: aide/{p.name}")
    else:
        print("no AIDE baseline yet (built just after first boot); pin it later: chp-site aide-pin")


def _ops_env(a):
    from .kanidm import Kanidm
    from .sshca import SshCa
    site, hosts = _load(a.site)
    return site, hosts, Kanidm(a.as_), SshCa()


def _onboard(a):
    from .ops import onboard
    site, _hosts, k, ca = _ops_env(a)
    key = Path(a.ssh_key).read_text() if a.ssh_key else None
    items = onboard(k, ca, a.user, site["DOMAIN"], display=a.display, groups=tuple(a.group), ssh_key=key,
                    replace_key=a.replace_key)
    print(f"onboarding checklist for {a.user}:")
    for item, done, note in items:
        print(f"  [{'x' if done else ' '}] {item}" + (f"  ({note})" if note else ""))


def _revoke(a):
    from .ops import revoke
    _site, hosts, k, ca = _ops_env(a)
    revoke(k, ca, hosts, a.user, group=a.group)


def _unexpire(a):
    from .ops import unexpire
    site, hosts, k, ca = _ops_env(a)
    unexpire(k, ca, site, hosts, a.user, a.approver, a.reason)


def _client_token(a):
    from .ops import client_token
    _site, hosts, k, _ca = _ops_env(a)
    p = client_token(k, hosts, a.host)
    print(f"token for {a.host} written to {p}; now run chp-site export-client with the site stick")


def _authselect_patch(a):
    from .authselect import main as patch
    from .authselect_ga import main as patch_ga
    patch(a.dir)
    patch_ga(a.dir)
    print(f"patched {a.dir}: pam_kanidm placed jump-safe; Google Authenticator before it for Kanidm users (local "
          "accounts skip it); kanidm first on passwd, group, initgroups")


def _pam_test(a):
    import re as _re
    from . import pamtest
    from .kanidm import valid_name
    if not _re.fullmatch(r"[a-z0-9-]{1,32}", a.service):
        raise SiteError(f"{a.service!r} is not a valid PAM service name")
    if not valid_name(a.user):
        raise SiteError(f"{a.user!r} is not a valid user name")
    lines = sys.stdin.read().splitlines()
    pw, code = (lines + ["", ""])[0], (lines[1] if len(lines) > 1 and lines[1] else None)
    ok, why, prompts = pamtest.authenticate(a.service, a.user, pw, code)
    print(("PAM_OK" if ok else f"PAM_FAIL {why}") + " prompts=" + "|".join(p.strip() for p in prompts))
    return 0 if ok else 1


def _ga_enrol(a):
    import socket
    from .ga import enrol
    if os.geteuid() != 0:
        raise SiteError("run as root: sudo chp-site ga-enrol USER")
    site = parse_site(read_file(Path(a.site) / "site.conf", "site.conf"))
    p = enrol(a.user, socket.getfqdn(), site["DOMAIN"], reset=a.reset, no_confirm=a.no_confirm)
    print(f"\nGoogle Authenticator token for {a.user} on {socket.getfqdn()} saved ({p}). The user scans the QR code above "
          "and keeps the 5 emergency scratch codes somewhere safe; each works once.")


def _host():
    import socket
    return socket.gethostname().split(".")[0]


def _aide_pin(a):
    import time
    from . import aide
    from .usbstick import site_stick
    base = aide.read_record(aide.STATE / "baseline")
    with site_stick(getattr(a, "stick", None)) as s:
        p = aide.write_pin(s, _host(), base, time.time())
    aide.write_record(aide.STATE / "pinned", {"DB_SHA512": base["DB_SHA512"]}, 0o644)
    print(f"pinned: aide/{p.name} on the site stick (SHA-512 {base['DB_SHA512'][:16]}…)")


def _stick_pin_hash(_a):
    import subprocess
    from . import usbstick
    try:
        out = subprocess.run(["usbguard", "list-devices"], capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise SiteError("USBGuard is not available to list devices; site-stick hash not pinned") from None
    h = usbstick.pin_stick_hash(out, usbstick.PIN_FILE, usbstick.HASH_FILE)
    print(f"site-stick hash pinned: {h}" if h else "site-stick hash: nothing to pin (already pinned, no pin, or no stick)")


def _docs(a):
    import subprocess
    from . import docs
    from .usbstick import site_stick
    with site_stick(getattr(a, "stick", None)) as s:     # USBGuard: ONLY the pinned stick, temporarily; always re-blocked
        out, used_profile, summary = docs.render(s, Path(a.site), Path(a.templates), Path(a.out_root), a.rev)
    if not used_profile:
        print("note: no profile.ini on the site stick; document values stay as placeholders (see fill-report.md)")
    print(summary or f"wrote {out}")
    print(f"documents: {out} (ssp.md, poam.md; fill-report.md lists what is still to fill)")
    subprocess.run(["logger", "-t", "chp-site", f"docs rendered {out}"], check=False)


def _aide_verify_pin(a):
    from . import aide
    from .usbstick import site_stick
    live = aide.sha512_file(aide.DB)
    with site_stick(a.stick) as s:
        ok, pinned = aide.verify_pin(s, _host(), live)
    print(f"{'MATCH' if ok else 'MISMATCH'}\n  live  {live}\n  stick {pinned}")
    return 0 if ok else 1


def _aide_accept(a):
    from . import aide
    site, _hosts = _load(a.site)
    def ask():
        try:
            return input("Type ACCEPT to make this the new baseline: ").strip() == "ACCEPT"
        except EOFError:                                    # no terminal (scripted, ssh -n): never a yes
            return False
    confirm = (lambda: True) if a.yes else ask
    nb = aide.accept(site, a.approver, a.reason, host=_host(), aide=aide.run_aide, rpm=aide.Rpm(), confirm=confirm,
                     investigated_mismatch=a.database_mismatch_investigated)
    if nb is None:
        return 0
    print("Pinning the new baseline: plug in the site stick.")
    try:
        _aide_pin(a)
    except SiteError as err:
        print(f"NOT pinned yet ({err}); the monitor reminds you until: chp-site aide-pin")
    return 0


def _security(a):
    import subprocess
    from . import security
    from .usbstick import site_stick
    if a.action == "status":
        print(security.status(Path("/"), subprocess.run))
        return 0
    site, hosts = _load(a.site)
    me = next((h for h in hosts if h.hostname == _host()), None)
    if me is None:
        raise SiteError(f"this host ({_host()}) is not in the hosts table")
    with site_stick(getattr(a, "stick", None)) as s:     # USBGuard: ONLY the pinned stick, temporarily
        done = security.enable(me.role, me.hostname, site, hosts, stick=s, run=subprocess.run)
    print("\n".join(f"- {x}" for x in done))
    if me.role == "server":
        print("next: run `chp-site security enable` on each client, with the site stick")
    return 0


def _alerts(a):
    import time
    from . import wazuh_alerts as wa
    try:
        since = time.time() - wa.parse_since(a.since)
    except ValueError as err:
        raise SiteError(str(err)) from None
    print(wa.summarize(wa.load_alerts("/var/ossec/logs/alerts", since), since, a.level))
    return 0


def _wazuh_forward(_a):
    import subprocess
    import time
    from . import wazuh_alerts as wa
    kv = dict(ln.split("=", 1) for ln in Path("/etc/chp/security.conf").read_text().splitlines() if "=" in ln)
    hook = subprocess.run(["chp-site", "get", "ALERT_HOOK"], capture_output=True, text=True).stdout.strip()
    f = wa.Forwarder(int(kv.get("ALERT_LEVEL", "10")))

    def send(msg):
        subprocess.run(["logger", "-p", "auth.warning", "-t", "chp-wazuh", msg], check=False)
        if hook and os.access(hook, os.X_OK):
            try:
                subprocess.run([hook, msg], check=False, timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(["logger", "-p", "auth.warning", "-t", "chp-wazuh", f"ALERT_HOOK timed out: {hook}"],
                               check=False)
    Path("/var/lib/chp/wazuh").mkdir(parents=True, exist_ok=True)
    for alert in wa.follow("/var/ossec/logs/alerts/alerts.json", "/var/lib/chp/wazuh/forward.state"):
        now = time.time()
        msgs = (f.feed(alert, now) if alert is not None else []) + f.flush(now)
        d = f.daily(now)
        for m in msgs + ([d] if d else []):
            send(m)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="chp-site")
    ap.add_argument("--version", action="version", version=f"chp-site {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate"); v.add_argument("--site", required=True)
    v.add_argument("--role", choices=("server", "client")); v.add_argument("--mac", nargs="*")
    p = sub.add_parser("pre"); p.add_argument("--role", required=True, choices=("server", "client"))
    p.add_argument("--stick", required=True); p.add_argument("--out", required=True)
    p.add_argument("--repo-url", default="file:///run/install/repo/chp")
    vr = sub.add_parser("verify-repo", help="row 37: the repo's repomd.xml must be signed by a pinned project key")
    vr.add_argument("--url", required=True)
    g = sub.add_parser("get"); g.add_argument("key"); g.add_argument("--site", default="/etc/chp")
    r = sub.add_parser("render"); r.add_argument("what"); r.add_argument("--site", default="/etc/chp")
    e = sub.add_parser("export-client"); e.add_argument("--stick")
    e.add_argument("--pending", default="/root/chp-escrow-pending")
    e.add_argument("--site", default="/etc/chp/site.conf"); e.add_argument("--root", default="/etc/step-ca/certs/root_ca.crt")
    e.add_argument("--ssh-ca", default="/etc/ssh-ca/user_ca.pub")
    e.add_argument("--cache-key", default="/var/lib/chp/cache-key/id_ecdsa.pub")
    o = sub.add_parser("onboard", help="create/complete a person: POSIX, groups, reset token, SSH key + certificate")
    o.add_argument("user"); o.add_argument("--display"); o.add_argument("--group", action="append", default=[])
    o.add_argument("--ssh-key", help="the user's OpenSSH public key file (ECDSA or RSA >= 3072)")
    o.add_argument("--replace-key", action="store_true")
    o.add_argument("--as", dest="as_", default="idm_admin", help="your Kanidm admin session (kanidm login -D NAME)")
    o.add_argument("--site", default="/etc/chp")
    v = sub.add_parser("revoke", help="expire a person now (or remove one group membership) and clear every client's cache")
    v.add_argument("user"); v.add_argument("--group")
    v.add_argument("--as", dest="as_", default="idm_admin"); v.add_argument("--site", default="/etc/chp")
    u = sub.add_parser("unexpire", help="re-enable an expired person (ISSO or delegate approval, audited; ISSO #32)")
    u.add_argument("user"); u.add_argument("--approver", required=True); u.add_argument("--reason", required=True)
    u.add_argument("--as", dest="as_", default="idm_admin"); u.add_argument("--site", default="/etc/chp")
    t = sub.add_parser("client-token", help="mint a read-only unixd token for a client added later (then export-client)")
    t.add_argument("host"); t.add_argument("--as", dest="as_", default="idm_admin"); t.add_argument("--site", default="/etc/chp")
    ap_ = sub.add_parser("authselect-patch", help="add Kanidm to an authselect profile dir (client enrolment)")
    ap_.add_argument("dir")
    pt = sub.add_parser("pam-test", help="authenticate USER through PAM service SERVICE (secrets on stdin; root)")
    pt.add_argument("service"); pt.add_argument("user")
    ge = sub.add_parser("ga-enrol", help="host-local Google Authenticator token for a Kanidm user (root; audited)")
    ge.add_argument("user"); ge.add_argument("--reset", action="store_true")
    ge.add_argument("--no-confirm", action="store_true", help="skip the app-code confirmation (scripted use only)"); ge.add_argument("--site", default="/etc/chp")
    aa = sub.add_parser("aide-accept", help="accept the current files as the new AIDE baseline (ISSO or BASELINE_DELEGATES; audited)")
    aa.add_argument("--approver", required=True); aa.add_argument("--reason", required=True)
    aa.add_argument("--yes", action="store_true", help="skip the ACCEPT prompt (scripted lab use only)")
    aa.add_argument("--database-mismatch-investigated", action="store_true")
    aa.add_argument("--stick"); aa.add_argument("--site", default="/etc/chp")
    apn = sub.add_parser("aide-pin", help="write this host's AIDE baseline hash to the site stick (aide/<host>.txt)")
    apn.add_argument("--stick")
    sub.add_parser("stick-pin-hash", help="pin the plugged-in (still blocked) site stick's USBGuard hash; never allows it")
    dc = sub.add_parser("docs", help="render the site's SSP and POA&M from the site stick's profile.ini (chp-templates)")
    dc.add_argument("--stick"); dc.add_argument("--site", default="/etc/chp/site.conf")
    dc.add_argument("--templates", default="/usr/share/chp-templates"); dc.add_argument("--out-root", default="/var/lib/chp/docs")
    dc.add_argument("--rev", default="rev2")
    avp = sub.add_parser("aide-verify-pin", help="compare the live AIDE database with the site stick's pin (MATCH/MISMATCH)")
    avp.add_argument("--stick")
    se = sub.add_parser("security", help="security add-on: enable Wazuh on this host (server first), or show status")
    se.add_argument("action", choices=("enable", "status")); se.add_argument("--stick"); se.add_argument("--site", default="/etc/chp")
    al = sub.add_parser("alerts", help="summarise Wazuh alerts by host and rule (server; root)")
    al.add_argument("--since", default="24h"); al.add_argument("--level", type=int, default=7)
    sub.add_parser("wazuh-forward", help="(service) send important Wazuh alerts to the log and ALERT_HOOK")
    a = ap.parse_args(argv)
    try:
        rc = {"validate": _validate, "pre": _pre, "verify-repo": _verify_repo, "export-client": _export, "get": _get, "render": _render_cmd,
         "onboard": _onboard, "revoke": _revoke,
         "unexpire": _unexpire,
         "client-token": _client_token,
         "authselect-patch": _authselect_patch,
         "pam-test": _pam_test,
         "ga-enrol": _ga_enrol,
         "aide-accept": _aide_accept, "aide-pin": _aide_pin, "aide-verify-pin": _aide_verify_pin,
         "stick-pin-hash": _stick_pin_hash, "docs": _docs,
         "security": _security, "alerts": _alerts, "wazuh-forward": _wazuh_forward}[a.cmd](a)
        if isinstance(rc, int):
            return rc                      # a handler's own exit status (pam-test: 0 ok, 1 refused)
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
