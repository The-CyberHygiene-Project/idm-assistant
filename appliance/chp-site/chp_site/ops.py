# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site onboard | revoke | unexpire (spec 4.4; ISSO #28, #32). Kanidm runs as the operator's own session; every change
is audited before and after; secrets (reset tokens) go to root-only files and are never printed."""
import os
import time
from pathlib import Path

from . import audit, fanout
from .kanidm import PROTECTED, expired, valid_name
from .sitefile import SiteError

OUT = Path("/root/chp-onboard")


def _stamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _user(u):
    if not valid_name(u):
        raise SiteError(f"{u!r} is not a valid user name")
    if u in PROTECTED:
        raise SiteError(f"refusing: {u} is a built-in Kanidm admin account; chp-site does not manage it")
    return u


def write_private(out, name, text):
    out = Path(out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    p = out / name
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(p, 0o600)
    return p


def onboard(k, ca, user, domain, display=None, groups=(), ssh_key=None, replace_key=False, out=OUT,
            rec=audit.record, say=print):
    _user(user)
    for g in groups:
        if not valid_name(g):
            raise SiteError(f"{g!r} is not a valid group name")
    e = k.person(user)
    if e is not None and expired(e):
        raise SiteError(f"{user} is expired; re-enabling needs the ISSO's approval: "
                        f"chp-site unexpire {user} --approver NAME --reason TEXT")
    fields = {"user": user, "groups": ",".join(groups), "operator": audit.operator(), "as": k.as_}
    rec("onboard", fields)
    if e is None:
        k.create_person(user, display or user)
        say(f"created Kanidm person {user}")
        e = k.person(user)
    if "posixaccount" not in e.get("class", []):
        k.posix_set(user)
        e = k.person(user)
    member = {m.split("@")[0] for m in e.get("directmemberof", [])}
    for g in groups:
        if g not in member:
            k.add_member(g, user)
            say(f"added {user} to {g}")
    e = k.person(user)
    has_primary, has_unix = "primary_credential" in e, "unix_password" in e
    token = None
    if not (has_primary and has_unix):
        token = write_private(out, f"{user}.reset-token.txt", k.reset_token_text(user))
    if ssh_key is not None:
        say(f"SSH key for {user}: {ca.register(user, ssh_key, replace=replace_key)}")
    cert_note = None
    if ca.registered(user) is not None:
        cert, valid_to = ca.sign(user, domain)
        p = write_private(out, f"{user}-cert.pub", cert)
        os.chmod(p, 0o644)
        cert_note = f"valid to {valid_to}: {p} (public; give it to the user)"
    rec("onboard.done", fields, after=True)
    tok_note = f"reset token (valid 1 h, re-run onboard for a new one): {token}" if token else ""
    return [("account", True, user),
            ("POSIX enabled", True, ""),
            ("primary credential", has_primary, tok_note),
            ("POSIX (unix) password", has_unix, "same reset token" if token else ""),
            ("SSH key registered", ca.registered(user) is not None, "" if ca.registered(user) else "pass --ssh-key FILE"),
            ("SSH certificate issued", cert_note is not None, cert_note or ""),
            ("Google Authenticator", False, "the user enrols on each client at first login (client role)")]


def revoke(k, ca, hosts, user, group=None, rec=audit.record, fan=fanout.invalidate_all, say=print):
    _user(user)
    if user == k.as_:
        raise SiteError(f"refusing: {user} is the Kanidm session you are using; revoking it locks out administration")
    if group is not None and not valid_name(group):
        raise SiteError(f"{group!r} is not a valid group name")
    e = k.person(user)
    if e is None:
        raise SiteError(f"no Kanidm person {user}")
    if group is not None and group not in {m.split("@")[0] for m in e.get("directmemberof", [])}:
        raise SiteError(f"{user} is not a direct member of {group} (membership through another group: revoke that one)")
    fields = {"user": user, "scope": f"group:{group}" if group else "account", "operator": audit.operator(), "as": k.as_}
    rec("revoke", fields)
    if group is not None:
        k.remove_member(group, user)
        say(f"removed {user} from {group}")
    else:
        k.expire_now(user)
        moved = ca.revoke_key(user, _stamp())
        say(f"{user}: account expired now" + ("; registered SSH key moved to /var/lib/ssh-ca/revoked/" if moved else ""))
    rec("revoke.done", fields, after=True)
    text, failed = fanout.report(fan(hosts))
    say(text)
    if failed:
        raise SiteError(f"the Kanidm change IS in effect, but {', '.join(failed)} may keep cached access for up to "
                        "~2 min (fix and re-run, or wait)")
