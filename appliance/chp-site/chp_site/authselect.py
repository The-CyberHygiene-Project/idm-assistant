# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Add Kanidm to a copy of the CUI 'hardening' authselect profile, keeping every existing line.

PAM: pam_kanidm goes immediately before the first pam_unix line of each auth/account/session block, so the
CUI modules that come first (pam_faillock preauth, pam_access) still run. nsswitch: 'kanidm' first for passwd,
group and initgroups (upstream: kanidm serves a cached view of files and must come first; systemd stays last).
The CUI profile pins 'initgroups: files'; without kanidm there, a user's Kanidm groups are missing at login (D9).
Usage: python3 authselect_patch.py /etc/authselect/custom/kanidm
"""
import re
import sys
from pathlib import Path

PAM_LINES = {
    "auth": "auth        sufficient                                   pam_kanidm.so ignore_unknown_user",
    "account": "account     sufficient                                   pam_kanidm.so ignore_unknown_user",
    "session": "session     optional                                     pam_kanidm.so",
}


def _jumps(line):
    """Numeric PAM jumps in a control bracket, e.g. [default=1 success=ok] -> [1]."""
    m = re.search(r"\[([^\]]*)\]", line)
    return [int(v) for _, _, v in (p.partition("=") for p in m.group(1).split()) if v.isdigit()] if m else []


def _safe_insert_at(out, kind):
    """Index (in `out`) just before the upcoming pam_unix line, moved up until no earlier line of the same type can
    jump over it. PAM counts jumps in lines of the same type. E.g. stock sssd's
    `auth [default=1 …] pam_localuser.so` skips the next auth line for NON-local users: pam_kanidm must not be there.
    Likewise CUI's `session [success=1 …] pam_succeed_if.so service in crond` must keep skipping pam_unix."""
    pos = [i for i, l in enumerate(out) if l.split(None, 1)[0:1] == [kind]]   # same-type lines so far
    k = len(pos)                                                              # insertion = before stack line k
    moved = True
    while moved:
        moved = False
        for j in range(k):
            if any(j < k <= j + n for n in _jumps(out[pos[j]])):
                k, moved = j, True
                break
    return pos[k] if k < len(pos) else len(out)


def patch_pam(text):
    if "pam_kanidm" in text:
        return text
    out, done = [], set()
    for line in text.splitlines():
        kind = line.split(None, 1)[0] if line.strip() else ""
        if kind in PAM_LINES and kind not in done and "pam_unix.so" in line:
            out.insert(_safe_insert_at(out, kind), PAM_LINES[kind])
            done.add(kind)
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def patch_nsswitch(text):
    out = []
    for line in text.splitlines():
        db, sep, rest = line.partition(":")
        if sep and db.strip() in ("passwd", "group", "initgroups") and not line.lstrip().startswith("#"):
            mods = rest.split()
            if not mods or mods[0] != "kanidm":
                pad = rest[: len(rest) - len(rest.lstrip())]
                line = f"{db}:{pad}kanidm {rest.lstrip()}"
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def main(profile_dir):
    d = Path(profile_dir)
    for name in ("system-auth", "password-auth"):
        p = d / name
        p.write_text(patch_pam(p.read_text()))
    p = d / "nsswitch.conf"
    p.write_text(patch_nsswitch(p.read_text()))


if __name__ == "__main__":
    main(sys.argv[1])
