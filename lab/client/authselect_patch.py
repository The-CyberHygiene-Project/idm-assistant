"""Add Kanidm to a copy of the CUI 'hardening' authselect profile, keeping every existing line.

PAM: pam_kanidm goes immediately before the first pam_unix line of each auth/account/session block, so the
CUI modules that come first (pam_faillock preauth, pam_access) still run. nsswitch: 'kanidm' first for passwd
and group (upstream: kanidm serves a cached view of files and must come first; systemd stays last).
Usage: python3 authselect_patch.py /etc/authselect/custom/kanidm
"""
import sys
from pathlib import Path

PAM_LINES = {
    "auth": "auth        sufficient                                   pam_kanidm.so ignore_unknown_user",
    "account": "account     sufficient                                   pam_kanidm.so ignore_unknown_user",
    "session": "session     optional                                     pam_kanidm.so",
}


def patch_pam(text):
    if "pam_kanidm" in text:
        return text
    out, done = [], set()
    for line in text.splitlines():
        kind = line.split(None, 1)[0] if line.strip() else ""
        if kind in PAM_LINES and kind not in done and "pam_unix.so" in line:
            out.append(PAM_LINES[kind])
            done.add(kind)
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def patch_nsswitch(text):
    out = []
    for line in text.splitlines():
        db, sep, rest = line.partition(":")
        if sep and db.strip() in ("passwd", "group") and not line.lstrip().startswith("#"):
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
