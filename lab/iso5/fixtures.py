"""ISO Plan 5b Task 6: the scenario users and groups on the appliance lab (IDM_PROFILE=appliance), made with the engine's
own helpers. Run once after the lab adapter, before the golden snapshots. Secrets go to ~/idm-lab-secrets (iso5-*) only."""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
os.environ.setdefault("IDM_PROFILE", "appliance")

from engine import labsecrets, profile, remote  # noqa: E402
from engine.repairs import admin_login, stage  # noqa: E402
from scenarios import _login  # noqa: E402

USERS = {"lab01": "Lab User 1", "lab02": "Lab User 2", "lab03": "Lab User 3", "lab04": "Lab User 4", "lab06": "Lab User 6"}
NEEDS_LOGIN = ("lab01", "lab02", "lab06")          # probes log in as these (key/cert + GA + password)


class _S:
    host = "srv1"
    remote = remote


def k(*a, check=True):
    return remote.run("srv1", ["kanidm", *a, "-D", "idm_admin"], check=check)


def main():
    assert profile.current().name == "appliance", "run with IDM_PROFILE=appliance"
    stage(_S); admin_login(_S)
    if "name: lab_admins" not in k("group", "get", "lab_admins", check=False).stdout:
        k("group", "create", "lab_admins"); k("group", "posix", "set", "lab_admins")
    for u, disp in USERS.items():
        if f"name: {u}" not in k("person", "get", u, check=False).stdout:
            k("person", "create", u, disp)
        k("group", "add-members", profile.current().login_group, u)
        k("person", "posix", "set", u)
        tok = re.search(r"use-reset-token ([a-z0-9-]+)", k("person", "credential", "create-reset-token", u).stdout).group(1)
        pw, upw = labsecrets.new_password(), labsecrets.new_password()
        out = remote.run("srv1", ["expect", "idm-lab/srv1/enrol-user.exp"], stdin=f"{tok}\n{pw}\n{upw}\ntotp\n").stdout
        sec = re.search(r"TOTP_SECRET=([A-Z2-7]+)", out).group(1)
        labsecrets.write_json(f"{u}.json", {"password": pw, "posix_password": upw, "totp_secret": sec,
                                            "totp_algorithm": "sha256"})
        print(f"{u}: Kanidm person with password + TOTP + POSIX password")
    for u in NEEDS_LOGIN:
        _login.prepare_user(u)
    ok1 = _login.probe("lab01", "posix", print) == "OK"
    ok2 = _login.cert_probe("lab02", print).startswith("RESULT: OK")
    print(f"FIXTURES {'OK' if ok1 and ok2 else 'FAILED'}")
    return 0 if ok1 and ok2 else 1


if __name__ == "__main__":
    sys.exit(main())
