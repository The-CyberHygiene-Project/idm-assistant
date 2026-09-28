"""L1: a Kanidm user has a primary credential but NO POSIX password, so Linux login fails (spec §6)."""
import re
import subprocess
from pathlib import Path

from engine import labsecrets, remote
from engine.repairs import admin_login

ID = "l1"
USER = "lab08"
SYMPTOM = f"{USER} can log in to the Kanidm web UI but not to client2 over SSH."
EXPECT = {"srv1": {"POSIX_PW_MISSING"}}
REPAIRS = [("srv1", "kanidm-cred-reset-token")]
PARAMS = {"user": USER, "lab_standin": True}
ROOT = Path(__file__).resolve().parents[1]


class _R:
    remote = remote


def _k(*args):
    return remote.run("srv1", ["kanidm", *args, "-D", "idm_admin"], check=False)


def inject(log):
    subprocess.run(["rsync", "-a", f"{ROOT}/lab/srv1/", "srv1:/tmp/srv1/"], check=True, capture_output=True)
    admin_login(_R)
    if f"name: {USER}" in _k("person", "get", USER).stdout:
        remote.run("srv1", ["expect", "/tmp/srv1/kanidm-delete.exp", "person", USER])
    _k("person", "create", USER, "Lab User 8")
    _k("group", "add-members", "lab_users", USER)
    _k("person", "posix", "set", USER)
    tok = re.search(r"use-reset-token ([a-z0-9-]+)", _k("person", "credential", "create-reset-token", USER).stdout).group(1)
    pw = labsecrets.new_password()
    out = remote.run("srv1", ["expect", "/tmp/srv1/enrol-user.exp"], stdin=f"{tok}\n{pw}\nunused\ntotp-no-posix\n").stdout
    sec = re.search(r"TOTP_SECRET=([A-Z2-7]+)", out).group(1)
    labsecrets.write_json(f"{USER}.json", {"password": pw, "posix_password": None, "totp_secret": sec,
                                           "totp_algorithm": "sha256"})
    log(f"injected: {USER} with primary password + TOTP and no POSIX password")
    # Before the repair the user only has a primary (Kanidm) password: try THAT one, so the refusal comes from PAM
    # (an empty password would be refused by sshd itself before PAM runs, proving nothing).
    if probe("primary", log) != "DENIED":
        raise RuntimeError(f"{USER} was not refused by PAM before the repair; injection did not take")


def probe(which, log):
    r = subprocess.run(["/usr/bin/expect", str(ROOT / "lab/client/ssh-login.exp"), USER, which, "192.168.100.13"],
                       capture_output=True, text=True)
    res = "OK" if "RESULT: uid=" in r.stdout else "DENIED" if "RESULT: DENIED" in r.stdout else "ERROR"
    log(f"login probe {USER}@client2 with its {which} password: {res}")
    return res


def final_probe(log):
    return probe("posix", log) == "OK"
