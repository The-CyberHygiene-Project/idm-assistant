"""L5: a user's Kanidm account has expired, so every login is refused (spec §6). Expiry is usually deliberate, so the
model may rightly decline to propose a repair (MODEL_MAY_DECLINE)."""
import subprocess
from pathlib import Path

from engine import remote
from engine.repairs import admin_login, stage

ID = "l5"
USER = "lab06"
SYMPTOM = f"{USER} could log in to client2 yesterday; today every login is refused."
EXPECT = {"srv1": {"ACCOUNT_EXPIRED"}}
HOSTS = ["srv1", "client2"]
REPAIRS = [("srv1", "account-unexpire")]
PARAMS = {"user": USER}
MODEL_MAY_DECLINE = True
ROOT = Path(__file__).resolve().parents[1]


class _S:
    host = "srv1"
    remote = remote


def probe(log):
    r = subprocess.run(["/usr/bin/expect", str(ROOT / "lab/client/ssh-login.exp"), USER, "posix", "192.168.100.13"],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    res = "OK" if "RESULT: uid=" in r.stdout else "DENIED" if "RESULT: DENIED" in r.stdout else "ERROR"
    log(f"login probe {USER}@client2 with its posix password: {res}")
    return res


def inject(log):
    stage(_S); admin_login(_S)
    remote.run("srv1", ["kanidm", "person", "validity", "expire-at", USER, "now", "-D", "idm_admin"])
    log(f"injected: {USER}'s account expired now")
    if probe(log) != "DENIED":          # the one failed password login this scenario allows (faillock)
        raise RuntimeError(f"{USER} was not refused after expiry; injection did not take")


def final_probe(log):
    return probe(log) == "OK"
