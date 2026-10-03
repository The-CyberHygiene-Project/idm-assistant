"""F1: wrong-password logins lock lab04 out of client2. pam_faillock in the CUI profile: deny = 3 within
fail_interval = 900 s, unlock_time = 0, so the lock never expires by itself; the approved unlock clears it. ISSO row 44."""
import subprocess
from pathlib import Path

from engine import remote
from engine.findings import evaluate

ID = "f1"
USER = "lab04"
SYMPTOM = f"{USER} cannot log in to client2 even with the right password; other people can."
EXPECT = {"client2": {"ACCOUNT_LOCKED"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "faillock-reset")]
PARAMS = {"user": USER}
ROOT = Path(__file__).resolve().parents[1]


def login(which):
    r = subprocess.run(["/usr/bin/expect", str(ROOT / "lab/client/ssh-login.exp"), USER, which, "192.168.100.13"],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    return "OK" if "RESULT: uid=" in r.stdout else "DENIED" if "RESULT: DENIED" in r.stdout else "ERROR"


def lock_out(log):
    for _ in range(5):
        login("wrong")
    if "ACCOUNT_LOCKED" not in {f.id for f in evaluate(remote.collect("client2-diag", USER))}:
        raise RuntimeError("five wrong passwords did not lock the account; injection did not take")
    log(f"injected: five wrong-password logins locked {USER} on client2 (limit 3)")


def inject(log):
    lock_out(log)


def final_probe(log):
    res = login("posix")
    log(f"login probe {USER}@client2 with its posix password: {res}")
    return res == "OK"
