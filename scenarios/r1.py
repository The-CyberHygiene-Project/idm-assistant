"""R1: client2 is restored from its snapshot (golden) with none of reset.sh's fix-ups. Its clock is as old as the
snapshot, but chrony keeps saying 'synchronized' while it rejects its source as too variable (~): requirement row 18.
TOTP_TIME_SKEW must be found, and time-resync (restart chronyd first) must fix and prove it."""
import subprocess
import time

from engine import remote
from engine.findings import evaluate
from scenarios import f1

ID = "r1"
USER = "lab04"
SYMPTOM = "client2 was restored from a backup image; authenticator codes are rejected there."
EXPECT = {"client2": {"TOTP_TIME_SKEW"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "time-resync")]


def inject(log):
    subprocess.run(["ssh", "-n", "aero", "sudo virsh snapshot-revert client2 golden --running"], check=True,
                   capture_output=True, text=True, timeout=300)
    for _ in range(60):
        if subprocess.run(["ssh", "-n", "-o", "ConnectTimeout=3", "-o", "BatchMode=yes", "client2", "true"]).returncode == 0:
            break
        time.sleep(3)
    log("injected: client2 reverted to golden without a chronyd restart (row 18)")
    for _ in range(30):             # the error is the time since golden was taken: wait until it is past the window
        if "TOTP_TIME_SKEW" in {f.id for f in evaluate(remote.collect("client2-diag", USER))}:
            log("restored clock visible to the collector")
            return
        time.sleep(10)
    raise RuntimeError("restored clock not visible within ~5 min")


def final_probe(log):
    t = remote.collect("client2-diag", USER).get("time") or {}
    src = t.get("source_offset_s")
    ok_clock = t.get("source_state") == "*" and src is not None and abs(src) < 1   # 0.0 is a perfect clock, not missing
    login = f1.login("posix")
    log(f"probe: source {t.get('source_state')!r} {t.get('source_offset_s')} s; login {login}")
    return ok_clock and login == "OK"
