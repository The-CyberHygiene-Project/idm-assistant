"""L6: unixd's socket directory is mislabelled, so Kanidm logins fail with NO AVC logged (dontaudit; measured
2026-09-29). Evidence is the collector's restorecon dry run (spec §6 L6; finding revised, see Plan 7)."""
import subprocess
from pathlib import Path

from engine import remote

ID = "l6"
USER = "lab01"
SYMPTOM = "After last night's patching nobody can log in to client2 with their Kanidm account; local admins can."
EXPECT = {"client2": {"SELINUX_LABEL_WRONG(/run/kanidm-unixd)"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "selinux-restorecon")]
ROOT = Path(__file__).resolve().parents[1]


def inject(log):
    remote.run("client2", ["sudo", "chcon", "-R", "-t", "var_run_t", "/run/kanidm-unixd"])
    log("injected: /run/kanidm-unixd relabelled var_run_t (no login attempted before the repair: faillock)")


def final_probe(log):
    r = subprocess.run(["/usr/bin/expect", str(ROOT / "lab/client/ssh-login.exp"), USER, "posix", "192.168.100.13"],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
    ok = "RESULT: uid=" in r.stdout
    log(f"probe: {USER} password login on client2 {'OK' if ok else 'FAILED'}")
    return ok
