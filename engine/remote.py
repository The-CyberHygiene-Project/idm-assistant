"""SSH execution from the Mac. Arguments are quoted individually (shlex) — never a shell string built from findings."""
import json
import shlex
import subprocess


def run(host, argv, stdin=None, timeout=600, check=True):
    cmd = ["ssh", "-o", "BatchMode=yes", host, shlex.join(argv)]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout, check=check)


def collect(diag_host, user=None):
    argv = ["sudo", "-n", "/usr/local/sbin/idm-collect"] + (["--user", user] if user else [])
    return json.loads(run(diag_host, argv).stdout)
