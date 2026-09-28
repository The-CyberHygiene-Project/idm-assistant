"""SSH execution from the Mac. Arguments are quoted individually (shlex) — never a shell string built from findings."""
import json
import shlex
import subprocess


def run(host, argv, stdin=None, timeout=600, check=True):
    cmd = ["ssh", "-o", "BatchMode=yes", host, shlex.join(argv)]
    io = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}   # never let ssh eat our stdin
    return subprocess.run(cmd, **io, capture_output=True, text=True, timeout=timeout, check=check)


def collect(diag_host, user=None):
    argv = ["sudo", "-n", "/usr/local/sbin/idm-collect"] + (["--user", user] if user else [])
    return json.loads(run(diag_host, argv).stdout)
