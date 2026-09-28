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


def push(host, src, dest):
    """Copy lab scripts into a 0700 directory in the admin user's home (never a world-writable /tmp parent)."""
    subprocess.run(["ssh", "-o", "BatchMode=yes", host, f"install -d -m 0700 {shlex.quote(dest)}"],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True)
    subprocess.run(["rsync", "-a", "--chmod=Du=rwx,Dgo=,Fu=rw,Fgo=", src, f"{host}:{dest}"],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True)
    # macOS ships openrsync, which ignores --chmod, and -a copies the source's modes: tighten the tree afterwards.
    top = dest.strip("/").split("/")[0]
    subprocess.run(["ssh", "-o", "BatchMode=yes", host, f"chmod -R go= {shlex.quote(top)}"],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True)
