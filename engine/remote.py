"""SSH execution from the Mac. Arguments are quoted individually (shlex) — never a shell string built from findings."""
import json
import shlex
import subprocess


def run(host, argv, stdin=None, timeout=600, check=True):
    cmd = ["ssh", "-o", "BatchMode=yes", host, shlex.join(argv)]
    io = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}   # never let ssh eat our stdin
    return subprocess.run(cmd, **io, capture_output=True, text=True, timeout=timeout, check=check)


def collect(diag_host, user=None):
    argv = ["sudo", "-n", "/usr/sbin/idm-collect"] + (["--user", user] if user else [])
    lines = [ln for ln in run(diag_host, argv).stdout.splitlines() if ln.strip()]
    # The report is the collector's LAST line and carries its schema. Lines before it are not the collector's (e.g.
    # the Kanidm NSS module inside sudo logging to stdout while unixd is down): counted, never copied (unredacted).
    try:
        rep = json.loads(lines[-1]) if lines else None
    except ValueError:
        rep = None
    if not isinstance(rep, dict) or rep.get("schema") != "idm-report/1":
        raise ValueError(f"no idm-report/1 from {diag_host} ({len(lines)} line(s) of other output)")
    if len(lines) > 1:
        rep.setdefault("errors", []).append(
            f"collect: {len(lines) - 1} non-report line(s) on stdout before the report (not copied)")
    return rep


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
