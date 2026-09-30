# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Clear the kanidm-unixd cache everywhere after a revoke (ISSO #28: the ~2 min cache window becomes seconds).
Clients accept the server's cache key only from the server's IP and only for the forced command
`sudo -n /usr/bin/kanidm-unix cache-invalidate` (client role, Plan 4). Host keys: trust on first use, in a dedicated file."""
import subprocess
from pathlib import Path

KEY = Path("/var/lib/chp/cache-key/id_ecdsa")
KNOWN = Path("/var/lib/chp/cache-key/known_hosts")
ACCOUNT = "chpcache"


def _local(run):
    name = "(this server)"
    if run(["systemctl", "is-active", "-q", "kanidm-unixd"], capture_output=True, text=True).returncode != 0:
        return (name, True, "not a Kanidm client yet: nothing cached")
    r = run(["kanidm-unix", "cache-invalidate"], capture_output=True, text=True)
    return (name, r.returncode == 0, "ok" if r.returncode == 0 else (r.stderr.strip() or "failed")[:120])


def invalidate_all(hosts, run=subprocess.run, key=KEY, known=KNOWN):
    server = next((h.hostname for h in hosts if h.role == "server"), "server")
    n, ok, d = _local(run)
    out = [(f"{server} {n}", ok, d)]
    for h in hosts:
        if h.role != "client":
            continue
        argv = ["ssh", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=accept-new",
                f"{ACCOUNT}@{h.ip}", "cache-invalidate"]
        try:
            r = run(argv, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            out.append((h.hostname, False, "timed out (host off or unreachable?)"))
            continue
        if r.returncode == 0:
            out.append((h.hostname, True, "ok"))
        elif "IDENTIFICATION HAS CHANGED" in r.stderr:
            out.append((h.hostname, False, f"host key changed (reinstalled?); if expected: ssh-keygen -R {h.ip} -f {known}"))
        else:
            last = [ln for ln in r.stderr.splitlines() if ln.strip()]
            out.append((h.hostname, False, (last[-1] if last else f"exit {r.returncode}")[:160]))
    return out


def report(results):
    lines = [f"  {'ok  ' if ok else 'FAIL'} {name}: {detail}" for name, ok, detail in results]
    if not any(True for n, _, _ in results if "(this server)" not in n):
        lines.append("  (no clients in the hosts table)")
    return "caches:\n" + "\n".join(lines), [n for n, ok, _ in results if not ok]
