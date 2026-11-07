# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Resource figures for the daily review (priority 3): sysstat's day so far (CPU, memory, network) and a df reading
for disk use. sysstat's default collection (-S DISK) has no filesystem figures, so disk use comes from df (R1 Task 4)."""
import json

SKIP_FS = ("tmpfs", "devtmpfs", "efivarfs")


def _r(x):
    return round(x, 1)


def day_summary(sadf_json):
    """CPU busy % (100 - idle), memory used %, and network kB/s summed over every interface but lo, as average and
    peak over the samples; {} when there is nothing to summarise."""
    try:
        st = json.loads(sadf_json)["sysstat"]["hosts"][0]["statistics"]
        cpu = [100 - s["cpu-load"][0]["idle"] for s in st]
        mem = [s["memory"]["memused-percent"] for s in st]
        rx = [sum(n["rxkB"] for n in s["network"]["net-dev"] if n["iface"] != "lo") for s in st]
        tx = [sum(n["txkB"] for n in s["network"]["net-dev"] if n["iface"] != "lo") for s in st]
    except (ValueError, KeyError, IndexError, TypeError):
        return {}
    if not st:
        return {}
    n = len(st)
    return {"cpu": {"avg": _r(sum(cpu) / n), "peak": _r(max(cpu))},
            "mem": {"avg_pct": _r(sum(mem) / n), "peak_pct": _r(max(mem))},
            "net": {"rx_kbs_avg": _r(sum(rx) / n), "tx_kbs_avg": _r(sum(tx) / n)}, "samples": n}


def disk_use(df_text):
    """Used % per real file system from `df -P` (pseudo file systems left out)."""
    out = []
    for ln in df_text.splitlines()[1:]:
        f = ln.split()
        if len(f) < 6 or f[0] in SKIP_FS or not f[4].endswith("%"):
            continue
        out.append({"mount": f[5], "used_pct": int(f[4][:-1])})
    return out


def _out(run, argv):
    try:
        r = run(argv, capture_output=True, text=True)
    except OSError:                                       # sysstat (or df) not installed on this host
        return ""
    return r.stdout if r.returncode == 0 else ""


def today(run):
    """The record's "sys": today's sysstat summary plus disk use; whatever is missing is left out."""
    out = day_summary(_out(run, ["sadf", "-j", "--", "-u", "-r", "-n", "DEV"]))
    disk = disk_use(_out(run, ["df", "-P", "-x", "tmpfs", "-x", "devtmpfs"]))
    if disk:
        out["disk"] = disk
    return out
