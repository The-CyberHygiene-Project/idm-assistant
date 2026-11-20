"""chp-base monitor.d/20-clock.sh: the clock offset on every host and (Task 12, owner decision 2026-11-20) on a
workstation, the time source: the CHP server and nothing else. Fake chronyc / chp-site / hostname; made-up values."""
import os
import subprocess
from pathlib import Path

S = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-base" / "monitor.d" / "20-clock.sh"
TRACKING = "Reference ID    : C0A8641E (192.168.100.30)\nSystem time     : 0.000012 seconds fast of NTP time\n"
HEAD = ("MS Name/IP address         Stratum Poll Reach LastRx Last sample\n"
        "===============================================================================\n")


def run(tmp_path, sources, host="cli1", tracking=TRACKING):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    (tmp_path / "tracking").write_text(tracking)
    (tmp_path / "sources").write_text(HEAD + "".join(f"{s}\n" for s in sources))
    (b / "chronyc").write_text('#!/bin/bash\ncase "$*" in tracking) cat "%s";; "-n sources") cat "%s";; *) exit 9;; '
                               "esac\n" % (tmp_path / "tracking", tmp_path / "sources"))
    (b / "chp-site").write_text('#!/bin/bash\ncase "$2" in SERVER_IP) echo 192.168.100.30;; SERVER_HOSTNAME) echo srv1;;'
                                " *) exit 2;; esac\n")
    (b / "hostname").write_text(f"#!/bin/bash\necho {host}\n")
    for f in ("chronyc", "chp-site", "hostname"):
        (b / f).chmod(0o755)
    r = subprocess.run(["bash", str(S)], env=dict(os.environ, PATH=f"{b}:{os.environ['PATH']}"), capture_output=True,
                       text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.splitlines()


SRV = "^* 192.168.100.30                3   6   377    35   +12us[ +15us] +/-   20ms"


def test_workstation_on_the_server_is_ok(tmp_path):
    out = run(tmp_path, [SRV])
    assert out[0].startswith("OK clock offset") and out[1] == "OK time source: the CHP server 192.168.100.30"


def test_workstation_with_another_source_alerts(tmp_path):
    for other in ("^- 192.168.100.1                 2   6   377    35   +1ms[ +1ms] +/-   20ms",
                  "^? 203.0.113.123                 0   6     0     -     +0ns[   +0ns] +/-    0ns"):
        out = run(tmp_path, [SRV, other])
        a = [x for x in out if x.startswith("ALERT")]
        assert len(a) == 1 and "other than the CHP server 192.168.100.30" in a[0] and other.split()[1] in a[0]


def test_workstation_without_a_source_alerts(tmp_path):
    a = [x for x in run(tmp_path, []) if x.startswith("ALERT")]
    assert a == ["ALERT no time source (a workstation takes time from the CHP server 192.168.100.30 only)"]


def test_the_server_keeps_its_upstream(tmp_path):
    out = run(tmp_path, ["^* 192.168.100.1                 2   6   377    35   +1ms[ +1ms] +/-   20ms"], host="srv1")
    assert len(out) == 1 and out[0].startswith("OK clock offset")
