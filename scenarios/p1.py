"""P1: a signed EPEL package (google-authenticator) is installed with `rpm --noplugins`, so fapolicyd is never told;
running its program is denied. FAPOLICYD_TRUST_STALE; the approved refresh (row 46) makes it run."""
from engine import remote
from engine.findings import evaluate

ID = "p1"
USER = None
SYMPTOM = "A newly installed program on client2 fails with 'permission denied'."
EXPECT = {"client2": {"FAPOLICYD_TRUST_STALE"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "fapolicyd-trust-refresh")]
RPM = "google-authenticator-1.09-5.el9.x86_64.rpm"
URL = "http://192.168.100.1:8080/chp"
PROG = "/usr/bin/google-authenticator"


def run_prog():
    return remote.run("client2", [PROG, "--help"], check=False).returncode


def inject(log):
    out = remote.run("client2", ["sudo", "sh", "-c", f"cd /tmp && curl -fsSO {URL}/0.5.4/{RPM} && "
                                 f"(rpm -i --noplugins /tmp/{RPM} 2>&1 || (curl -fsS {URL}/RPM-GPG-KEY-EPEL-9 -o /tmp/epel.key "
                                 f"&& rpm --import /tmp/epel.key && echo 'EPEL key imported' && rpm -i --noplugins /tmp/{RPM}))"],
                     check=False).stdout
    log(f"injected: {RPM} installed with rpm --noplugins ({out.strip()[:120] or 'ok'})")
    if run_prog() != 126:
        raise RuntimeError("the program was not denied: injection did not take")
    if "FAPOLICYD_TRUST_STALE" not in {f.id for f in evaluate(remote.collect("client2-diag"))}:
        raise RuntimeError("denied, but the collector does not show stale trust")


def final_probe(log):
    rc = run_prog()
    log(f"probe: {PROG} --help exit {rc} (126 = still denied)")
    return rc != 126
