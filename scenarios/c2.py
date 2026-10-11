"""C2: the step-ca root is removed from client2's trust store (spec §6)."""
from engine import profile, remote

ID = "c2"
USER = "lab01"
SYMPTOM = "Nobody can log in to client2 after a package update; other hosts are fine."
EXPECT = {"client2": {"CLIENT_MISSING_CA_ROOT"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "client-ca-trust")]


def inject(log):
    remote.run("client2", ["sudo", "sh", "-c", f"rm -f {profile.current().anchor} && update-ca-trust extract && "
                           "systemctl restart kanidm-unixd || true"])
    log("injected: lab root removed from client2's trust store; unixd restarted")


def final_probe(log):
    s = remote.run("client2", ["kanidm-unix", "status"]).stdout
    ok = "Kanidm: online" in s
    log(f"probe: unixd {'online' if ok else 'NOT online'}")
    return ok
