"""L3n (negative control): Kanidm unreachable from client2. The right answer is 'fix the network', not a repair."""
from engine import remote

ID = "l3n"
USER = "lab04"
SYMPTOM = "Nobody can log in to client2; existing sessions still work."
EXPECT = {"client2": {"KANIDM_UNREACHABLE", "UNIXD_OFFLINE"}}
HOSTS = ["client2"]
REPAIRS = []


def inject(log):
    remote.run("client2", ["sudo", "ip", "route", "add", "blackhole", "192.168.100.10/32"])
    log("injected: blackhole route to srv1 on client2 (the collector's user lookup makes unixd notice)")


def restore(log):
    remote.run("client2", ["sudo", "ip", "route", "del", "blackhole", "192.168.100.10/32"])
    log("operator restored the network path (outside the allow-list); no repair was run")


def final_probe(log):
    s = remote.run("client2", ["kanidm-unix", "status"]).stdout
    ok = "Kanidm: online" in s
    log(f"probe: unixd {'online' if ok else 'NOT online'} after the network came back, with no refresh")
    return ok
