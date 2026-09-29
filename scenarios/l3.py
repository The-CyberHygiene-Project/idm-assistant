"""L3: a group is revoked on the server while client2 is cut off; after reconnection the client still grants it
from cache (spec §6 L3, revised on measured behaviour: see Plan 6 Task 6)."""
from engine import remote
from engine.repairs import admin_login, stage

ID = "l3"
USER = "lab03"
GROUP = "lab_admins"
SPN = f"{GROUP}@idm.kanidm.lab.test"
SYMPTOM = f"{USER} was removed from {GROUP} but can still use {GROUP} access on client2."
EXPECT = {"client2": {"UNIXD_CACHE_STALE"}}
HOSTS = ["srv1", "client2"]
REPAIRS = [("client2", "unixd-refresh")]
PARAMS = {"user": USER}
CLEAR_BEFORE_S = 90            # natural cache expiry measured at ~123 s


class _S:
    host = "srv1"
    remote = remote


def _k(*a):
    return remote.run("srv1", ["kanidm", *a, "-D", "idm_admin"])


def _client_groups():
    return remote.run("client2", ["id", "-Gn", USER]).stdout.split()


def inject(log):
    stage(_S); admin_login(_S)
    _k("group", "add-members", GROUP, USER)
    remote.run("client2", ["sudo", "kanidm-unix", "cache-invalidate"])
    if SPN not in _client_groups():
        raise RuntimeError("setup failed: client2 does not show the group before the cut")
    remote.run("client2", ["sudo", "ip", "route", "add", "blackhole", "192.168.100.10/32"])
    try:
        _k("group", "remove-members", GROUP, USER)
    finally:
        remote.run("client2", ["sudo", "ip", "route", "del", "blackhole", "192.168.100.10/32"])
    if SPN not in _client_groups():
        raise RuntimeError("injection did not take: the client already dropped the group")
    log(f"injected: {USER} removed from {GROUP} while client2 was cut off; client2 still shows it after reconnection")


def final_probe(log):
    ok = SPN not in _client_groups()
    log(f"probe: client2 {'no longer shows' if ok else 'STILL shows'} {SPN} for {USER}")
    return ok
