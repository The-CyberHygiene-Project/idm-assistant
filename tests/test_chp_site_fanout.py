import subprocess
import types

from chp_site.fanout import ACCOUNT, invalidate_all, report
from chp_site.hosts import Host

HOSTS = [Host("52:54:00:00:00:30", "srv", "192.168.100.30", "server", None),
         Host("52:54:00:00:00:31", "cli1", "192.168.100.31", "client", None),
         Host("52:54:00:00:00:32", "cli2", "192.168.100.32", "client", None)]


class Run:
    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        for needle, res in self.table.items():
            if needle in " ".join(argv):
                if res == "timeout":
                    raise subprocess.TimeoutExpired(argv, 20)
                return types.SimpleNamespace(returncode=res[0], stdout="", stderr=res[1])
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def test_only_clients_over_the_pinned_key_and_local_unixd_when_active():
    r = Run({"is-active": (0, "")})
    res = invalidate_all(HOSTS, run=r)
    ssh = [c for c in r.calls if c[0] == "ssh"]
    assert [c[-2] for c in ssh] == [f"{ACCOUNT}@192.168.100.31", f"{ACCOUNT}@192.168.100.32"]
    assert all("BatchMode=yes" in c and "IdentitiesOnly=yes" in c and "StrictHostKeyChecking=accept-new" in c for c in ssh)
    assert ["kanidm-unix", "cache-invalidate"] in r.calls and [n for n, ok, _ in res] == ["srv (this server)", "cli1", "cli2"]


def test_server_not_yet_a_client_is_reported_not_hidden():
    res = invalidate_all(HOSTS[:1], run=Run({"is-active": (3, "")}))
    assert res == [("srv (this server)", True, "not a Kanidm client yet: nothing cached")]


def test_unreachable_and_changed_host_key_are_named():
    r = Run({"is-active": (3, ""), "100.31": "timeout",
             "100.32": (255, "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@")})
    text, failed = report(invalidate_all(HOSTS, run=r))
    assert failed == ["cli1", "cli2"] and "timed out" in text
    assert "ssh-keygen -R 192.168.100.32 -f /var/lib/chp/cache-key/known_hosts" in text


def test_no_clients_at_all():
    text, failed = report(invalidate_all(HOSTS[:1], run=Run({"is-active": (3, "")})))
    assert failed == [] and "no clients in the hosts table" in text
