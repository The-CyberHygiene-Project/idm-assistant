"""L2: kanidm dropped from initgroups (spike defect #3): users log in without their supplementary groups (spec §6)."""
from engine import remote

ID = "l2"
USER = "lab01"
SYMPTOM = f"{USER} can log in to client2 but sudo and group-shared folders stopped working."
EXPECT = {"client2": {"NSS_ORDER_WRONG"}}
HOSTS = ["srv1", "client2"]
REPAIRS = [("client2", "nsswitch-restore")]
GROUP = "lab_users@idm.kanidm.lab.test"


def _groups():
    return remote.run("client2", ["id", "-Gn", USER]).stdout.split()


def inject(log):
    remote.run("client2", ["sudo", "sed", "-i", "s/^initgroups:.*/initgroups: files/", "/etc/authselect/nsswitch.conf"])
    if GROUP in _groups():
        raise RuntimeError("injection did not take: supplementary groups still resolve")
    log(f"injected: initgroups is 'files' only; {USER} lost {GROUP}")


def final_probe(log):
    ok = GROUP in _groups()
    log(f"probe: id -Gn {USER} on client2 {'includes' if ok else 'LACKS'} {GROUP}")
    return ok
