"""L4: client2's clock jumps 10 minutes ahead; chrony will only slew it back over hours (spec §6)."""
import time

from engine import remote
from engine.findings import evaluate

ID = "l4"
USER = None
SYMPTOM = "Authenticator codes are rejected on client2 and some TLS connections fail."
EXPECT = {"client2": {"TOTP_TIME_SKEW"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "time-resync")]


def inject(log):
    # reset.sh restarts chronyd (iburst + makestep 1.0 3): let those first steps pass so ours is not undone by them.
    remote.run("client2", ["bash", "-c", "until [ $(( $(date +%s) - $(date -d \"$(systemctl show chronyd "
                           "-p ActiveEnterTimestamp --value)\" +%s) )) -ge 30 ]; do sleep 2; done"])
    remote.run("client2", ["sudo", "date", "-s", "+10 min"])
    log("injected: client2 clock +10 min")
    for _ in range(30):                                 # chrony samples every 64 s; the source line shows it first
        if "TOTP_TIME_SKEW" in {f.id for f in evaluate(remote.collect("client2-diag"))}:
            log("skew visible to the collector")
            return
        time.sleep(10)
    raise RuntimeError("skew not visible within ~5 min")
