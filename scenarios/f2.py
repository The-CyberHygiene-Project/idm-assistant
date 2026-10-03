"""F2: the lockout has a cause. client2's clock is 10 minutes off (as L4), then the same five failures lock lab04.
ISSO row 44: the cause is fixed first (time-resync); only then may the unlock run. In the lab the failures are wrong
passwords, so this tests the cause-first rule, not that the skew produced the failures."""
from scenarios import f1, l4

ID = "f2"
USER = f1.USER
SYMPTOM = f"{USER} is locked out of client2 and authenticator codes are rejected there."
EXPECT = {"client2": {"ACCOUNT_LOCKED", "TOTP_TIME_SKEW"}}
HOSTS = ["client2"]
REPAIRS = [("client2", "time-resync"), ("client2", "faillock-reset")]
PARAMS = {"user": USER}


def inject(log):
    l4.inject(log)
    f1.lock_out(log)


def final_probe(log):
    return f1.final_probe(log)
