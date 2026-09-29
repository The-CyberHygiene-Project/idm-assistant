import pytest

from engine import runbooks
from engine.findings import Finding

BASES = ["POSIX_PW_MISSING", "TLS_CERT_EXPIRED", "ACME_RENEWAL_STOPPED", "TLS_CERT_UNTRUSTED", "CLIENT_MISSING_CA_ROOT",
         "NSS_ORDER_WRONG", "UNIXD_CACHE_STALE", "UNIXD_OFFLINE", "KANIDM_UNREACHABLE", "TOTP_TIME_SKEW",
         "TIME_UNVERIFIED", "SERVICE_DOWN", "ACCOUNT_EXPIRED", "ACCOUNT_NOT_YET_VALID", "SSH_USER_CERT_EXPIRED",
         "SSH_CA_NOT_TRUSTED", "SELINUX_LABEL_WRONG", "COLLECT_CONF_INVALID"]
FUTURE_REPAIRS = {"ssh-user-cert-reissue", "ssh-ca-trust-restore", "selinux-restorecon"}   # Plan 7 Tasks 4-6


@pytest.mark.parametrize("base", BASES)
def test_every_finding_has_a_short_runbook(base):
    rb = runbooks.load(base)
    assert rb and rb.excerpt and len(rb.excerpt) <= 600


def test_parameterised_ids_use_the_base_runbook():
    assert runbooks.load("SERVICE_DOWN(kanidmd)").finding == "SERVICE_DOWN"


def test_default_repairs_exist_or_are_none():
    from engine.repairs import REGISTRY
    for base in BASES:
        d = runbooks.load(base).default_repair
        assert d is None or d in REGISTRY or d in FUTURE_REPAIRS, (base, d)


def test_for_findings_deduplicates_in_order():
    fs = [Finding("SERVICE_DOWN(a)", "service", ("x",)), Finding("SERVICE_DOWN(b)", "service", ("y",)),
          Finding("NSS_ORDER_WRONG", "nss", ("z",))]
    assert [r.finding for r in runbooks.for_findings(fs)] == ["SERVICE_DOWN", "NSS_ORDER_WRONG"]


def test_unknown_finding_has_no_runbook():
    assert runbooks.load("NO_SUCH_THING") is None
