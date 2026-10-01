import pytest

from chp_site import audit
from chp_site.sitefile import SiteError


class Run:
    def __init__(self, rc=0, missing=()):
        self.calls, self.rc, self.missing = [], rc, missing

    def __call__(self, argv, **kw):
        if argv[0] in self.missing:
            raise FileNotFoundError(argv[0])
        self.calls.append(argv)
        import types
        return types.SimpleNamespace(returncode=self.rc, stdout="", stderr="denied")


def test_record_goes_to_audit_and_journal():
    r = Run()
    audit.record("unexpire", {"user": "lab04", "approver": "Pat ISSO"}, run=r)
    assert r.calls[0][:2] == ["auditctl", "-m"] and r.calls[1][:5] == ["logger", "-p", "authpriv.notice", "-t", "chp-site"]
    assert r.calls[0][2] == r.calls[1][5] == 'chp-site unexpire user="lab04" approver="Pat ISSO"'


def test_fields_cannot_forge_or_split_the_record():
    r = Run()
    audit.record("unexpire", {"reason": 'ok" approver="ISSO\nuser="root'}, run=r)
    msg = r.calls[0][2]
    assert "\n" not in msg and msg.count('"') == 2 and 'approver="ISSO' not in msg


def test_failed_record_before_a_change_says_nothing_changed():
    with pytest.raises(SiteError, match="nothing was changed"):
        audit.record("revoke", {"user": "x"}, run=Run(rc=1))
    with pytest.raises(SiteError, match="nothing was changed"):
        audit.record("revoke", {"user": "x"}, run=Run(missing=("auditctl",)))


def test_failed_record_after_a_change_says_it_was_made():
    with pytest.raises(SiteError, match="the change WAS made"):
        audit.record("revoke.done", {"user": "x"}, after=True, run=Run(rc=1))


def test_operator_is_a_string():
    assert isinstance(audit.operator(), str) and audit.operator()
