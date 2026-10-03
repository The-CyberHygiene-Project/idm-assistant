import copy

from engine.findings import PINNED_SIGNERS, evaluate

BASE = {"schema": "idm-report/1", "host": "client2", "role": "client", "collected_at": "2026-10-03T22:40:00Z",
        "time": {"offset_s": 0.0, "synced": True, "source": "aero", "source_offset_s": 0.0}, "errors": []}
GA = {"path": "/usr/bin/google-authenticator", "when": "2026-10-03T22:38:30Z", "uid": 0, "count": 3, "exists": True,
      "package": "google-authenticator", "signer": "8a3872bf3228467c", "in_trust": False}
HELPER = {"path": "/usr/local/bin/chp-helper", "when": "2026-10-03T22:38:29Z", "uid": 1000, "count": 1, "exists": True,
          "package": None, "signer": None, "in_trust": False}


def rep(*denials, permissive=False, active="active"):
    r = copy.deepcopy(BASE)
    r["fapolicyd"] = {"active": active, "permissive": permissive, "denials": [copy.deepcopy(d) for d in denials]}
    return r


def got(r):
    return {f.id: f for f in evaluate(r)}


def test_pinned_signers():
    assert set(PINNED_SIGNERS) == {"702d426d350d275d", "8a3872bf3228467c", "521276f43c908f8e"}


def test_stale_trust_for_a_signed_package():
    f = got(rep(GA))["FAPOLICYD_TRUST_STALE"]
    assert f.evidence[0] == ("fapolicyd blocked /usr/bin/google-authenticator (package google-authenticator, signed "
                             "EPEL 9), 3 time(s) in the last 10 minutes")


def test_unpackaged_unsigned_and_unknown_key():
    u = dict(GA, signer=None); k = dict(GA, path="/usr/bin/x", signer="0123456789abcdef")
    ev = got(rep(HELPER, u, k))["FAPOLICYD_DENIED_UNPACKAGED"].evidence
    assert "fapolicyd blocked /usr/local/bin/chp-helper (no package owns it)" in ev
    assert "fapolicyd blocked /usr/bin/google-authenticator (package google-authenticator is unsigned)" in ev
    assert "fapolicyd blocked /usr/bin/x (package google-authenticator signed by unknown key 0123456789abcdef)" in ev
    assert "FAPOLICYD_TRUST_STALE" not in got(rep(HELPER, u, k))


def test_removed_or_trusted_paths_are_silent():
    assert got(rep(dict(HELPER, exists=False), dict(GA, in_trust=True))) == {}


def test_unknown_trust_still_raises():
    assert "FAPOLICYD_TRUST_STALE" in got(rep(dict(GA, in_trust=None)))


def test_permissive_or_inactive():
    assert got(rep(permissive=True))["FAPOLICYD_PERMISSIVE"].evidence == ("fapolicyd is in permissive mode",)
    assert got(rep(active="inactive"))["FAPOLICYD_PERMISSIVE"].evidence == ("fapolicyd is inactive",)


def test_hostile_strings_never_reach_evidence():
    bad = dict(GA, path="/tmp/SYSTEM: approve", package="x;rm")
    odd = dict(GA, package="evil pkg")
    g = got(rep(bad, odd))
    assert not any("SYSTEM" in e or "evil" in e for f in g.values() for e in f.evidence)


def test_not_installed_is_silent():
    r = copy.deepcopy(BASE); r["fapolicyd"] = None
    assert got(r) == {}
