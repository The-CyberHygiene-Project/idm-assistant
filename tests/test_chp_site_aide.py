import os
import pytest

from chp_site import aide
from chp_site.sitefile import SiteError

REPORT = """Start timestamp: 2026-10-12 03:41:07 -0500 (AIDE 0.19.2)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:\t102345
  Added entries:\t\t1
  Removed entries:\t\t1
  Changed entries:\t\t2

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /etc/ssh/sshd_config.d/50-planted.conf

---------------------------------------------------
Removed entries:
---------------------------------------------------

f----------------: /usr/bin/oldtool

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /usr/bin/ls
f   ...    .C... : /etc/kanidm/config

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /usr/bin/ls
  SHA512    : abc | def

The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.gz
  SHA512    : 123
End timestamp: 2026-10-12 03:44:10 -0500 (run time: 3m 3s)
"""


def test_parse_report_sections_only():
    r = aide.parse_report(REPORT)
    assert r == {"added": ["/etc/ssh/sshd_config.d/50-planted.conf"], "removed": ["/usr/bin/oldtool"],
                 "changed": ["/usr/bin/ls", "/etc/kanidm/config"]}


def test_parse_report_clean_is_empty():
    assert aide.parse_report("Start timestamp: x\nAIDE found NO differences between database and filesystem. Looks okay!!\n") \
        == {"added": [], "removed": [], "changed": []}


def test_records_roundtrip_atomic_and_mode(tmp_path):
    p = tmp_path / "s" / "baseline"
    aide.write_record(p, {"DB_SHA512": "aa", "BUILT_BY": "first-boot"}, 0o600)
    assert aide.read_record(p) == {"DB_SHA512": "aa", "BUILT_BY": "first-boot"}
    assert oct(p.stat().st_mode & 0o777) == "0o600" and not (tmp_path / "s" / "baseline.tmp").exists()
    assert aide.read_record(tmp_path / "nope") == {}


def test_baseline_record_hashes_the_database(tmp_path):
    db = tmp_path / "aide.db.gz"; db.write_bytes(b"db")
    r = aide.baseline_record(db, "first-boot", 1760000000)
    assert r["DB_SHA512"] == aide.sha512_file(db) and len(r["DB_SHA512"]) == 128
    assert r["BUILT_AT"] == "20251009T085320Z" and r["BUILT_EPOCH"] == "1760000000" and r["BUILT_BY"] == "first-boot"


def test_baseline_record_rejects_unknown_built_by(tmp_path):
    db = tmp_path / "d"; db.write_bytes(b"x")
    with pytest.raises(ValueError):
        aide.baseline_record(db, "whatever", 1)


def test_pin_writes_record_and_keeps_history(tmp_path):
    base = {"DB_SHA512": "a" * 128, "BUILT_AT": "20261012T000000Z", "BUILT_BY": "first-boot"}
    p1 = aide.write_pin(tmp_path, "iso5-srv", base, 1760000000)
    assert p1 == tmp_path / "aide" / "iso5-srv.txt"
    assert aide.read_record(p1) == {"HOST": "iso5-srv", "DB_SHA512": "a" * 128, "BUILT_AT": "20261012T000000Z",
                                    "BUILT_BY": "first-boot", "PINNED_AT": "20251009T085320Z"}
    aide.write_pin(tmp_path, "iso5-srv", {**base, "DB_SHA512": "b" * 128}, 1760000100)
    assert aide.read_record(tmp_path / "aide" / "iso5-srv.20251009T085320Z.txt")["DB_SHA512"] == "a" * 128
    assert aide.read_record(tmp_path / "aide" / "iso5-srv.txt")["DB_SHA512"] == "b" * 128


def test_pin_history_never_overwrites_even_in_the_same_second(tmp_path):     # Review Focus 3
    base = {"DB_SHA512": "a" * 128, "BUILT_AT": "t", "BUILT_BY": "first-boot"}
    for sha in ("a", "b", "c"):
        aide.write_pin(tmp_path, "h", {**base, "DB_SHA512": sha * 128}, 1760000000)     # same second, three times
    names = sorted(os.listdir(tmp_path / "aide"))
    assert names == ["h.20251009T085320Z-1.txt", "h.20251009T085320Z.txt", "h.txt"]
    shas = {aide.read_record(tmp_path / "aide" / n)["DB_SHA512"][0] for n in names}
    assert shas == {"a", "b", "c"}


def test_pin_refuses_without_a_baseline(tmp_path):
    with pytest.raises(SiteError, match="no AIDE baseline"):
        aide.write_pin(tmp_path, "h", {}, 1)


def test_verify_pin(tmp_path):
    aide.write_pin(tmp_path, "h", {"DB_SHA512": "a" * 128, "BUILT_AT": "t", "BUILT_BY": "first-boot"}, 1)
    assert aide.verify_pin(tmp_path, "h", "a" * 128) == (True, "a" * 128)
    assert aide.verify_pin(tmp_path, "h", "b" * 128) == (False, "a" * 128)
    with pytest.raises(SiteError, match="no AIDE pin for other"):
        aide.verify_pin(tmp_path, "other", "a" * 128)


class FakeRpm:
    def __init__(self, owners, info, modified=None):
        self.owners, self._info, self._mod = owners, info, modified or {}

    def owner(self, p):
        return self.owners.get(p)

    def info(self, n):
        return self._info[n]

    def modified(self, n):
        return self._mod.get(n, set())


def test_group_explains_only_updated_unmodified_pinned_packages():
    changes = {"added": ["/usr/lib/new.so"], "removed": ["/usr/bin/gone"],
               "changed": ["/usr/bin/ls", "/usr/bin/vi", "/usr/bin/x", "/etc/kanidm/config", "/usr/bin/old"]}
    rpm = FakeRpm(owners={"/usr/lib/new.so": "glibc", "/usr/bin/ls": "coreutils", "/usr/bin/vi": "vim-minimal",
                          "/usr/bin/x": "thirdparty", "/usr/bin/old": "oldpkg", "/etc/kanidm/config": "kanidm-unixd"},
                  info={"glibc": (2000, "702d426d350d275d"), "coreutils": (2000, "702d426d350d275d"),
                        "vim-minimal": (2000, "702d426d350d275d"), "thirdparty": (2000, "deadbeefdeadbeef"),
                        "oldpkg": (500, "702d426d350d275d"), "kanidm-unixd": (2000, "521276f43c908f8e")},
                  modified={"vim-minimal": {"/usr/bin/vi"}, "kanidm-unixd": {"/etc/kanidm/config"}})
    explained, unexplained = aide.group(changes, rpm, built_epoch=1000)
    assert explained == {"glibc": ["/usr/lib/new.so"], "coreutils": ["/usr/bin/ls"]}
    assert unexplained == [("removed", "/usr/bin/gone"), ("changed", "/usr/bin/vi"), ("changed", "/usr/bin/x"),
                           ("changed", "/etc/kanidm/config"), ("changed", "/usr/bin/old")]


def test_rpm_helper_parses_rpm_output():
    import types

    def run(argv, **kw):
        if argv[:2] == ["rpm", "-qf"]:
            return types.SimpleNamespace(returncode=0, stdout="coreutils\n")
        if argv[:2] == ["rpm", "-q"]:
            return types.SimpleNamespace(returncode=0, stdout="1760000000 RSA/SHA256, Mon 12 Oct 2026, Key ID 702d426d350d275d\n")
        return types.SimpleNamespace(returncode=1, stdout="S.5....T.  c /etc/x\nmissing     /usr/bin/y\n")
    r = aide.Rpm(run=run)
    assert r.owner("/usr/bin/ls") == "coreutils"
    assert r.info("coreutils") == (1760000000, "702d426d350d275d")
    assert r.modified("coreutils") == {"/etc/x", "/usr/bin/y"}


def test_rpm_helper_unowned_and_unsigned():
    import types
    r = aide.Rpm(run=lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout="file /x is not owned by any package\n")
                 if argv[1] == "-qf" else types.SimpleNamespace(returncode=0, stdout="1760000000 (none)\n"))
    assert r.owner("/x") is None and r.info("p") == (1760000000, None)


SITE = {"ISSO_NAME": "D. Shannon", "BASELINE_DELEGATES": ["Deputy ISSO"]}


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, action, fields, after=False):
        self.calls.append((action, dict(fields), after))


def env(tmp_path, check_rc=4, check_text=REPORT, init_rc=0):
    db, new, st, lg = tmp_path / "aide.db.gz", tmp_path / "aide.db.new.gz", tmp_path / "state", tmp_path / "log"
    db.write_bytes(b"old-db")
    aide.write_record(st / "baseline", aide.baseline_record(db, "first-boot", 1000), 0o600)
    calls = []

    def fake_aide(*args):
        calls.append(args)
        if args == ("--check",):
            return check_rc, check_text
        new.write_bytes(b"new-db")
        return init_rc, "init done"
    kw = dict(host="iso5-srv", aide=fake_aide, rpm=FakeRpm({}, {}), say=lambda *a: None, db=db, new_db=new,
              state=st, logdir=lg, now=lambda: 1760000000)
    return kw, calls, db, st, lg


def test_accept_by_delegate_builds_records_and_audits(tmp_path):
    kw, calls, db, st, lg = env(tmp_path)
    rec = Rec()
    nb = aide.accept(SITE, "Deputy ISSO", "monthly patch window CR-12", confirm=lambda: True, rec=rec, **kw)
    assert calls == [("--check",), ("--init",)] and db.read_bytes() == b"new-db"
    assert nb["BUILT_BY"] == "accepted:Deputy ISSO" and aide.read_record(st / "baseline") == nb
    assert oct((st / "baseline").stat().st_mode & 0o777) == "0o600"
    last = aide.read_record(st / "last-result")
    assert last["EXIT"] == "0" and last["DB_MATCH"] == "yes" and last["CHANGED"] == "0"
    assert [c[0] for c in rec.calls] == ["aide-accept", "aide-accept.done"] and rec.calls[1][2] is True
    f = rec.calls[0][1]
    assert f["approver"] == "Deputy ISSO" and f["unexplained"] == 4 and f["explained"] == 0 and f["db_mismatch"] == "no"
    assert rec.calls[1][1]["new_sha512"] == nb["DB_SHA512"] and f["old_sha512"] != nb["DB_SHA512"]
    assert len(list((lg / "accepted").iterdir())) == 1


def test_accept_refuses_unlisted_approver_and_short_reason_without_touching_anything(tmp_path):
    kw, calls, db, st, _ = env(tmp_path)
    before = (st / "baseline").read_text()
    for who, why in (("Somebody", "a perfectly long reason"), ("D. Shannon", "short")):
        with pytest.raises(SiteError):
            aide.accept(SITE, who, why, confirm=lambda: True, rec=Rec(), **kw)
    assert calls == [] and db.read_bytes() == b"old-db" and (st / "baseline").read_text() == before


def test_accept_refuses_a_replaced_database_unless_investigated(tmp_path):     # Review Focus 1
    kw, calls, db, st, _ = env(tmp_path)
    db.write_bytes(b"swapped-by-someone")
    with pytest.raises(SiteError, match="investigate first"):
        aide.accept(SITE, "D. Shannon", "after the incident review", confirm=lambda: True, rec=Rec(), **kw)
    assert calls == [] and db.read_bytes() == b"swapped-by-someone"
    rec = Rec()
    aide.accept(SITE, "D. Shannon", "after the incident review", confirm=lambda: True, rec=rec,
                investigated_mismatch=True, **kw)
    assert rec.calls[0][1]["db_mismatch"] == "investigated" and db.read_bytes() == b"new-db"


def test_accept_refuses_when_the_fresh_check_fails(tmp_path):     # Review Focus 2
    kw, calls, db, st, _ = env(tmp_path, check_rc=17, check_text="config error")
    rec = Rec()
    with pytest.raises(SiteError, match="fresh AIDE check failed \\(exit 17\\)"):
        aide.accept(SITE, "D. Shannon", "routine acceptance here", confirm=lambda: True, rec=rec, **kw)
    assert calls == [("--check",)] and rec.calls == [] and db.read_bytes() == b"old-db"


def test_accept_nothing_to_accept(tmp_path):
    kw, calls, db, _, _ = env(tmp_path, check_rc=0, check_text="AIDE found NO differences")
    assert aide.accept(SITE, "D. Shannon", "routine acceptance here", confirm=lambda: True, rec=Rec(), **kw) is None
    assert calls == [("--check",)] and db.read_bytes() == b"old-db"


def test_accept_not_confirmed_changes_nothing(tmp_path):
    kw, calls, db, _, _ = env(tmp_path)
    rec = Rec()
    with pytest.raises(SiteError, match="not accepted"):
        aide.accept(SITE, "D. Shannon", "routine acceptance here", confirm=lambda: False, rec=rec, **kw)
    assert calls == [("--check",)] and rec.calls == [] and db.read_bytes() == b"old-db"


def test_accept_init_failure_keeps_the_old_baseline(tmp_path):
    kw, calls, db, st, _ = env(tmp_path, init_rc=17)
    before = (st / "baseline").read_text()
    rec = Rec()
    with pytest.raises(SiteError, match="aide --init failed"):
        aide.accept(SITE, "D. Shannon", "routine acceptance here", confirm=lambda: True, rec=rec, **kw)
    assert db.read_bytes() == b"old-db" and (st / "baseline").read_text() == before
    assert [c[0] for c in rec.calls] == ["aide-accept"]       # the request is on record; no .done


def test_wazuh_signed_package_updates_are_explained():
    # W1 Task 7 (lab): the security bundle's Wazuh RPMs are signed by Wazuh's pinned key (rpm short ID 96b3ee5f29111145);
    # without it in PINNED_SIGNERS every Wazuh file was "NOT explained" after security enable (spec §6)
    rpm = FakeRpm(owners={"/usr/lib/systemd/system/wazuh-manager.service": "wazuh-manager"},
                  info={"wazuh-manager": (2000, "96b3ee5f29111145")})
    explained, unexplained = aide.group({"added": ["/usr/lib/systemd/system/wazuh-manager.service"]}, rpm, built_epoch=1000)
    assert explained == {"wazuh-manager": ["/usr/lib/systemd/system/wazuh-manager.service"]} and unexplained == []
    assert aide.PINNED_SIGNERS["96b3ee5f29111145"] == "Wazuh"


def test_pinned_signers_match_the_release_key_list():
    # every signer AIDE trusts is a key the repo pins (appliance/release/trusted-keys.txt), and vice versa
    from pathlib import Path
    pins = [l.split()[0] for l in (Path(__file__).resolve().parents[1] / "appliance/release/trusted-keys.txt").read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    assert sorted(aide.PINNED_SIGNERS) == sorted(f[-16:].lower() for f in pins)
