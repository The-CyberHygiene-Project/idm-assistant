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
