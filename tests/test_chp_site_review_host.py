import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_site import review_host as rh

NOW = 1_800_000_000.0
EXPIRES = 1_810_339_200
COLONS = f"pub:-:4096:1:96B3EE5F29111145:1470009600:{EXPIRES}::-:\nfpr:::::::::0DCFCA5547B19D2A6099506096B3EE5F29111145:\n"


def fake_run(argv, **kw):
    out = ""
    if argv[:2] == ["rpm", "-q"]:
        out = {"chp-site": "0.12.0-1.chp.el9", "chp-security": "0.4.0-1.chp.el9"}.get(argv[-1], "")
    elif argv[:1] == ["gpg"]:
        out = COLONS
    elif argv[:1] == ["openssl"]:
        return subprocess.run(argv, capture_output=True, text=True)
    return SimpleNamespace(returncode=0, stdout=out, stderr="")


def make_cert(path, days):
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(path) + ".key",
                    "-out", str(path), "-days", str(days), "-subj", "/CN=t"], check=True, capture_output=True)
    Path(str(path) + ".key").unlink()


def lab_root(tmp_path):
    r = tmp_path / "root"
    make_cert(r / "etc/pki/kanidm/chain.pem", 1)
    make_cert(r / "etc/step-ca/certs/root_ca.crt", 3650)
    (r / "etc/pki/rpm-gpg").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH").write_text("key")
    (r / "var/lib/chp/yara").mkdir(parents=True)
    (r / "var/lib/chp/yara/last-recent").write_text("1799999700\n")
    (r / "var/lib/chp/aide").mkdir(parents=True)
    (r / "var/lib/chp/aide/last-result").write_text("EPOCH=1799990000\nEXIT=0\nDB_MATCH=yes\n")
    (r / "var/lib/chp/repo/repodata").mkdir(parents=True)
    (r / "var/lib/chp/repo/repodata/repomd.xml").write_text("<repomd/>")
    return r


def body(rec):
    assert set(rec) == {"chp_review"} and set(rec["chp_review"]) == {"v", "host", "body"}   # Task 1: payload is a string
    return json.loads(rec["chp_review"]["body"])


def test_record_has_every_field_and_fits_the_limit(tmp_path):
    rec = rh.host_record(host="iso5-cli2", now=NOW, run=fake_run, root=lab_root(tmp_path))
    b = body(rec)
    assert b["host"] == "iso5-cli2" and b["time"] == NOW and b["v"] == 1
    assert b["versions"] == {"chp-site": "0.12.0-1.chp.el9", "chp-security": "0.4.0-1.chp.el9",
                             "repo": rh.repo_id(lab_root(tmp_path / "again"))}
    assert set(b["scans"]) == {"yara_recent", "yara_full", "suricata_stats", "aide_check", "aide_ok"}
    assert b["scans"]["yara_recent"] == 1799999700 and b["scans"]["aide_check"] == 1799990000 and b["scans"]["aide_ok"] is True
    assert {c["path"] for c in b["certs"]} == {"/etc/pki/kanidm/chain.pem", "/etc/step-ca/certs/root_ca.crt"}
    assert b["keys"][0]["file"] == "/etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH" and b["keys"][0]["expires"] == EXPIRES
    assert len(json.dumps(rec)) < rh.MAX_RECORD


def test_missing_state_files_are_none_not_errors(tmp_path):
    b = body(rh.host_record(host="h", now=NOW, run=fake_run, root=tmp_path / "empty"))
    assert b["scans"] == {"yara_recent": None, "yara_full": None, "suricata_stats": None, "aide_check": None, "aide_ok": None}
    assert b["certs"] == [] and b["keys"] == [] and b["versions"]["repo"] is None and b["sys"] == {}


def test_find_certs_reads_not_before_and_not_after(tmp_path):
    r = lab_root(tmp_path)
    certs = {c["path"]: c for c in rh.cert_dates(r, fake_run)}
    k = certs["/etc/pki/kanidm/chain.pem"]
    assert 0 < k["not_after"] - k["not_before"] <= 86400 + 60
    assert certs["/etc/step-ca/certs/root_ca.crt"]["not_after"] - certs["/etc/step-ca/certs/root_ca.crt"]["not_before"] > 3000 * 86400


def test_pinned_key_expiry_uses_a_private_gnupg_home(tmp_path):
    seen = []
    def run(argv, **kw):
        seen.append(argv); return fake_run(argv, **kw)
    keys = rh.pinned_keys(lab_root(tmp_path), run)
    assert keys == [{"file": "/etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH", "fpr": "0DCFCA5547B19D2A6099506096B3EE5F29111145",
                     "expires": EXPIRES}]
    g = [a for a in seen if a[:1] == ["gpg"]]
    assert g and all("--homedir" in a for a in g)


def test_key_without_expiry_is_none(tmp_path):
    def run(argv, **kw):
        if argv[:1] == ["gpg"]:
            return SimpleNamespace(returncode=0, stdout="pub:-:4096:1:AAAA:1470009600:::-:\nfpr:::::::::AB:\n", stderr="")
        return fake_run(argv, **kw)
    assert rh.pinned_keys(lab_root(tmp_path), run)[0]["expires"] is None


def test_record_holds_no_secrets(tmp_path):
    r = lab_root(tmp_path)
    (r / "var/ossec/etc").mkdir(parents=True); (r / "var/ossec/etc/client.keys").write_text("001 ws1 any SECRETKEY\n")
    t = json.dumps(rh.host_record(host="h", now=NOW, run=fake_run, root=r))
    assert "BEGIN" not in t and "SECRETKEY" not in t and "PRIVATE" not in t


def test_append_writes_one_line_0640(tmp_path):
    log = tmp_path / "chp-review.json"
    rh.append(rh.host_record(host="h", now=NOW, run=fake_run, root=tmp_path / "e"), log)
    rh.append(rh.host_record(host="h", now=NOW + 600, run=fake_run, root=tmp_path / "e"), log)
    lines = log.read_text().splitlines()
    assert len(lines) == 2 and all(json.loads(x)["chp_review"]["host"] == "h" for x in lines)
    assert oct(log.stat().st_mode & 0o777) == "0o640"


def test_cli_prints_one_line(capsys, monkeypatch, tmp_path):
    from chp_site import cli
    monkeypatch.setattr(rh, "host_record", lambda **kw: {"chp_review": {"v": 1, "host": "h", "body": "{}"}})
    assert cli.main(["review", "host-record"]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and json.loads(out)["chp_review"]["host"] == "h"


def test_record_carries_when_the_add_on_was_enabled(tmp_path):
    import os
    r = lab_root(tmp_path); (r / "etc/chp").mkdir(parents=True); c = r / "etc/chp/security.conf"; c.write_text("ROLE=client\n")
    os.utime(c, (1_799_000_000, 1_799_000_000))
    assert body(rh.host_record(host="h", now=NOW, run=fake_run, root=r))["security_since"] == 1_799_000_000
    assert body(rh.host_record(host="h", now=NOW, run=fake_run, root=tmp_path / "none"))["security_since"] is None
