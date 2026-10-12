import subprocess
import sys
from pathlib import Path

from tests.test_chp_site_clientconf import FX
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import GOOD

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "appliance" / "chp-site"


def cli(*args):
    return subprocess.run([sys.executable, "-m", "chp_site.cli", *args], cwd=PKG, capture_output=True, text=True)


def site(tmp_path, extra=""):
    d = tmp_path / "s"; d.mkdir()
    (d / "site.conf").write_text(GOOD + extra); (d / "hosts").write_text(HOSTS)
    return d


def test_validate_ok_and_host_found(tmp_path):
    from chp_site.clientconf import make_client_conf
    d = site(tmp_path)
    (d / "client.conf").write_text(make_client_conf("iso2.lab.test", (FX / "root_ca.crt").read_text(), (FX / "user_ca.pub").read_text(), (FX / "cache_key.pub").read_text()))
    r = cli("validate", "--site", str(d), "--mac", "52-54-00-C4-02-31")
    assert r.returncode == 0 and "iso2-cli" in r.stdout and "client" in r.stdout


def test_validate_error_is_one_readable_line(tmp_path):
    r = cli("validate", "--site", str(site(tmp_path, "BOGUS=1\n")))
    assert r.returncode == 2 and r.stderr.strip() == "chp-site: site.conf: unknown key BOGUS"


def test_export_client_writes_and_prints_fingerprints(tmp_path):
    d = site(tmp_path); stick = tmp_path / "stick"; stick.mkdir()
    r = cli("export-client", "--stick", str(stick), "--site", str(d / "site.conf"),
            "--root", str(FX / "root_ca.crt"), "--ssh-ca", str(FX / "user_ca.pub"), "--cache-key", str(FX / "cache_key.pub"))
    assert r.returncode == 0, r.stderr
    assert "CA root SHA-256:" in r.stdout and "SSH CA fingerprint: SHA256:" in r.stdout
    c = cli("validate", "--site", str(d), "--role", "client")      # spec 4.2: a client site needs client.conf (final review I2)
    assert c.returncode == 2 and "client.conf" in c.stderr
    c = cli("validate", "--site", str(d), "--mac", "52:54:00:c4:02:31")   # a MAC that resolves to a client: the same
    assert c.returncode == 2 and "client.conf" in c.stderr
    (d / "client.conf").write_text((stick / "client.conf").read_text())
    assert cli("validate", "--site", str(d), "--role", "client").returncode == 0


def test_zipapp_builds_and_runs(tmp_path):
    subprocess.run(["bash", str(PKG / "build.sh")], check=True, capture_output=True)
    pyz = PKG / "dist" / "chp-site.pyz"
    # no shebang: a plain zip (application/zip) is not a "language" file to fapolicyd, so rpmbuild may read it;
    # hosts run it through the /usr/bin/chp-site shell wrapper, the installer and the Mac as `python3 chp-site.pyz`
    assert pyz.read_bytes()[:2] == b"PK"
    r = subprocess.run([sys.executable, str(pyz), "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "chp-site 0.7.0"


def test_wrapper_runs_the_packaged_zipapp():
    w = (PKG / "chp-site.sh").read_text()
    assert w.startswith("#!/bin/sh\n")
    assert 'exec /usr/bin/python3 /usr/share/chp-site/chp-site.pyz "$@"' in w


def test_non_utf8_file_is_a_readable_error_not_a_traceback(tmp_path):    # final review Minor 1 (Review Focus 1)
    d = site(tmp_path)
    (d / "site.conf").write_bytes(GOOD.replace("D. Shannon", "Pat O\u2019Brien").encode("cp1252"))
    r = cli("validate", "--site", str(d))
    assert r.returncode == 2 and "not UTF-8 text" in r.stderr and "Traceback" not in r.stderr


def test_onboard_help_lists_the_options():
    r = cli("onboard", "--help")
    assert r.returncode == 0 and all(o in r.stdout for o in ("--group", "--ssh-key", "--replace-key", "--as", "--display"))


def test_export_client_moves_pending_client_tokens(tmp_path):
    d = site(tmp_path); stick = tmp_path / "stick"; stick.mkdir()
    pend = tmp_path / "pend"; (pend / "tokens").mkdir(parents=True)
    tok = "a" * 20 + "." + "b" * 20 + "." + "c" * 20
    (pend / "tokens" / "iso2-cli.token").write_text(tok + "\n")
    r = cli("export-client", "--stick", str(stick), "--site", str(d / "site.conf"), "--pending", str(pend),
            "--root", str(FX / "root_ca.crt"), "--ssh-ca", str(FX / "user_ca.pub"), "--cache-key", str(FX / "cache_key.pub"))
    assert r.returncode == 0, r.stderr
    assert "tokens moved to the stick: iso2-cli" in r.stdout and tok not in r.stdout
    assert (stick / "tokens" / "iso2-cli.token").read_text().strip() == tok and not (pend / "tokens" / "iso2-cli.token").exists()


def test_client_token_help():
    r = cli("client-token", "--help")
    assert r.returncode == 0 and "--as" in r.stdout


def test_authselect_patch_subcommand(tmp_path):
    d = tmp_path / "p"; d.mkdir()
    (d / "system-auth").write_text("auth        required      pam_env.so\nauth        required      pam_faillock.so preauth silent\n"
                                   "auth        sufficient    pam_unix.so\n")
    (d / "password-auth").write_text("auth        sufficient    pam_unix.so\n")
    (d / "nsswitch.conf").write_text("passwd:     files systemd\ngroup:      files\ninitgroups: files\n")
    r = cli("authselect-patch", str(d))
    assert r.returncode == 0, r.stderr
    assert "pam_kanidm.so" in (d / "system-auth").read_text()
    assert (d / "nsswitch.conf").read_text().splitlines()[2].split()[:2] == ["initgroups:", "kanidm"]
    from chp_site.authselect_ga import GA_LINES
    sa = (d / "system-auth").read_text()
    assert sa.count(GA_LINES[1]) == 1 and sa.index(GA_LINES[1]) < sa.index("pam_kanidm.so")
    assert GA_LINES[1] in (d / "password-auth").read_text()


def test_aide_pin_and_verify_with_a_stick_dir(tmp_path, monkeypatch, capsys):
    from chp_site import aide, cli as cli_mod
    st = tmp_path / "state"; db = tmp_path / "aide.db.gz"; db.write_bytes(b"db")
    aide.write_record(st / "baseline", aide.baseline_record(db, "first-boot", 1000), 0o600)
    monkeypatch.setattr(aide, "STATE", st); monkeypatch.setattr(aide, "DB", db)
    monkeypatch.setattr(cli_mod, "_host", lambda: "iso5-srv")
    stick = tmp_path / "stick"; stick.mkdir()
    assert cli_mod.main(["aide-pin", "--stick", str(stick)]) == 0
    assert (stick / "aide" / "iso5-srv.txt").exists()
    assert aide.read_record(st / "pinned")["DB_SHA512"] == aide.sha512_file(db)
    assert cli_mod.main(["aide-verify-pin", "--stick", str(stick)]) == 0 and "MATCH" in capsys.readouterr().out
    db.write_bytes(b"tampered")
    assert cli_mod.main(["aide-verify-pin", "--stick", str(stick)]) == 1 and "MISMATCH" in capsys.readouterr().out


def test_aide_pin_without_baseline_is_a_readable_error(tmp_path, monkeypatch, capsys):
    from chp_site import aide, cli as cli_mod
    monkeypatch.setattr(aide, "STATE", tmp_path / "none")
    stick = tmp_path / "stick"; stick.mkdir()
    assert cli_mod.main(["aide-pin", "--stick", str(stick)]) == 2
    assert "no AIDE baseline" in capsys.readouterr().err


def test_aide_accept_wires_through_and_pins(tmp_path, monkeypatch, capsys):
    from chp_site import aide, cli as cli_mod
    seen = {}

    def fake_accept(site, approver, reason, **kw):
        seen.update(approver=approver, reason=reason, mismatch=kw["investigated_mismatch"], yes=kw["confirm"]())
        return {"DB_SHA512": "x"}
    monkeypatch.setattr(aide, "accept", fake_accept)
    monkeypatch.setattr(cli_mod, "_aide_pin", lambda a: print("PINNED"))
    rc = cli_mod.main(["aide-accept", "--approver", "D. Shannon", "--reason", "patch window CR-12", "--yes",
                   "--site", str(site(tmp_path))])
    assert rc == 0 and seen == {"approver": "D. Shannon", "reason": "patch window CR-12", "mismatch": False, "yes": True}
    assert "PINNED" in capsys.readouterr().out


def test_aide_accept_without_a_stick_still_succeeds(tmp_path, monkeypatch, capsys):
    from chp_site import aide, cli as cli_mod
    from chp_site.sitefile import SiteError
    monkeypatch.setattr(aide, "accept", lambda *a, **k: {"DB_SHA512": "x"})

    def no_stick(a):
        raise SiteError("no site stick found: plug in the USB stick labelled OEMDRV")
    monkeypatch.setattr(cli_mod, "_aide_pin", no_stick)
    rc = cli_mod.main(["aide-accept", "--approver", "D. Shannon", "--reason", "patch window CR-12", "--yes",
                   "--site", str(site(tmp_path))])
    assert rc == 0 and "NOT pinned yet" in capsys.readouterr().out


def test_version_is_0_7_0(capsys):
    import pytest
    from chp_site import cli as cli_mod
    with pytest.raises(SystemExit):
        cli_mod.main(["--version"])
    assert "chp-site 0.7.0" in capsys.readouterr().out


def test_export_client_pins_the_aide_baseline_when_there_is_one(tmp_path, monkeypatch, capsys):
    from chp_site import aide, cli as cli_mod
    args = lambda stick: ["export-client", "--stick", str(stick), "--site", str(d / "site.conf"),
                          "--pending", str(tmp_path / "pending"), "--root", str(FX / "root_ca.crt"),
                          "--ssh-ca", str(FX / "user_ca.pub"), "--cache-key", str(FX / "cache_key.pub")]
    d = site(tmp_path); st = tmp_path / "state"
    monkeypatch.setattr(aide, "STATE", st)
    s1 = tmp_path / "s1"; s1.mkdir()
    assert cli_mod.main(args(s1)) == 0 and "no AIDE baseline yet" in capsys.readouterr().out
    assert not (s1 / "aide").exists()
    db = tmp_path / "aide.db.gz"; db.write_bytes(b"db")
    aide.write_record(st / "baseline", aide.baseline_record(db, "first-boot", 1000), 0o600)
    s2 = tmp_path / "s2"; s2.mkdir()
    assert cli_mod.main(args(s2)) == 0 and "AIDE baseline pinned: aide/" in capsys.readouterr().out
    recs = list((s2 / "aide").glob("*.txt"))
    assert len(recs) == 1 and aide.read_record(recs[0])["DB_SHA512"] == aide.sha512_file(db)
    assert aide.read_record(st / "pinned")["DB_SHA512"] == aide.sha512_file(db)
