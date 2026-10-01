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
    (d / "client.conf").write_text(make_client_conf("iso2.lab.test", (FX / "root_ca.crt").read_text(), (FX / "user_ca.pub").read_text()))
    r = cli("validate", "--site", str(d), "--mac", "52-54-00-C4-02-31")
    assert r.returncode == 0 and "iso2-cli" in r.stdout and "client" in r.stdout


def test_validate_error_is_one_readable_line(tmp_path):
    r = cli("validate", "--site", str(site(tmp_path, "BOGUS=1\n")))
    assert r.returncode == 2 and r.stderr.strip() == "chp-site: site.conf: unknown key BOGUS"


def test_export_client_writes_and_prints_fingerprints(tmp_path):
    d = site(tmp_path); stick = tmp_path / "stick"; stick.mkdir()
    r = cli("export-client", "--stick", str(stick), "--site", str(d / "site.conf"),
            "--root", str(FX / "root_ca.crt"), "--ssh-ca", str(FX / "user_ca.pub"))
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
    assert r.returncode == 0 and r.stdout.strip() == "chp-site 0.2.2"


def test_wrapper_runs_the_packaged_zipapp():
    w = (PKG / "chp-site.sh").read_text()
    assert w.startswith("#!/bin/sh\n")
    assert 'exec /usr/bin/python3 /usr/share/chp-site/chp-site.pyz "$@"' in w


def test_non_utf8_file_is_a_readable_error_not_a_traceback(tmp_path):    # final review Minor 1 (Review Focus 1)
    d = site(tmp_path)
    (d / "site.conf").write_bytes(GOOD.replace("D. Shannon", "Pat O\u2019Brien").encode("cp1252"))
    r = cli("validate", "--site", str(d))
    assert r.returncode == 2 and "not UTF-8 text" in r.stderr and "Traceback" not in r.stderr
