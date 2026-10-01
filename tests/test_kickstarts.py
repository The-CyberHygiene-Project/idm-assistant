import re
import shutil
import subprocess
from pathlib import Path

import pytest

from chp_site.hosts import parse_hosts
from chp_site.render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
from chp_site.sitefile import parse_site
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import GOOD

KS = Path(__file__).resolve().parents[1] / "appliance" / "kickstart"
HEADER = (Path(__file__).resolve().parents[1] / "appliance" / "branding" / "file-header.txt").read_text()


@pytest.mark.parametrize("role", ["server", "client"])
def test_committed_kickstart_equals_the_template(role):
    import subprocess, tempfile, shutil
    with tempfile.TemporaryDirectory() as d:
        for f in ("chp.ks.in", "render-ks.sh"):
            shutil.copy(KS / f, d)
        subprocess.run(["bash", f"{d}/render-ks.sh"], check=True, capture_output=True)
        assert (KS / f"{role}.ks").read_text() == open(f"{d}/{role}.ks").read()


@pytest.mark.parametrize("role", ["server", "client"])
def test_kickstart_rules(role):
    t = (KS / f"{role}.ks").read_text()
    assert t.startswith(HEADER)
    assert "--erroronfail" in t and "%pre" in t and f"pre --role {role}" in t
    for inc in ("misc", "net", "users", "disk", "repo"):
        assert f"%include /tmp/chp/{inc}.ks" in t
    assert "fips=1" in t and "selinux --enforcing" in t and "content_profile_cui" in t
    assert "--passphrase" not in t and "rootpw --plaintext" not in t     # secrets only ever come from /tmp/chp
    assert not re.search(r"cp .*escrow|escrow.*/mnt/sysimage", t)      # the escrow never reaches the host


@pytest.mark.skipif(shutil.which("uvx") is None, reason="needs uvx (pykickstart)")
@pytest.mark.parametrize("role,host", [("server", 0), ("client", 1)])
def test_kickstart_with_snippets_validates(tmp_path, role, host):
    site = parse_site(GOOD); hs = parse_hosts(HOSTS, site)
    snip = {"misc": misc_ks(site), "net": net_ks(site, hs[host], hs), "users": users_ks(site, "$6$x$y"),
            "disk": disk_ks("vda", "test-only"), "repo": repo_ks("file:///run/install/repo/chp")}
    t = (KS / f"{role}.ks").read_text()
    for k, v in snip.items():
        t = t.replace(f"%include /tmp/chp/{k}.ks", v.rstrip("\n"))
    f = tmp_path / "ks.cfg"; f.write_text(t)
    r = subprocess.run(["uvx", "--from", "pykickstart", "ksvalidator", "-v", "RHEL9", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("role", ["server", "client"])
def test_nochroot_post_stops_on_failure_and_marks_the_escrow_completed(role):   # final review I1 + Minor 7
    t = (KS / f"{role}.ks").read_text()
    post = t[t.index("%post --nochroot"):]
    post = post[:post.index("%end")]
    assert "--erroronfail" in post.splitlines()[0]
    assert "INSTALL COMPLETED" in post and "/tmp/chp/escrow-name" in post


def _section(t, head):
    s = t[t.index(head):]
    return s[:s.index("%end")]


def test_role_packages():                                              # Plan 3a Task 5
    srv = _section((KS / "server.ks").read_text(), "%packages")
    cli_ = _section((KS / "client.ks").read_text(), "%packages")
    assert "\nchp-base\n" in srv and "\nchp-identity-server\n" in srv
    assert "\nchp-base\n" in cli_ and "chp-identity-server" not in cli_


@pytest.mark.parametrize("role", ["server", "client"])
def test_one_time_luks_key_for_the_first_boot_tpm_bind(role):
    post = _section((KS / f"{role}.ks").read_text(), "%post --nochroot")
    assert "cryptsetup luksAddKey --key-file=/tmp/chp/luks-pass" in post and "/mnt/sysimage/root/.chp-bind.key" in post
    assert "head -c 64 /dev/urandom" in post and "umask 0377" in post
    assert "shred -u /tmp/chp/luks-pass" in post
    assert post.index("luksAddKey") < post.index("shred -u /tmp/chp/luks-pass")


def test_units_enabled_per_role():
    srv = _section((KS / "server.ks").read_text(), "%post --log=/root/chp-post.log")
    cli_ = _section((KS / "client.ks").read_text(), "%post --log=/root/chp-post.log")
    for u in ("chp-firstboot-common.service", "chp-monitor.timer"):
        assert u in srv and u in cli_
    assert "chp-server-firstboot.service" in srv and "chp-server-firstboot.service" not in cli_


@pytest.mark.parametrize("role", ["server", "client"])
def test_site_stick_pin_is_copied_to_etc_chp(role):
    post = _section((KS / f"{role}.ks").read_text(), "%post --nochroot")
    assert "/tmp/chp/site-stick.id" in post and "/mnt/sysimage/etc/chp/site-stick.id" in post
