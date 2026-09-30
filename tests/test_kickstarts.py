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
    assert (KS / f"{role}.ks").read_text() == (KS / "chp.ks.in").read_text().replace("@ROLE@", role)


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
