import json
import os
import stat
from pathlib import Path

import pytest

from chp_site.pre import Facts, run_pre
from chp_site.sitefile import SiteError
from tests.test_chp_site_clientconf import PEM, PUB
from chp_site.clientconf import make_client_conf
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import GOOD

G = 1_000_000_000
ONE_DISK = [("vda", 120 * G, "virtio", False, "disk")]


def facts(macs, disks=ONE_DISK):
    from chp_site.disks import disks_from_lsblk
    lsblk = json.dumps({"blockdevices": [dict(zip(("name", "size", "tran", "rm", "type"), d)) for d in disks]})
    return Facts(macs, disks_from_lsblk(lsblk, {}), "20260930T120000Z")


def stick(tmp_path, client_conf=True):
    s = tmp_path / "stick"; s.mkdir()
    (s / "site.conf").write_text(GOOD); (s / "hosts").write_text(HOSTS)
    if client_conf:
        (s / "client.conf").write_text(make_client_conf("iso2.lab.test", PEM, PUB))
    return s


def run(tmp_path, role, macs, **kw):
    s = kw.pop("stick_dir", None) or stick(tmp_path)
    out = tmp_path / "out"
    h = run_pre(role, s, out, "file:///run/install/repo/chp", kw.pop("facts", facts(macs)),
                hasher=lambda pw: "$6$fake$" + str(len(pw)), secret=lambda n: "S" * n)
    return h, s, out


def test_server_install_writes_snippets_and_escrow(tmp_path):
    h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
    assert h.hostname == "iso2-srv"
    for f in ("misc", "net", "users", "disk", "repo"):
        p = out / f"{f}.ks"
        assert p.exists() and stat.S_IMODE(p.stat().st_mode) == 0o600
    esc = (s / "escrow" / "iso2-srv.txt").read_text()
    assert "LUKS_PASSPHRASE=" + "S" * 32 in esc and "ROOT_CONSOLE_PASSWORD=" in esc
    assert "--passphrase=" + "S" * 32 in (out / "disk.ks").read_text()
    assert "S" * 32 not in (out / "users.ks").read_text()     # only the hash goes to users.ks


def test_role_must_match_the_boot_entry(tmp_path):
    with pytest.raises(SiteError, match="booted the client installer.*server"):
        run(tmp_path, "client", ["52:54:00:c4:02:30"])


def test_client_needs_a_valid_client_conf(tmp_path):
    s = stick(tmp_path, client_conf=False)
    with pytest.raises(SiteError, match="client.conf"):
        run(tmp_path, "client", ["52:54:00:c4:02:31"], stick_dir=s)


def test_nothing_is_written_when_validation_fails(tmp_path):
    s = stick(tmp_path)
    with pytest.raises(SiteError, match="not in the hosts table"):
        run(tmp_path, "server", ["aa:bb:cc:dd:ee:ff"], stick_dir=s)
    assert not (s / "escrow").exists() and not (tmp_path / "out").exists()


def test_read_only_stick_stops_the_install(tmp_path):                # Review Focus 3
    s = stick(tmp_path)
    os.chmod(s, 0o555)
    try:
        with pytest.raises(SiteError, match="cannot write the escrow.*stick"):
            run(tmp_path, "server", ["52:54:00:c4:02:30"], stick_dir=s)
        assert not (tmp_path / "out").exists()
    finally:
        os.chmod(s, 0o755)


def test_reinstall_keeps_the_previous_escrow(tmp_path):              # Review Focus 4
    s = stick(tmp_path)
    (s / "escrow").mkdir(); (s / "escrow" / "iso2-srv.txt").write_text("OLD\n")
    run(tmp_path, "server", ["52:54:00:c4:02:30"], stick_dir=s)
    olds = list((s / "escrow").glob("iso2-srv.txt.*.old"))
    assert len(olds) == 1 and olds[0].read_text() == "OLD\n"
    assert "LUKS_PASSPHRASE=" in (s / "escrow" / "iso2-srv.txt").read_text()


def test_disk_rules_apply(tmp_path):
    two = [("vda", 120 * G, "virtio", False, "disk"), ("vdb", 120 * G, "virtio", False, "disk")]
    with pytest.raises(SiteError, match="name one in the hosts table"):
        run(tmp_path, "server", ["52:54:00:c4:02:30"], facts=facts(["52:54:00:c4:02:30"], two))


def test_escrow_header_says_it_is_valid_only_after_completion(tmp_path):   # final review I1
    h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
    esc = (s / "escrow" / "iso2-srv.txt").read_text()
    assert "installed" not in esc.splitlines()[0]
    assert "valid only if a line 'INSTALL COMPLETED' follows" in esc
    assert (out / "escrow-name").read_text() == "iso2-srv"          # %post --nochroot appends the completion line


def test_luks_pass_for_post_nochroot(tmp_path):                        # Plan 3a Task 2
    h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
    p = out / "luks-pass"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and p.read_text() == "S" * 32
    assert ("--passphrase=" + p.read_text()) in (out / "disk.ks").read_text()
    assert "S" * 32 not in (out / "users.ks").read_text()
