import json
import os
import stat
from pathlib import Path

import pytest

from chp_site.pre import Facts, run_pre
from chp_site.sitefile import SiteError
from tests.test_chp_site_clientconf import CACHE, PEM, PUB
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
        (s / "client.conf").write_text(make_client_conf("iso2.lab.test", PEM, PUB, CACHE))
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


def test_server_install_escrows_a_boot_loader_password_and_writes_only_its_hash(tmp_path):
    h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
    esc = (s / "escrow" / "iso2-srv.txt").read_text()
    assert "GRUB_PASSWORD=" + "S" * 18 in esc
    p = out / "boot.ks"
    assert p.exists() and stat.S_IMODE(p.stat().st_mode) == 0o600
    b = p.read_text()
    assert b.startswith('bootloader --append="fips=1" --iscrypted --password=grub.pbkdf2.sha512.10000.')
    assert "S" * 18 not in b


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


def test_site_stick_identity_is_recorded_for_the_host(tmp_path):        # user request: pin the site stick
    s = stick(tmp_path); out = tmp_path / "out"
    run_pre("server", s, out, "file:///x", facts(["52:54:00:c4:02:30"]), hasher=lambda p: "$6$h",
            secret=lambda n: "S" * n, stick_id={"ID": "46f4:0001", "SERIAL": "ABC123", "NAME": "Site Stick"})
    assert (out / "site-stick.id").read_text() == "ID=46f4:0001\nSERIAL=ABC123\nNAME=Site Stick\n"


TOKEN = "eyJhbGciOiJFUzI1NiJ9AAAAAAAAAAAA.eyJzdWIiOiJ1bml4ZC1jbGkifQAAAAAAA.c2lnbmF0dXJlc2lnbmF0dXJlc2ln"
CLI_MAC = ["52:54:00:c4:02:31"]


def test_client_needs_its_own_token_before_any_disk(tmp_path):       # Review Focus 3
    s = stick(tmp_path)
    with pytest.raises(SiteError, match=r"no unixd token for iso2-cli.*chp-site client-token iso2-cli"):
        run(tmp_path, "client", CLI_MAC, stick_dir=s)
    assert not (s / "escrow").exists() and not (tmp_path / "out").exists()


def test_client_token_staged_0600(tmp_path):
    s = stick(tmp_path); (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text(TOKEN + "\n")
    h, s, out = run(tmp_path, "client", CLI_MAC, stick_dir=s)
    t = out / "unixd.token"
    assert h.hostname == "iso2-cli" and t.read_text() == TOKEN and stat.S_IMODE(t.stat().st_mode) == 0o600


def test_client_token_garbage_refused(tmp_path):
    s = stick(tmp_path); (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text("not a token\n")
    with pytest.raises(SiteError, match="is not a Kanidm API token"):
        run(tmp_path, "client", CLI_MAC, stick_dir=s)


def test_server_gets_no_token_file(tmp_path):
    h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
    assert not (out / "unixd.token").exists()


# ---- security bundle W2 ----
WKEY = "001 iso2-cli 192.168.100.31 " + "ab" * 32 + "\n"


def addon_stick(tmp_path, key=True):
    s = stick(tmp_path); (s / "site.conf").write_text(GOOD + "SECURITY_ADDONS=yes\n")
    (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text(TOKEN + "\n")
    if key:
        (s / "wazuh").mkdir(); (s / "wazuh" / "iso2-cli.key").write_text(WKEY)
    return s


def test_pre_stages_this_clients_wazuh_key_when_the_add_on_is_on(tmp_path):
    h, s, out = run(tmp_path, "client", CLI_MAC, stick_dir=addon_stick(tmp_path))
    k = out / "wazuh.key"
    assert k.read_text() == WKEY and stat.S_IMODE(k.stat().st_mode) == 0o600
    assert (out / "security-addons").read_text().strip() == "yes"
    assert (out / "repo-dir").read_text().strip() == "/run/install/repo/chp"     # the ISO's repo, not the stick


def test_pre_refuses_a_client_without_its_wazuh_key_before_any_disk(tmp_path):
    s = addon_stick(tmp_path, key=False)
    with pytest.raises(SiteError, match=r"no Wazuh agent key for iso2-cli .*export-client"):
        run(tmp_path, "client", CLI_MAC, stick_dir=s)
    assert not (s / "escrow").exists() and not (tmp_path / "out").exists()


def test_pre_refuses_another_hosts_wazuh_key(tmp_path):
    s = addon_stick(tmp_path); (s / "wazuh" / "iso2-cli.key").write_text(WKEY.replace("iso2-cli", "iso2-xyz"))
    with pytest.raises(SiteError, match="not iso2-cli's"):
        run(tmp_path, "client", CLI_MAC, stick_dir=s)


def test_pre_add_on_off_stages_nothing(tmp_path):
    s = stick(tmp_path); (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text(TOKEN + "\n")
    h, s, out = run(tmp_path, "client", CLI_MAC, stick_dir=s)
    assert not (out / "wazuh.key").exists() and (out / "security-addons").read_text().strip() == "no"


def test_pre_network_repo_writes_no_repo_dir(tmp_path):
    s = addon_stick(tmp_path); out = tmp_path / "out"
    run_pre("client", s, out, "http://192.0.2.1/chp", facts(CLI_MAC), hasher=lambda pw: "$6$x$" + str(len(pw)),
            secret=lambda n: "S" * n)
    assert not (out / "repo-dir").exists()


def test_second_disk_is_never_in_the_kickstart(tmp_path):
    two = [("vda", 120 * G, "virtio", False, "disk"), ("vdb", 500 * G, "virtio", False, "disk")]
    s = stick(tmp_path); (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text(TOKEN + "\n")
    h, s, out = run(tmp_path, "client", ["52:54:00:c4:02:31"], stick_dir=s, facts=facts(["52:54:00:c4:02:31"], two))
    ks = (out / "disk.ks").read_text()
    assert "vda" in ks and "vdb" not in ks


def test_disk_note_written_below_recommended(tmp_path):
    h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
    assert "smaller than the recommended 2 TB" in (out / "disk-note").read_text()
    (tmp_path / "b").mkdir()
    big = [("vda", 2_000_398_934_016, "nvme", False, "disk")]
    h, s, out = run(tmp_path / "b", "server", ["52:54:00:c4:02:30"], facts=facts(["52:54:00:c4:02:30"], big))
    assert not (out / "disk-note").exists()
