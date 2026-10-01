from chp_site.hosts import parse_hosts
from chp_site.render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
from chp_site.sitefile import parse_site
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import ECDSA, GOOD

SITE = parse_site(GOOD)
HS = parse_hosts(HOSTS, SITE)


def test_net_binds_the_matched_nic_and_resolves_via_the_server():
    srv, cli = HS
    s = net_ks(SITE, srv, HS)
    assert "--device=52:54:00:c4:02:30" in s and "--ip=192.168.100.30" in s and "--netmask=255.255.255.0" in s
    assert "--gateway=192.168.100.1" in s and "--hostname=iso2-srv.iso2.lab.test" in s
    assert "--nameserver=192.168.100.30" in s                  # the server resolves via itself (dc1 lesson)
    assert "--nameserver=192.168.100.30" in net_ks(SITE, cli, HS)


def test_users_root_hash_and_keyonly_admin():
    s = users_ks(SITE, "$6$salt$hash")
    assert "rootpw --iscrypted $6$salt$hash" in s
    assert "user --name=chpadmin --groups=wheel" in s and "--password" not in s
    assert f'sshkey --username=chpadmin "{ECDSA}"' in s


def test_disk_is_luks2_on_the_chosen_disk_only():
    s = disk_ks("vda", "PASSPHRASE")
    assert "ignoredisk --only-use=vda" in s and "clearpart --all --initlabel --drives=vda" in s
    assert "--encrypted --luks-version=luks2 --passphrase=PASSPHRASE" in s
    for mnt in ("/boot/efi", "/boot", "/home", "/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "swap"):
        assert f" {mnt} " in s or f" {mnt}\n" in s or f"logvol {mnt}" in s or f"part {mnt}" in s


def test_misc_time_and_repo():
    assert "timezone America/Denver --utc" in misc_ks(SITE)
    assert "timesource --ntp-server=192.168.100.1" in misc_ks(SITE)
    assert repo_ks("file:///run/install/repo/chp") == "repo --name=chp --baseurl=file:///run/install/repo/chp\n"
