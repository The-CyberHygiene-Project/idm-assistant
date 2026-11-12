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
    s = disk_ks("vda", 120 * 2**30, "server", "PASSPHRASE")
    assert "ignoredisk --only-use=vda" in s and "clearpart --all --initlabel --drives=vda" in s
    assert "--encrypted --luks-version=luks2 --passphrase=PASSPHRASE" in s
    for mnt in ("/boot/efi", "/boot", "/home", "/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "swap"):
        assert f" {mnt} " in s or f" {mnt}\n" in s or f"logvol {mnt}" in s or f"part {mnt}" in s


def test_misc_time_and_repo():
    assert "timezone America/Denver --utc" in misc_ks(SITE)
    assert "timesource --ntp-server=192.168.100.1" in misc_ks(SITE)
    assert repo_ks("file:///run/install/repo/chp") == "repo --name=chp --baseurl=file:///run/install/repo/chp\n"


# ISSO 2026-10-10 (CUI rule grub2_password): a per-host boot-loader password, set hashed through the kickstart.
GRUB_VECTOR = ("grub.pbkdf2.sha512.10000.DCCFC1965A3FBA8A1A078FC7F109AF63631E3092F66F118B4EA6C0B15A5B74302A6370D67F2CE03D8F3BF"
               "B12A30996861B770886D999C31AEA7A561B0A634BB9.50D162EA141BD67476BF39407C64E118E17B7788E1E4CB74C304AAF3D9FC137466B7"
               "274BFB9C5FCAACF658CF17F3FA76742364899EF2282B8813246FC62AE38B")   # grub2-mkpasswd-pbkdf2 on aero, pw "chp-test-vector"


def test_grub_pbkdf2_matches_grub2_mkpasswd():
    from chp_site.render import grub_pbkdf2
    salt = bytes.fromhex(GRUB_VECTOR.split(".")[4])
    assert grub_pbkdf2("chp-test-vector", salt) == GRUB_VECTOR


def test_grub_pbkdf2_uses_a_fresh_64_byte_salt():
    from chp_site.render import grub_pbkdf2
    a, b = grub_pbkdf2("x"), grub_pbkdf2("x")
    assert a != b and len(a.split(".")[4]) == 128 and a.startswith("grub.pbkdf2.sha512.10000.")


def test_boot_ks_sets_fips_and_the_hashed_password():
    from chp_site.render import boot_ks
    assert boot_ks("grub.pbkdf2.sha512.10000.AA.BB") == \
        'bootloader --append="fips=1" --iscrypted --password=grub.pbkdf2.sha512.10000.AA.BB\n'


def test_todays_layout_unchanged_byte_for_byte():
    want = (
        "ignoredisk --only-use=vda\nclearpart --all --initlabel --drives=vda\npart /boot/efi --fstype=efi --size=1024\n"
        "part /boot --fstype=xfs --size=2048\n"
        "part pv.01 --size=1 --grow --encrypted --luks-version=luks2 --passphrase=P\nvolgroup chp pv.01\n"
        "logvol swap           --vgname=chp --name=swap          --size=8192\n"
        "logvol /home          --vgname=chp --name=home          --fstype=xfs --size=10240\n"
        "logvol /tmp           --vgname=chp --name=tmp           --fstype=xfs --size=4096\n"
        "logvol /var           --vgname=chp --name=var           --fstype=xfs --size=20480\n"
        "logvol /var/tmp       --vgname=chp --name=var_tmp       --fstype=xfs --size=4096\n"
        "logvol /var/log       --vgname=chp --name=var_log       --fstype=xfs --size=8192\n"
        "logvol /var/log/audit --vgname=chp --name=var_log_audit --fstype=xfs --size=8192\n"
        "logvol /              --vgname=chp --name=root          --fstype=xfs --size=20480 --grow\n")
    assert disk_ks("vda", 120 * 2**30, "server", "P") == want
    assert disk_ks("vda", 120 * 2**30, "client", "P") == want


def test_sized_layout_has_no_grow_and_options():
    s = disk_ks("vda", 2_000_398_934_016, "server", "P")
    assert "--grow" not in s.split("volgroup")[1]
    assert "--name=var           --fstype=xfs --size=102400" in s
    assert [l for l in s.splitlines() if l.startswith("logvol /backup")][0].endswith(
        '--size=614400 --fsoptions="nodev,nosuid,noexec"')
    assert '--fsoptions="nodev,nosuid"' in [l for l in s.splitlines() if l.startswith("logvol /data")][0]
    assert s.count("--fsoptions") == 2
