from chp_site.layout import note, plan, unallocated_gib


def gib(vols): return {v.mount: v.mib // 1024 for v in vols}


def test_2tb_server_is_the_spec_table():
    vols, grow = plan("server", 2_000_398_934_016)
    assert not grow
    assert gib(vols) == {"/": 90, "/var": 100, "/var/log": 50, "/var/log/audit": 30, "/var/tmp": 15, "/tmp": 15,
                         "swap": 29, "/home": 238, "/data": 350, "/backup": 600}
    assert unallocated_gib("server", 2_000_398_934_016) == 342


def test_other_server_sizes():   # 960 GB, 1 TB, 4 TB: (home, data, backup, unallocated)
    for b, want in ((960_197_124_096, (87, 128, 220, 127)), (1_000_204_886_016, (93, 137, 234, 135)),
                    (4_000_787_030_016, (529, 777, 1330, 757))):
        g = gib(plan("server", b)[0]); assert (g["/home"], g["/data"], g["/backup"], unallocated_gib("server", b)) == want


def test_workstation_layout():   # 512 GiB lab disk, 256 GB, 240 GB
    for b, home, free in ((512 * 2**30, 101, 303), (256_060_514_304, 32, 99), (240_057_409_536, 29, 87)):
        g = gib(plan("client", b)[0])
        assert g["/"] == 40 and g["/var/log"] == 20 and g["/home"] == home and "/data" not in g and "/backup" not in g
        assert unallocated_gib("client", b) == free


def test_small_disks_keep_todays_layout():
    for role, b in (("server", 120 * 2**30), ("server", 899_999_999_999), ("client", 120 * 2**30),
                    ("client", 239_999_999_999)):
        vols, grow = plan(role, b)
        assert grow and gib(vols)["/var"] == 20 and gib(vols)["/home"] == 10 and "/data" not in gib(vols)


def test_thresholds():
    assert not plan("server", 900_000_000_000)[1] and not plan("client", 240_000_000_000)[1]
    assert "smaller than the recommended 2 TB" in note("server", 1_000_204_886_016)
    assert "smaller than the recommended 2 TB" in note("server", 120 * 2**30)
    assert note("server", 1_900_000_000_000) == "" and note("client", 512 * 2**30) == ""
    assert note("client", 120 * 2**30) == ""


def test_mount_options():
    o = {v.mount: v.fsoptions for v in plan("server", 2_000_398_934_016)[0]}
    assert o["/data"] == "nodev,nosuid" and o["/backup"] == "nodev,nosuid,noexec"


def test_volumes_always_fit():
    for role in ("server", "client"):
        for b in range(100 * 10**9, 8 * 10**12, 37 * 10**9):
            vols, _ = plan(role, b)
            assert sum(v.mib for v in vols) <= b // 2**20 - 3072 - 64
