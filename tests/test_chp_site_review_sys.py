from pathlib import Path

from chp_site import review_sys as rs

FX = Path(__file__).parent / "fixtures" / "review" / "sadf-day.json"


def test_summary_from_a_real_day():                        # captured with sadc on iso5-cli2 (R1 Task 4)
    s = rs.day_summary(FX.read_text())
    assert s == {"cpu": {"avg": 3.2, "peak": 10.0}, "mem": {"avg_pct": 20.3, "peak_pct": 20.3},
                 "net": {"rx_kbs_avg": 6.2, "tx_kbs_avg": 80.4}, "samples": 5}


def test_loopback_is_not_counted():
    s = rs.day_summary(FX.read_text())
    assert s["net"]["rx_kbs_avg"] < 23.1                     # enp1s0 only; lo would not raise it, but must not count


def test_empty_or_bad_input_is_empty_dict():
    assert rs.day_summary("") == {} and rs.day_summary("not json") == {} and rs.day_summary('{"sysstat": {"hosts": []}}') == {}


def test_disk_use_from_df():
    df = ("Filesystem     1024-blocks    Used Available Capacity Mounted on\n"
          "/dev/mapper/r  10000000 4500000  5500000      45% /\n"
          "tmpfs            100000       0   100000       0% /dev/shm\n"
          "/dev/vda1       1000000  910000    90000      91% /boot\n")
    assert rs.disk_use(df) == [{"mount": "/", "used_pct": 45}, {"mount": "/boot", "used_pct": 91}]


def test_today_combines_sysstat_and_df():
    from types import SimpleNamespace as N
    def run(argv, **kw):
        if argv[0] == "sadf":
            return N(returncode=0, stdout=FX.read_text(), stderr="")
        return N(returncode=0, stdout="Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 5 50% /\n", stderr="")
    s = rs.today(run)
    assert s["samples"] == 5 and s["disk"] == [{"mount": "/", "used_pct": 50}]


def test_today_without_sysstat_is_disk_only():
    from types import SimpleNamespace as N
    def run(argv, **kw):
        if argv[0] == "sadf":
            return N(returncode=1, stdout="", stderr="no data")
        return N(returncode=0, stdout="h\n/dev/x 10 5 5 50% /\n", stderr="")
    assert rs.today(run) == {"disk": [{"mount": "/", "used_pct": 50}]}


def test_today_when_sadf_or_df_is_missing():                # a host without sysstat still sends its record
    def run(argv, **kw):
        raise FileNotFoundError(argv[0])
    assert rs.today(run) == {}
