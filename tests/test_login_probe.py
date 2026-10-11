from scenarios import _login


def test_fresh_window_waits_into_the_next_30s_window():              # Review Focus 2
    slept = []
    _login.fresh_window(now=lambda: 1020.0 + 29.5, sleep=slept.append)    # 0.5 s before a boundary (1020 = 34 x 30)
    assert slept and 1.0 <= slept[0] <= 2.0                               # waits past the boundary (+1 s margin)
    slept.clear()
    _login.fresh_window(now=lambda: 1020.0 + 1.0, sleep=slept.append)     # 1 s into a window
    assert 29.0 <= slept[0] <= 31.0


def test_appliance_probe_command(monkeypatch):
    monkeypatch.setenv("IDM_PROFILE", "appliance")
    argv = _login.appliance_argv("lab01")
    assert argv[0] == "/usr/bin/expect" and argv[1].endswith("lab/iso5/login.exp")
    assert argv[2:4] == ["192.168.100.52", "lab01"] and argv[4].endswith("iso5-lab01_ecdsa")
    assert argv[5].endswith("iso5-lab01_ecdsa-cert.pub") and argv[6].endswith("iso5-lab01.ga")


def test_scenarios_carry_no_lab_literals():
    from pathlib import Path
    for f in Path(_login.__file__).parent.glob("[lc][0-9]*.py"):
        t = f.read_text()
        for lit in ("kanidm.lab.test", "192.168.100.1", "kanidm-lab-root.crt", "10-kanidm.conf", "lab_users@"):
            assert lit not in t, (f.name, lit)
