import os
import subprocess
from pathlib import Path

M = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-security" / "monitor.d"


def run(tmp_path, name, conf="ROLE=server\nALERT_LEVEL=10\nRETENTION_DAYS=90\nDATA_DIR=/srv/wazuh\n",
        active="", agents="", dfpct="40"):
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text(
        "#!/bin/bash\n" + f'case " {active} " in *" $3 "*) exit 0;; esac\nexit 3\n'); (b / "systemctl").chmod(0o755)
    (b / "agent_control").write_text(f"#!/bin/bash\ncat <<'EOF'\n{agents}\nEOF\n"); (b / "agent_control").chmod(0o755)
    (b / "df").write_text(f"#!/bin/bash\necho 'Use%'; echo ' {dfpct}%'\n"); (b / "df").chmod(0o755)
    c = tmp_path / "security.conf"
    if conf is not None:
        c.write_text(conf)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_SECURITY_CONF=str(c),
               CHP_AGENT_CONTROL=str(b / "agent_control"))
    r = subprocess.run(["bash", str(M / name)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_not_enabled_is_silent_ok(tmp_path):
    assert run(tmp_path, "70-wazuh-service.sh", conf=None).startswith("OK")


def test_server_services_down_alert(tmp_path):
    out = run(tmp_path, "70-wazuh-service.sh", active="chp-wazuh-alerts")
    assert "ALERT Wazuh wazuh-manager is not running" in out


def test_server_services_up_ok(tmp_path):
    assert run(tmp_path, "70-wazuh-service.sh", active="wazuh-manager chp-wazuh-alerts").startswith("OK")


def test_client_checks_its_agent(tmp_path):
    out = run(tmp_path, "70-wazuh-service.sh", conf="ROLE=client\n", active="")
    assert "ALERT Wazuh wazuh-agent is not running" in out


def test_disconnected_agents_alert(tmp_path):
    agents = ("   ID: 000, Name: srv1 (server), IP: 127.0.0.1, Active/Local\n"
              "   ID: 001, Name: ws1, IP: 192.0.2.21, Active\n   ID: 002, Name: ws2, IP: 192.0.2.22, Disconnected\n"
              "   ID: 003, Name: ws3, IP: 192.0.2.23, Never connected")
    out = run(tmp_path, "71-wazuh-agents.sh", agents=agents)
    assert "ALERT Wazuh agent ws2 (002) is disconnected" in out and "ALERT Wazuh agent ws3 (003) has never connected" in out
    assert "ws1" not in out


def test_agents_check_is_server_only(tmp_path):
    assert run(tmp_path, "71-wazuh-agents.sh", conf="ROLE=client\n").startswith("OK")


def test_disk_over_80_alerts(tmp_path):
    assert "ALERT Wazuh data directory /srv/wazuh is 85% full" in run(tmp_path, "72-wazuh-disk.sh", dfpct="85")
    assert run(tmp_path, "72-wazuh-disk.sh", dfpct="50").startswith("OK")


def run_yara(tmp_path, last_full=None, conf_age_days=0, now=1_000_000_000):
    st = tmp_path / "yara"; st.mkdir(exist_ok=True)
    if last_full is not None:
        (st / "last-full").write_text(f"{last_full}\n")
    c = tmp_path / "security.conf"; c.write_text("ROLE=client\n")
    os.utime(c, (now - conf_age_days * 86400,) * 2)
    env = dict(os.environ, CHP_SECURITY_CONF=str(c), CHP_YARA_STATE=str(st), CHP_NOW=str(now))
    r = subprocess.run(["bash", str(M / "73-yara-scan.sh")], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_yara_recent_full_scan_is_ok(tmp_path):
    assert run_yara(tmp_path, last_full=1_000_000_000 - 3 * 86400).startswith("OK")


def test_yara_full_scan_overdue_alerts(tmp_path):
    assert "ALERT" in run_yara(tmp_path, last_full=1_000_000_000 - 9 * 86400)


def test_yara_never_scanned_is_ok_in_the_first_week_then_alerts(tmp_path):
    assert run_yara(tmp_path, conf_age_days=2).startswith("OK")
    assert "ALERT" in run_yara(tmp_path, conf_age_days=9)


def test_yara_not_enabled_is_silent_ok(tmp_path):
    env = dict(os.environ, CHP_SECURITY_CONF=str(tmp_path / "none"))
    out = subprocess.run(["bash", str(M / "73-yara-scan.sh")], env=env, capture_output=True, text=True).stdout
    assert out.startswith("OK")


def test_yara_recent_scan_stale_alerts(tmp_path):                                     # final review I2
    now = 1_000_000_000
    st = tmp_path / "yara"; st.mkdir(); (st / "last-full").write_text(f"{now - 86400}\n")
    (st / "last-recent").write_text(f"{now - 45 * 60}\n")
    c = tmp_path / "security.conf"; c.write_text("ROLE=client\n"); os.utime(c, (now - 3 * 86400,) * 2)
    env = dict(os.environ, CHP_SECURITY_CONF=str(c), CHP_YARA_STATE=str(st), CHP_NOW=str(now))
    out = subprocess.run(["bash", str(M / "73-yara-scan.sh")], env=env, capture_output=True, text=True).stdout
    assert "ALERT" in out and "5-minute" in out
    (st / "last-recent").write_text(f"{now - 4 * 60}\n")
    out = subprocess.run(["bash", str(M / "73-yara-scan.sh")], env=env, capture_output=True, text=True).stdout
    assert out.startswith("OK")


def _uptime(s):
    return f"{s // 86400}d, {s % 86400 // 3600}h {s % 3600 // 60}m {s % 60}s"


def run_suri(tmp_path, active=True, stats_age_min=1, packets=1000, drops=None, conf=True, now=1_000_000_000,
             blocks=None):
    """blocks: [(uptime_s, packets, drops or None)] oldest first, as Suricata appends them (zero counters left out);
    default = one block of (3600, packets, drops)."""
    b = tmp_path / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text("#!/bin/bash\n" + ("exit 0\n" if active else "exit 3\n")); (b / "systemctl").chmod(0o755)
    c = tmp_path / "security.conf"
    if conf:
        c.write_text("ROLE=client\nALERT_LEVEL=10\nRETENTION_DAYS=90\nDATA_DIR=/srv/wazuh\n")
    d = tmp_path / "suricata"; d.mkdir(exist_ok=True)
    if stats_age_min is not None:
        lines = []
        for up, pk, dr in (blocks or [(3600, packets, drops)]):
            lines += ["-" * 79, f"Date: 11/5/2026 -- 08:07:58 (uptime: {_uptime(up)})", "-" * 79,
                      "Counter                                       | TM Name                   | Value", "-" * 79,
                      f"capture.kernel_packets                         | Total                     | {pk}"]
            if dr is not None:
                lines.append(f"capture.kernel_drops                           | Total                     | {dr}")
            lines.append("decoder.pkts                                   | Total                     | 1")
        (d / "stats.log").write_text("\n".join(lines) + "\n")
        t0 = now - stats_age_min * 60
        os.utime(d / "stats.log", (t0, t0))
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_SECURITY_CONF=str(c), CHP_SURICATA_LOG_DIR=str(d),
               CHP_NOW=str(now))
    r = subprocess.run(["bash", str(M / "74-suricata.sh")], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_suricata_not_enabled_is_ok(tmp_path):
    assert run_suri(tmp_path, conf=False).startswith("OK")


def test_suricata_not_running_alerts(tmp_path):
    out = run_suri(tmp_path, active=False)
    assert "ALERT" in out and "Suricata is not running" in out and "after an upgrade: chp-site security enable" in out


def test_monitor_alerts_when_eve_is_stale_while_running(tmp_path):             # Review Focus 4
    out = run_suri(tmp_path, stats_age_min=25)
    assert out.startswith("ALERT") and "has written no stats for 25 minutes" in out and "capture interface" in out


def test_suricata_without_stats_yet_alerts(tmp_path):
    out = run_suri(tmp_path, stats_age_min=None)
    assert out.startswith("ALERT") and "no stats" in out


def test_suricata_running_and_fresh_is_ok(tmp_path):
    out = run_suri(tmp_path, drops=0)
    assert out.startswith("OK") and "ALERT" not in out


def test_suricata_dropping_packets_alerts(tmp_path):
    out = run_suri(tmp_path, packets=1000, drops=50)
    assert "ALERT" in out and "dropping packets" in out and "5.0%" in out and "since it started" in out


def test_suricata_small_drop_rate_is_ok(tmp_path):
    assert "ALERT" not in run_suri(tmp_path, packets=100000, drops=50)


def test_restart_does_not_count_the_old_runs_drops(tmp_path):                  # S1 final review I-1 (reproduced)
    out = run_suri(tmp_path, blocks=[(57600, 100000, 60), (120, 1000, None)])
    assert "ALERT" not in out and out.startswith("OK")


def test_a_past_burst_clears(tmp_path):                                         # judged on the last 15+ minutes
    out = run_suri(tmp_path, blocks=[(1000, 100000, 20000), (1900, 500000, 20000), (2000, 1000000, 20000)])
    assert "ALERT" not in out


def test_dropping_now_alerts_over_the_recent_window(tmp_path):
    out = run_suri(tmp_path, blocks=[(1000, 100000, 0), (1900, 150000, 0), (2000, 200000, 5000)])
    assert "dropping packets" in out and "5000 of 100000" in out and "in the last 16 minutes" in out


def test_too_few_packets_are_not_judged(tmp_path):
    assert "ALERT" not in run_suri(tmp_path, blocks=[(300, 500, 50)])
