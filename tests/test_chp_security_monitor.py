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
