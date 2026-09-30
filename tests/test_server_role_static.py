"""Static rules for the shipped role scripts (chp-base, chp-identity-server): branding, syntax, no lab values,
first-boot step order and guards, offline root key, no secrets on command lines, ACME fallback."""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / "appliance" / "branding" / "file-header.txt").read_text()
SRV = ROOT / "appliance" / "rpm" / "chp-identity-server"
BASE = ROOT / "appliance" / "rpm" / "chp-base"
SHIPPED = sorted([*SRV.glob("*.sh"), *SRV.glob("monitor.d/*.sh"), *BASE.glob("*.sh"), *BASE.glob("monitor.d/*.sh")])
SHIPPED = [p for p in SHIPPED if p.name != "build-rpm.sh"]
ALL = SHIPPED + sorted([*SRV.glob("*.service"), *SRV.glob("*.timer"), *SRV.glob("*.conf"), *SRV.glob("*.spec"), *SRV.glob("*.exp")])
STEPS = ["bind", "step-ca", "kanidm-cert", "kanidmd", "recover", "collector", "ssh-ca"]


def test_there_are_shipped_scripts():
    assert any(p.name == "server-firstboot.sh" for p in SHIPPED) and any(p.name == "cert-renew-kanidm.sh" for p in SHIPPED)


@pytest.mark.parametrize("p", SHIPPED, ids=lambda p: p.name)
def test_header_and_syntax(p):
    t = p.read_text()
    assert t.split("\n", 1)[1].startswith(HEADER), "branding header right after the shebang"
    assert subprocess.run(["bash", "-n", str(p)]).returncode == 0


@pytest.mark.parametrize("p", ALL, ids=lambda p: p.name)
def test_no_lab_values(p):
    assert not re.search(r"kanidm\.lab\.test|192\.168\.100|iso[23]", p.read_text())


def test_firstboot_steps_in_order_each_guarded():
    t = (SRV / "server-firstboot.sh").read_text()
    pos = [t.index(f'step {s} ') for s in STEPS]
    assert pos == sorted(pos)
    assert 'step() {' in t and '.done' in t


def test_domain_guard_and_offline_root():
    t = (SRV / "server-firstboot.sh").read_text()
    assert "/var/lib/chp/kanidm-domain" in t
    assert re.search(r"\bmv\b[^\n]*/etc/step-ca/secrets/root_ca_key", t), "root CA key must be MOVED off the CA dir"


def test_no_literal_secret_on_a_command_line():
    for p in SHIPPED:
        t = p.read_text()
        assert not re.search(r"--password(=| )['\"]?[A-Za-z0-9]", t), p.name
        assert not re.search(r"password=[A-Za-z0-9]", t), p.name


def test_renewal_falls_back_to_acme():
    t = (SRV / "cert-renew-kanidm.sh").read_text()
    assert "ca renew" in t and "--provisioner acme" in t


def test_units_are_guarded():
    u = (SRV / "chp-server-firstboot.service").read_text()
    assert "ConditionPathExists=!/var/lib/chp/firstboot/server.done" in u and "After=" in u and "chp-firstboot-common.service" in u


def test_recover_uses_the_scripting_interface():                       # found by the Plan 3a proof
    t = (SRV / "server-firstboot.sh").read_text()
    assert "kanidmd scripting -c /etc/kanidm/server.toml recover-account" in t
    assert '"status"' in t and '"output"' in t


def test_one_time_slot_is_killed_in_batch_mode_without_a_key_and_rebind_is_skipped():   # found by the proof
    t = (BASE / "firstboot-common.sh").read_text()
    kill = [l for l in t.splitlines() if "luksKillSlot" in l and not l.strip().startswith("#") and "log " not in l]
    assert kill and all("--key-file" not in l for l in kill) and all(" -q " in l for l in kill)
    assert "clevis luks list" in t


def test_firstboot_unit_sets_home_for_the_kanidm_cli():                # found by the proof (token cache needs $HOME)
    assert "Environment=HOME=/root" in (SRV / "chp-server-firstboot.service").read_text()


def test_cert_monitor_threshold_fits_24h_acme_certificates():          # found by the proof (7 days always alerted)
    t = (SRV / "monitor.d" / "30-kanidm-cert.sh").read_text()
    assert "checkend 14400" in t and "604800" not in t


def test_retry_hints_say_restart_not_start():                           # RemainAfterExit units ignore `start`
    for p in (SRV / "server-firstboot.sh", BASE / "firstboot-common.sh"):
        assert "systemctl start chp-" not in p.read_text(), p.name


def test_tpm_binding_requires_secure_boot():                            # final review I2 (spec 5.2)
    t = (BASE / "firstboot-common.sh").read_text()
    assert "mokutil --sb-state" in t and "SecureBoot enabled" in t
    assert t.index("mokutil --sb-state") < t.index("clevis luks bind")


def test_domain_guard_at_the_top_and_in_renewal():                      # final review I5
    t = (SRV / "server-firstboot.sh").read_text()
    assert t.index("/var/lib/chp/kanidm-domain") < t.index("step bind ")
    assert "kanidm-domain" in (SRV / "cert-renew-kanidm.sh").read_text()
    kd = t[t.index("do_kanidmd() {"):t.index("do_recover() {")]
    assert kd.index("/status") < kd.rindex("> /var/lib/chp/kanidm-domain")   # guard written only once Kanidm answers


def test_collector_step_resumes_cleanly_and_logs_out():                 # final review Minor 8
    t = (SRV / "server-firstboot.sh").read_text()
    col = t[t.index("do_collector() {"):t.index("do_sshca() {")]
    assert "| grep -q" not in col and "kanidm logout" in col


def test_failing_renewal_service_is_an_alert():                        # final review Minor 12
    assert "is-failed" in (SRV / "monitor.d" / "31-renew-timer.sh").read_text()


def test_collector_login_retries_while_kanidm_settles():                # proof run 2: login timed out 2 s after recover
    t = (SRV / "server-firstboot.sh").read_text()
    col = t[t.index("do_collector() {"):t.index("do_sshca() {")]
    assert re.search(r"for [a-z]+ in 1 2 3 4 5", col) and "sleep 10" in col
    assert "set timeout 60" in (SRV / "kanidm-login.exp").read_text()
