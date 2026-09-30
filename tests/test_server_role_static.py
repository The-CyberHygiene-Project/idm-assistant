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
