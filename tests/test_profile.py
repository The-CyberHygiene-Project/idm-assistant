import json

import pytest

from engine import labsecrets, profile, remote
from engine.repairs import target_role


def test_default_is_the_lab(monkeypatch):
    monkeypatch.delenv("IDM_PROFILE", raising=False)
    p = profile.current()
    assert p.name == "lab" and p.fqdn() == "idm.kanidm.lab.test" and p.group("lab_users") == "lab_users@idm.kanidm.lab.test"
    assert remote.ssh_base() == ["ssh", "-o", "BatchMode=yes"] and labsecrets.path("x.json").name == "x.json"


def test_appliance_mapping(monkeypatch):
    monkeypatch.setenv("IDM_PROFILE", "appliance")
    p = profile.current()
    assert p.hostnames == {"srv1": "iso5-srv", "client2": "iso5-cli2"} and p.ip("srv1") == "192.168.100.50"
    assert p.group("chp_users") == "chp_users" and p.anchor.endswith("/chp-root.crt")
    assert p.sshd_dropin.endswith("/10-chp.conf") and p.trusted_ca_keys == "/etc/ssh/chp_user_ca.pub"
    assert remote.ssh_base()[:3] == ["ssh", "-F", str(profile.ROOT / "lab/iso5/ssh_config")]
    assert labsecrets.path("lab01.json").name == "iso5-lab01.json"


def test_unknown_profile_stops(monkeypatch):                    # Review Focus 1
    monkeypatch.setenv("IDM_PROFILE", "aplliance")
    with pytest.raises(ValueError, match="IDM_PROFILE"):
        profile.current()


def test_target_role_uses_the_mapped_hostname(monkeypatch):    # Review Focus 3
    monkeypatch.setenv("IDM_PROFILE", "appliance")
    assert target_role({"host": "iso5-cli2", "role": "client"}, "client2") == "client"
    with pytest.raises(ValueError):
        target_role({"host": "iso5-cli1", "role": "client"}, "client2")


def test_appliance_pins_come_from_the_secrets_file(monkeypatch, tmp_path):
    monkeypatch.setenv("IDM_PROFILE", "appliance"); monkeypatch.setattr(labsecrets, "DIR", tmp_path)
    (tmp_path / "iso5-pins.json").write_text(json.dumps({"CA_ROOT_SHA256": "ab" * 32, "SSH_CA_FPR": "SHA256:xyz"}))
    assert profile.current().pinned_root() == ":".join(["AB"] * 32) and profile.current().pinned_ssh_ca() == "SHA256:xyz"


def test_missing_pins_file_refuses(monkeypatch, tmp_path):        # Review Focus 4
    monkeypatch.setenv("IDM_PROFILE", "appliance"); monkeypatch.setattr(labsecrets, "DIR", tmp_path)
    with pytest.raises(FileNotFoundError, match="pins"):
        profile.current().pinned_root()
