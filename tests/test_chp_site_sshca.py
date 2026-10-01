import subprocess

import pytest

from chp_site.sshca import SshCa, VALIDITY
from chp_site.sitefile import SiteError


def keypair(d, name):
    subprocess.run(["ssh-keygen", "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", name, "-f", str(d / name)], check=True)
    return (d / f"{name}.pub").read_text()


@pytest.fixture
def ca(tmp_path):
    (tmp_path / "etc/ssh-ca").mkdir(parents=True)
    keypair(tmp_path / "etc/ssh-ca", "user_ca")
    for d in ("keys", "issued"):
        (tmp_path / "var/lib/ssh-ca" / d).mkdir(parents=True)
    return SshCa(base=tmp_path)


def test_register_new_same_and_refuse_a_different_key(ca, tmp_path):
    k1, k2 = keypair(tmp_path, "k1"), keypair(tmp_path, "k2")
    assert ca.register("lab09", k1) == "new" and ca.register("lab09", k1) == "same"
    with pytest.raises(SiteError, match="different key is already registered"):
        ca.register("lab09", k2)
    assert ca.register("lab09", k2, replace=True) == "replaced" and ca.registered("lab09").split()[1] == k2.split()[1]


def test_register_refuses_ed25519(ca):
    with pytest.raises(SiteError, match="FIPS"):
        ca.register("lab09", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyHV2oRj8Uf8QdTf6eK8f5dDAXHhpxS5X0mGmAcBwUP x")


def test_sign_records_and_returns_the_certificate(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "k1"))
    cert, valid_to = ca.sign("lab09", "iso3.lab.test")
    rec = (tmp_path / "var/lib/ssh-ca/issued/lab09-cert.pub").read_text()
    assert rec == cert and cert.startswith("ecdsa-sha2-nistp384-cert-v01@openssh.com ")
    listing = subprocess.run(["ssh-keygen", "-L", "-f", "/dev/stdin"], input=cert, capture_output=True, text=True).stdout
    assert "lab09@idm.iso3.lab.test" in listing and valid_to in listing and VALIDITY == "+8h"


def test_sign_without_a_registered_key_is_refused(ca):
    with pytest.raises(SiteError, match="no registered SSH key"):
        ca.sign("lab09", "iso3.lab.test")


def test_revoke_key_moves_it_aside(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "k1"))
    assert ca.revoke_key("lab09", "20260930T200000Z") is True and ca.registered("lab09") is None
    assert (tmp_path / "var/lib/ssh-ca/revoked/lab09.pub.20260930T200000Z").exists()
    assert ca.revoke_key("lab09", "20260930T200001Z") is False
