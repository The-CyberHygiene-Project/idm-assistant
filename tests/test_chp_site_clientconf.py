import subprocess
from pathlib import Path

import pytest

from chp_site.clientconf import cert_sha256, make_client_conf, parse_client_conf, ssh_fpr
from chp_site.sitefile import SiteError, parse_site
from tests.test_chp_site_sitefile import GOOD

FX = Path(__file__).parent / "fixtures" / "chp-site"
PEM = (FX / "root_ca.crt").read_text()
PUB = (FX / "user_ca.pub").read_text()
CACHE = (FX / "cache_key.pub").read_text()
SITE = parse_site(GOOD)
# Expected values come from the reference tools, not from our own code:
ROOT_SHA = subprocess.run(["openssl", "x509", "-in", str(FX / "root_ca.crt"), "-noout", "-fingerprint", "-sha256"],
                          capture_output=True, text=True, check=True).stdout.split("=", 1)[1].strip().replace(":", "").lower()
SSH_FPR = subprocess.run(["ssh-keygen", "-lf", str(FX / "user_ca.pub")], capture_output=True, text=True,
                         check=True).stdout.split()[1]


def test_fingerprints_match_openssl_and_ssh_keygen():
    assert cert_sha256(PEM) == ROOT_SHA
    assert ssh_fpr(PUB) == SSH_FPR


def test_round_trip():
    c = parse_client_conf(make_client_conf("iso2.lab.test", PEM, PUB, CACHE), SITE)
    assert c["KANIDM_URL"] == "https://idm.iso2.lab.test" and c["SSH_CA_FPR"] == SSH_FPR


@pytest.mark.parametrize("edit,why", [
    (lambda t: t.replace(SSH_FPR, "SHA256:" + "A" * 43), "SSH_CA_FPR does not match"),
    (lambda t: t.replace("idm.iso2.lab.test", "idm.other.test"), "KANIDM_URL"),
    (lambda t: t.replace(ROOT_SHA, "zz"), "CA_ROOT_SHA256"),
    (lambda t: "\n".join(l for l in t.splitlines() if not l.startswith("SSH_CA_PUBKEY")), "SSH_CA_PUBKEY is required"),
])
def test_tampered_client_conf_is_refused(edit, why):
    with pytest.raises(SiteError, match=why):
        parse_client_conf(edit(make_client_conf("iso2.lab.test", PEM, PUB, CACHE)), SITE)


def test_no_certificate_in_pem():
    with pytest.raises(SiteError, match="no CERTIFICATE"):
        cert_sha256("hello")


def test_client_conf_carries_the_cache_key():
    t = make_client_conf("iso2.lab.test", (FX / "root_ca.crt").read_text(), (FX / "user_ca.pub").read_text(),
                         (FX / "cache_key.pub").read_text())
    c = parse_client_conf(t, {"DOMAIN": "iso2.lab.test"})
    assert c["CACHE_PUBKEY"].startswith("ecdsa-sha2-nistp384 ")


def test_client_conf_without_cache_key_is_refused():
    t = make_client_conf("iso2.lab.test", (FX / "root_ca.crt").read_text(), (FX / "user_ca.pub").read_text(),
                         (FX / "cache_key.pub").read_text())
    t = "\n".join(ln for ln in t.splitlines() if not ln.startswith("CACHE_PUBKEY=")) + "\n"
    with pytest.raises(SiteError, match="CACHE_PUBKEY is required"):
        parse_client_conf(t, {"DOMAIN": "iso2.lab.test"})
