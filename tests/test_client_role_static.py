import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "appliance/rpm/chp-identity-client"


def text(n):
    return (C / n).read_text()


def test_enrol_is_bash_strict_and_branded():
    t = text("client-enrol.sh")
    assert t.startswith("#!/bin/bash\n# CyberHygiene Project Lab Installer") and "set -Eeuo pipefail" in t
    assert subprocess.run(["bash", "-n", str(C / "client-enrol.sh")]).returncode == 0


def test_trust_is_pinned_and_rechecked():
    t = text("client-enrol.sh")
    assert 'step-cli ca root "$T/root.pem" --ca-url "https://$CA:9000" --fingerprint "$PIN" --force' in t
    assert "openssl x509 -in \"$T/root.pem\" -outform DER | sha256sum" in t
    assert re.search(r'\[ "\$got" = "\$PIN" \] \|\| \{ log "CHP: refusing', t)


def test_unixd_token_is_never_copied_or_printed():
    t = text("client-enrol.sh")
    assert "LoadCredential=unixd_token:/etc/kanidm/token" in t
    assert "cat /etc/kanidm/token" not in t and "echo \"$token" not in t


def test_authselect_rebuilt_from_the_recorded_original():
    t = text("client-enrol.sh")
    assert "/var/lib/chp/authselect-original" in t
    assert "authselect select custom/kanidm" in t and "--force" in t
    assert "LOST authselect feature" in t


def test_sshd_validated_before_reload_and_removed_on_failure():
    t = text("client-enrol.sh")
    i, j = t.index("sshd -t"), t.index("systemctl reload sshd")
    assert i < j and "rm -f /etc/ssh/sshd_config.d/10-chp.conf /etc/ssh/sshd_config.d/99-chp-exceptions.conf" in t


def test_lab_and_appliance_patchers_do_not_drift():
    lab = (ROOT / "lab/client/authselect_patch.py").read_text()
    app = text("authselect_patch.py")
    assert app.endswith(lab) and app.startswith("# CyberHygiene Project Lab Installer")
