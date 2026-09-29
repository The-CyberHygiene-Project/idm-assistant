"""C4: a client's sshd no longer trusts the SSH user CA (TrustedUserCAKeys removed), so every certificate login fails
(spec §6)."""
import subprocess
from pathlib import Path

from engine import labsecrets, remote
from engine.repairs import sign_user_cert

ID = "c4"
USER = "lab02"
SYMPTOM = "Nobody's SSH key login to client2 works since a config push; password logins still do."
EXPECT = {"client2": {"SSH_CA_NOT_TRUSTED"}}
HOSTS = ["srv1", "client2"]
REPAIRS = [("client2", "ssh-ca-trust-restore")]
ROOT = Path(__file__).resolve().parents[1]
DROPIN = "/etc/ssh/sshd_config.d/10-kanidm.conf"


def cert_probe(log):
    out = subprocess.run([str(ROOT / "lab/client/ssh-cert-login.sh"), USER], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True).stdout.strip()
    log(f"certificate login probe {USER}@client2: {out}")
    return out


def inject(log):
    labsecrets.write(f"{USER}_ecdsa-cert.pub", sign_user_cert(remote, "srv1", USER, "+1h"))   # valid: test trust only
    if not cert_probe(log).startswith("RESULT: OK"):
        raise RuntimeError("setup failed: certificate login does not work before the fault")
    remote.run("client2", ["sudo", "sh", "-c", f"set -e; sed -i '/^TrustedUserCAKeys/d' {DROPIN}; sshd -t; "
                           "systemctl reload sshd"])
    log("injected: TrustedUserCAKeys removed from sshd's drop-in; sshd reloaded")
    if cert_probe(log) != "RESULT: DENIED":
        raise RuntimeError("certificate login still works; injection did not take")


def final_probe(log):
    return cert_probe(log).startswith("RESULT: OK")
