"""C3: a user's SSH certificate has expired, so certificate logins are refused (spec §6). The SSH CA's issuance
record (public) is the server-side evidence (Plan 7 deviation 2)."""
import subprocess
from pathlib import Path

from engine import labsecrets, remote
from engine.repairs import sign_user_cert

ID = "c3"
USER = "lab02"
SYMPTOM = f"{USER}'s SSH key login to client2 stopped working this morning; nothing changed on their laptop."
EXPECT = {"srv1": {"SSH_USER_CERT_EXPIRED"}}
HOSTS = ["srv1", "client2"]
REPAIRS = [("srv1", "ssh-user-cert-reissue")]
PARAMS = {"user": USER, "lab_standin": True}
ROOT = Path(__file__).resolve().parents[1]


def cert_probe(log):
    out = subprocess.run([str(ROOT / "lab/client/ssh-cert-login.sh"), USER], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True).stdout.strip()
    log(f"certificate login probe {USER}@client2: {out}")
    return out


def inject(log):
    cert = sign_user_cert(remote, "srv1", USER, "-2m:-1m")          # issued already expired
    labsecrets.write(f"{USER}_ecdsa-cert.pub", cert)                 # the user's machine now holds it
    log(f"injected: {USER}'s newest certificate expired one minute ago")
    if cert_probe(log) != "RESULT: DENIED":
        raise RuntimeError("certificate login still works; injection did not take")


def final_probe(log):
    return cert_probe(log).startswith("RESULT: OK")
