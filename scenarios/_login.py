"""Login probes for both profiles. lab: password-only (ssh-login.exp) or certificate-only (ssh-cert-login.sh) logins to
client2, as before. appliance: sshd demands key/certificate AND the GA code AND the password (row 10), so one helper
(lab/iso5/login.exp) does all three. GA refuses a code reused in the same 30-s window (-d): wait for a fresh one."""
import subprocess
import time
from pathlib import Path

from engine import labsecrets, profile, remote

ROOT = Path(__file__).resolve().parents[1]
# Lab stand-in certificates (the user's own, held in ~/idm-lab-secrets): valid for the whole test period, because the CA
# records each one and an expired record is a real SSH_USER_CERT_EXPIRED finding (c3 injects that on purpose).
LAB_CERT_VALIDITY = "+30d"


def fresh_window(now=time.time, sleep=time.sleep):
    sleep(31 - now() % 30)              # 1 s past the next 30-s boundary: a code never used yet


def appliance_argv(user):
    k = labsecrets.path(f"{user}_ecdsa")
    return ["/usr/bin/expect", str(ROOT / "lab/iso5/login.exp"), profile.current().ip("client2"), user, str(k),
            f"{k}-cert.pub", str(labsecrets.path(f"{user}.ga"))]


def _appliance(user, password, log, fresh_cert):
    from engine.repairs import sign_user_cert
    if fresh_cert:          # password probes test the PASSWORD path: give them a valid certificate
        labsecrets.write(f"{user}_ecdsa-cert.pub", sign_user_cert(remote, "srv1", user, LAB_CERT_VALIDITY))
    fresh_window()
    r = subprocess.run(appliance_argv(user), input=f"{password}\n", capture_output=True, text=True)
    return "OK" if "LOGIN_OK" in r.stdout else "DENIED" if "LOGIN_REFUSED" in r.stdout else "ERROR"


def probe(user, which, log):
    if profile.current().name == "appliance":
        d = labsecrets.read_json(f"{user}.json")
        pw = d["password"] if which == "primary" else (d.get("posix_password") or "")
        res = _appliance(user, pw, log, fresh_cert=True)
    else:
        r = subprocess.run(["/usr/bin/expect", str(ROOT / "lab/client/ssh-login.exp"), user, which,
                            profile.current().ip("client2")], stdin=subprocess.DEVNULL, capture_output=True, text=True)
        res = "OK" if "RESULT: uid=" in r.stdout else "DENIED" if "RESULT: DENIED" in r.stdout else "ERROR"
    log(f"login probe {user}@client2 with its {which} password: {res}")
    return res


def cert_probe(user, log):
    if profile.current().name == "appliance":
        d = labsecrets.read_json(f"{user}.json")
        res = _appliance(user, d.get("posix_password") or "", log, fresh_cert=False)
        out = f"RESULT: OK {user}" if res == "OK" else "RESULT: DENIED"
    else:
        out = subprocess.run([str(ROOT / "lab/client/ssh-cert-login.sh"), user], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True).stdout.strip()
    log(f"certificate login probe {user}@client2: {out}")
    return out


def prepare_user(user, posix=True, log=print):
    """appliance only (lab: nothing): give USER what an appliance login needs besides the Kanidm credentials: a key
    registered with the SSH CA, a fresh certificate, and a GA token on client2 (row 11). Secrets go to ~/idm-lab-secrets
    only; nothing is logged but the steps."""
    if profile.current().name != "appliance":
        return
    from engine.repairs import sign_user_cert, valid_user
    if not valid_user(user):
        raise ValueError(f"invalid user name {user!r}")
    k = labsecrets.path(f"{user}_ecdsa")
    if not k.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", f"{user} (iso5 lab)", "-f", str(k)],
                       check=True, stdin=subprocess.DEVNULL)
    pub = (k.parent / (k.name + ".pub")).read_text()
    remote.run("srv1", ["sudo", "install", "-m", "0644", "/dev/stdin", f"/var/lib/ssh-ca/keys/{user}.pub"], stdin=pub)
    labsecrets.write(f"{user}_ecdsa-cert.pub", sign_user_cert(remote, "srv1", user, LAB_CERT_VALIDITY))
    remote.run("client2", ["sudo", "kanidm-unix", "cache-invalidate"])
    remote.run("client2", ["sudo", "sh", "-c", f"chp-site ga-enrol {user} --reset --no-confirm >/dev/null 2>&1 || "
                           f"chp-site ga-enrol {user} --no-confirm >/dev/null"])
    sec = remote.run("client2", ["sudo", "head", "-1", f"/var/lib/google-authenticator/{user}"]).stdout.strip()
    labsecrets.write(f"{user}.ga", sec + "\n")
    log(f"prepared {user}: key registered, certificate {LAB_CERT_VALIDITY}, GA token on client2 (posix={posix})")
