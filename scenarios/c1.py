"""C1: the Kanidm TLS certificate expires because its renewal timer stopped (spec §6)."""
import time

from engine import remote

ID = "c1"
SYMPTOM = "Users on client2 cannot log in; the Kanidm web UI shows a certificate error."
EXPECT = {"srv1": {"TLS_CERT_EXPIRED(kanidm)", "ACME_RENEWAL_STOPPED"}, "client2": {"TLS_CERT_EXPIRED(kanidm)"}}
REPAIRS = [("srv1", "kanidm-cert-renew"), ("srv1", "acme-timer-restore")]
USER = None


def inject(log):
    out = remote.run("srv1", ["sudo", "bash", "-c",
        "set -e; export STEPPATH=/root/.step; systemctl disable --now cert-renew-kanidm.timer; "
        "firewall-cmd -q --add-service=http; trap 'firewall-cmd -q --remove-service=http' EXIT; "
        "step-cli ca certificate idm.kanidm.lab.test /etc/pki/kanidm/chain.pem /etc/pki/kanidm/key.pem "
        "--provisioner acme --kty EC --crv P-384 --not-after 5m --force >/dev/null 2>&1; "
        "chmod 600 /etc/pki/kanidm/*.pem; systemctl try-restart kanidmd; "
        "openssl x509 -in /etc/pki/kanidm/chain.pem -noout -enddate"]).stdout
    log(f"injected: renewal timer disabled; short certificate {out.strip()}")
    # wait until the SERVED certificate has expired (plus a margin)
    for _ in range(80):
        r = remote.collect("srv1-diag")
        if (r.get("tls", {}).get("kanidm") or {}).get("verify") == "expired":
            log("served certificate is now expired")
            return
        time.sleep(10)
    raise RuntimeError("certificate did not expire within ~13 min")
