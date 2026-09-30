# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""client.conf: the server's trust values pinned for client installs (written by export-client, never by hand)."""
import base64
import hashlib
import re

from .sitefile import SiteError, read_kv, ssh_pubkey


def cert_sha256(pem):
    m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", pem, re.S)
    if not m:
        raise SiteError("no CERTIFICATE block in the CA root file")
    return hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest()


def ssh_fpr(pub):
    blob = base64.b64decode(pub.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def make_client_conf(domain, root_pem, ssh_ca_pub):
    key = ssh_pubkey(ssh_ca_pub)
    return ("# client.conf: written by `chp-site export-client` on the server. Do not edit.\n"
            f"CA_ROOT_SHA256={cert_sha256(root_pem)}\n"
            f"SSH_CA_PUBKEY={key}\n"
            f"SSH_CA_FPR={ssh_fpr(key)}\n"
            f"KANIDM_URL=https://idm.{domain}\n")


def parse_client_conf(text, site):
    raw = read_kv(text, "client.conf")
    for k in ("CA_ROOT_SHA256", "SSH_CA_PUBKEY", "SSH_CA_FPR", "KANIDM_URL"):
        if not raw.get(k):
            raise SiteError(f"client.conf: {k} is required (run `chp-site export-client` on the server)")
    if not re.fullmatch(r"[0-9a-f]{64}", raw["CA_ROOT_SHA256"]):
        raise SiteError("client.conf: CA_ROOT_SHA256 must be 64 lower-case hex digits")
    try:
        key = ssh_pubkey(raw["SSH_CA_PUBKEY"])
    except SiteError as e:
        raise SiteError(str(e).replace("ADMIN_SSH_PUBKEY", "client.conf SSH_CA_PUBKEY")) from None
    if ssh_fpr(key) != raw["SSH_CA_FPR"]:
        raise SiteError("client.conf: SSH_CA_FPR does not match SSH_CA_PUBKEY (tampered or corrupted)")
    if raw["KANIDM_URL"] != f"https://idm.{site['DOMAIN']}":
        raise SiteError(f"client.conf: KANIDM_URL must be https://idm.{site['DOMAIN']} (site DOMAIN)")
    return {"CA_ROOT_SHA256": raw["CA_ROOT_SHA256"], "SSH_CA_PUBKEY": key, "SSH_CA_FPR": raw["SSH_CA_FPR"],
            "KANIDM_URL": raw["KANIDM_URL"]}
