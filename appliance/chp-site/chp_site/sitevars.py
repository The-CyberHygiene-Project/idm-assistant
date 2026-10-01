# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Derived site values for the shell (first-boot scripts use `chp-site get KEY`; they never parse site files)."""
from .hosts import server_of

ANCHOR = "/etc/pki/ca-trust/source/anchors/chp-root.crt"


def values(site, hosts, client=None):
    """client: the parsed client.conf (a client host), so first-boot scripts can `chp-site get` its pinned values."""
    srv = server_of(hosts)
    d = site["DOMAIN"]
    v = {"DOMAIN": d, "SUBNET": str(site["SUBNET"].network_address), "SUBNET_CIDR": str(site["SUBNET"]),
         "SERVER_IP": srv.ip, "SERVER_HOSTNAME": srv.hostname, "SERVER_FQDN": f"{srv.hostname}.{d}",
         "KANIDM_FQDN": f"idm.{d}", "CA_FQDN": f"ca.{d}", "ALERT_HOOK": site["ALERT_HOOK"],
         "CLIENT_HOSTS": " ".join(h.hostname for h in hosts if h.role == "client"),
         "COLLECTOR_IP": site.get("COLLECTOR_IP", ""), "COLLECTOR_SSH_PUBKEY": site.get("COLLECTOR_SSH_PUBKEY", "")}
    if client:
        v.update({k: client[k] for k in ("CA_ROOT_SHA256", "SSH_CA_PUBKEY", "SSH_CA_FPR", "CACHE_PUBKEY", "KANIDM_URL")})
    return v
