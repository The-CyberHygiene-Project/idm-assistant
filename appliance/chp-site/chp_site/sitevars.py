# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Derived site values for the shell (first-boot scripts use `chp-site get KEY`; they never parse site files)."""
from .hosts import server_of

ANCHOR = "/etc/pki/ca-trust/source/anchors/chp-root.crt"


def values(site, hosts):
    srv = server_of(hosts)
    d = site["DOMAIN"]
    return {"DOMAIN": d, "SUBNET": str(site["SUBNET"].network_address), "SUBNET_CIDR": str(site["SUBNET"]),
            "SERVER_IP": srv.ip, "SERVER_HOSTNAME": srv.hostname, "SERVER_FQDN": f"{srv.hostname}.{d}",
            "KANIDM_FQDN": f"idm.{d}", "CA_FQDN": f"ca.{d}", "ALERT_HOOK": site["ALERT_HOOK"]}
