# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Document server (Nextcloud) pieces derived from the site files."""
from .hosts import server_of
from .sitefile import SiteError


def fqdn(site):
    return f"files.{site['DOMAIN']}"


def hosts_file(site, hosts):
    """The WHOLE /etc/hosts for the server: the Rocky loopback defaults, then the site names -> the server's address,
    so apache and Nextcloud resolve them without DNS. Refuses when DOCUMENTS=no."""
    if site.get("DOCUMENTS") != "yes":
        raise SiteError("hosts_file: DOCUMENTS is not yes")
    srv = server_of(hosts)
    d = site["DOMAIN"]
    names = [f"idm.{d}", fqdn(site), f"ca.{d}", f"{srv.hostname}.{d}"]
    return ("127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n"
            "::1 localhost localhost.localdomain localhost6 localhost6.localdomain6\n"
            "# written by chp-site; the server's own site names\n"
            + "".join(f"{srv.ip} {n}\n" for n in names))
