# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Document server (Nextcloud) pieces derived from the site files."""
from .hosts import server_of


def fqdn(site):
    return f"files.{site['DOMAIN']}"


def hosts_file(site, hosts):
    """The server's own site names -> its own address, so apache and Nextcloud resolve them without DNS."""
    srv = server_of(hosts)
    d = site["DOMAIN"]
    names = [f"idm.{d}", fqdn(site), f"ca.{d}", f"{srv.hostname}.{d}"]
    return "# written by chp-site; the server's own site names\n" + "".join(f"{srv.ip} {n}\n" for n in names)
