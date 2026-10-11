# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Kickstart snippets written by %pre and %include'd by server.ks/client.ks."""
import hashlib
import os

from .hosts import server_of
from .sitevars import ANCHOR, values


def misc_ks(site):
    lines = [f"timezone {site['TIMEZONE']} --utc"] + [f"timesource --ntp-server={n}" for n in site["NTP_UPSTREAM"]]
    return "\n".join(lines) + "\n"


def net_ks(site, host, hosts):
    ns = server_of(hosts).ip                                  # the server resolves via itself; clients via the server
    return (f"network --bootproto=static --device={host.mac} --ip={host.ip} --netmask={site['SUBNET'].netmask} "
            f"--gateway={site['GATEWAY']} --nameserver={ns} --noipv6 --activate "
            f"--hostname={host.hostname}.{site['DOMAIN']}\n")


def users_ks(site, root_hash):
    return (f"rootpw --iscrypted {root_hash}\n"
            "user --name=chpadmin --groups=wheel --gecos=\"CHP break-glass admin (SSH key only)\"\n"
            f"sshkey --username=chpadmin \"{site['ADMIN_SSH_PUBKEY']}\"\n")


def grub_pbkdf2(password, salt=None, iterations=10000):
    """The grub2-mkpasswd-pbkdf2 format (PBKDF2-HMAC-SHA512, 64-byte salt and key, upper-case hex)."""
    salt = os.urandom(64) if salt is None else salt
    dk = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, 64)
    return f"grub.pbkdf2.sha512.{iterations}.{salt.hex().upper()}.{dk.hex().upper()}"


def boot_ks(grub_hash):
    # ISSO 2026-10-10 (CUI grub2_password): the TPM (PCR 7) unlocks the disk whatever the boot options say, so editing
    # an entry at the console must need a password. Normal boots need none (Anaconda writes GRUB2_PASSWORD to user.cfg).
    return f'bootloader --append="fips=1" --iscrypted --password={grub_hash}\n'


def disk_ks(disk, passphrase):
    vg = "chp"
    return (f"ignoredisk --only-use={disk}\n"
            f"clearpart --all --initlabel --drives={disk}\n"
            "part /boot/efi --fstype=efi --size=1024\n"
            "part /boot --fstype=xfs --size=2048\n"
            f"part pv.01 --size=1 --grow --encrypted --luks-version=luks2 --passphrase={passphrase}\n"
            f"volgroup {vg} pv.01\n"
            f"logvol swap           --vgname={vg} --name=swap          --size=8192\n"
            f"logvol /home          --vgname={vg} --name=home          --fstype=xfs --size=10240\n"
            f"logvol /tmp           --vgname={vg} --name=tmp           --fstype=xfs --size=4096\n"
            f"logvol /var           --vgname={vg} --name=var           --fstype=xfs --size=20480\n"
            f"logvol /var/tmp       --vgname={vg} --name=var_tmp       --fstype=xfs --size=4096\n"
            f"logvol /var/log       --vgname={vg} --name=var_log       --fstype=xfs --size=8192\n"
            f"logvol /var/log/audit --vgname={vg} --name=var_log_audit --fstype=xfs --size=8192\n"
            f"logvol /              --vgname={vg} --name=root          --fstype=xfs --size=20480 --grow\n")


def repo_ks(url):
    return f"repo --name=chp --baseurl={url}\n"


def zone(site, hosts, serial):
    v = values(site, hosts)
    lines = ["$TTL 300",
             f"@ IN SOA {v['SERVER_FQDN']}. hostmaster.{v['DOMAIN']}. ( {serial} 3600 600 86400 300 )",
             f"@ IN NS {v['SERVER_FQDN']}."]
    for h in hosts:
        lines.append(f"{h.hostname:<12} IN A {h.ip}")
    lines += [f"{'idm':<12} IN A {v['SERVER_IP']}", f"{'ca':<12} IN A {v['SERVER_IP']}"]
    return "\n".join(lines) + "\n"


def named_conf(site, hosts):
    v = values(site, hosts)
    fw = site["DNS_FORWARDERS"]
    rec = (f"    recursion yes;\n    allow-recursion {{ 127.0.0.1; {v['SUBNET_CIDR']}; }};\n"
           f"    forwarders {{ {'; '.join(fw)}; }};\n    forward only;\n") if fw else "    recursion no;\n"
    return ("options {\n"
            f"    listen-on port 53 {{ 127.0.0.1; {v['SERVER_IP']}; }};\n"
            "    listen-on-v6 { none; };\n"
            '    directory "/var/named";\n'
            f"    allow-query {{ 127.0.0.1; {v['SUBNET_CIDR']}; }};\n"
            + rec +
            "    dnssec-validation no;\n"
            '    pid-file "/run/named/named.pid";\n'
            "};\n"
            'logging { channel default_debug { file "data/named.run"; severity dynamic; }; };\n'
            f'zone "{v["DOMAIN"]}" IN {{ type primary; file "{v["DOMAIN"]}.zone"; allow-update {{ none; }}; }};\n')


def kanidm_server_toml(site, hosts):
    v = values(site, hosts)
    return ('version = "2"\n'
            f'bindaddress = "{v["SERVER_IP"]}:443"\n'
            'db_path = "/var/lib/private/kanidm/kanidm.db"\n'
            'tls_chain = "/run/kanidmd/tls_chain.pem"\n'
            'tls_key = "/run/kanidmd/tls_key.pem"\n'
            f'domain = "{v["KANIDM_FQDN"]}"\n'
            f'origin = "https://{v["KANIDM_FQDN"]}"\n'
            'log_level = "info"\n\n'
            "[online_backup]\n"
            'path = "/var/lib/private/kanidm/backups/"\n'
            'schedule = "00 22 * * *"\n'
            "versions = 7\n")


def kanidm_client_config(site):
    return f'uri = "https://idm.{site["DOMAIN"]}"\nca_path = "{ANCHOR}"\n'


def collect_conf(site):
    return f"KANIDM_URL=https://idm.{site['DOMAIN']}\nCA_ANCHOR={ANCHOR}\n"
