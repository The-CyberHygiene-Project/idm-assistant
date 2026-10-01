# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Kickstart snippets written by %pre and %include'd by server.ks/client.ks."""
from .hosts import server_of


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
