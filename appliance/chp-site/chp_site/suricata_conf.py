# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Suricata settings (Suricata spec §3): IDS only on the host's site interface, HOME_NET from SUBNET, alert-only eve.json.
Pure text and one read-only lookup; security.enable writes the files. config_text() is the config proven in the S1
spike (lab/security/spike-suricata/: 52,859 ET Open rules loaded, 0 failed); a test keeps them identical."""
import re

from .sitefile import SiteError

CONF = "/etc/suricata/chp-suricata.yaml"
EVE = "/var/log/suricata/eve.json"
RULES_DIR = "/usr/share/chp-suricata-rules"
DROPIN = "/etc/systemd/system/suricata.service.d/chp.conf"
SYSCONFIG = "/etc/sysconfig/suricata"
SYSCONFIG_TEXT = '# Managed by chp-security (Suricata spec §3)\nOPTIONS=""\n'
_IFACE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")


def _iface(name):
    if not _IFACE.fullmatch(name or ""):
        raise SiteError(f"{name!r} is not a usable network interface name for Suricata")
    return name


def iface_for(ip, run):
    out = run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/", ln)
        if m and m.group(2) == str(ip):
            return _iface(m.group(1))
    raise SiteError(f"no network interface holds this host's site address {ip}: Suricata cannot pick an interface")


def home_net(site):
    if not site.get("SUBNET"):
        raise SiteError("SUBNET is not set in site.conf: Suricata needs it for HOME_NET")
    return f"[{site['SUBNET']}]"


def config_text(iface, home_net):
    iface = _iface(iface)
    return f"""%YAML 1.1
---
# Managed by chp-security (Suricata spec §3); rewritten by chp-site security enable. IDS only: nothing is blocked.
vars:
  address-groups:
    HOME_NET: "{home_net}"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
default-log-dir: /var/log/suricata/
default-rule-path: {RULES_DIR}
rule-files:
  - chp-suricata.rules
classification-file: {RULES_DIR}/classification.config
reference-config-file: {RULES_DIR}/reference.config
af-packet:
  - interface: {iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    tpacket-v3: yes
stats:
  enabled: yes
  interval: 60
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
  - stats:
      enabled: yes
      filename: stats.log
      interval: 60
logging:
  default-log-level: notice
  outputs:
    - file:
        enabled: yes
        filename: /var/log/suricata/suricata.log
unix-command:
  enabled: no
"""


def dropin_text(iface):
    """systemd drop-in, not OPTIONS: the EPEL unit already passes -c, so OPTIONS="-c ..." gave two -c flags (S1 spike)."""
    iface = _iface(iface)
    return ("# Managed by chp-security (Suricata spec §3): CHP config, site interface, IDS only\n[Service]\nExecStart=\n"
            f"ExecStart=/sbin/suricata -c {CONF} --pidfile /var/run/suricata.pid --af-packet={iface} --user suricata\n")


LOGROTATE = "/etc/logrotate.d/suricata"


def logrotate_text(days):
    """Replaces EPEL's own /etc/logrotate.d/suricata (same globs; a second file would be a logrotate duplicate-entry
    error). Daily, keeping the site's RETENTION_DAYS (spec §3); EPEL's HUP makes Suricata reopen its logs."""
    if isinstance(days, bool) or not str(days).isdigit() or not 1 <= int(days) <= 3650:
        raise SiteError(f"RETENTION_DAYS {days!r} must be a whole number of days from 1 to 3650")
    return f"""# Managed by chp-security (Suricata spec §3); rewritten by chp-site security enable (RETENTION_DAYS).
/var/log/suricata/*.log /var/log/suricata/*.json {{
    daily
    rotate {int(days)}
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}}
"""
