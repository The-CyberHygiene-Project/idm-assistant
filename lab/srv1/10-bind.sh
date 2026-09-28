#!/usr/bin/env bash
# srv1: authoritative-only BIND for kanidm.lab.test, lab subnet only, no recursion (offline lab).
set -Eeuo pipefail
install -o root -g named -m 0640 /tmp/srv1/kanidm.lab.test.zone /var/named/kanidm.lab.test.zone
cat > /etc/named.conf <<'N'
options {
    listen-on port 53 { 127.0.0.1; 192.168.100.10; };
    listen-on-v6 { none; };
    directory "/var/named";
    allow-query { 127.0.0.1; 192.168.100.0/24; };
    recursion no;
    dnssec-validation no;
    pid-file "/run/named/named.pid";
};
logging { channel default_debug { file "data/named.run"; severity dynamic; }; };
zone "kanidm.lab.test" IN { type primary; file "kanidm.lab.test.zone"; allow-update { none; }; };
N
restorecon -R /var/named /etc/named.conf
named-checkconf
named-checkzone kanidm.lab.test /var/named/kanidm.lab.test.zone
systemctl enable --now named
firewall-cmd -q --permanent --add-service=dns
firewall-cmd -q --reload
dig +short @192.168.100.10 idm.kanidm.lab.test
