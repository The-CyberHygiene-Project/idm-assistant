# egress.sh (RUNS ON iso5-srv AS ROOT): ISO 0.7.0 Plan 2 item 6, the NextCloud egress table, by test and by breaking it.
c79() { /usr/lib/chp/monitor.d/79-nextcloud-egress.sh 2>&1 | head -2; }
echo "== as apache (the php-fpm/httpd/cron/occ user)"
runuser -u apache -- curl -s -m 5 -o /dev/null -w "outbound 93.184.216.34:80 -> %{http_code} rc=" http://93.184.216.34/; echo $?
runuser -u apache -- curl -s -m 5 -o /dev/null -w "outbound 1.1.1.1:443 -> %{http_code} rc=" https://1.1.1.1/; echo $?
runuser -u apache -- getent hosts example.com >/dev/null; echo "DNS lookup example.com rc=$? (2 = not found)"
runuser -u apache -- getent hosts idm.iso5.lab.test files.iso5.lab.test | awk '{print "hosts: "$0}'
runuser -u apache -- curl -s -m 5 -o /dev/null -w "to this server idm:443 -> %{http_code}\n" --cacert /etc/pki/ca-trust/source/anchors/chp-root.crt https://idm.iso5.lab.test/status
runuser -u apache -- php -r '$s=@fsockopen("93.184.216.34",80,$e,$m,5); echo "php fsockopen out: ".($s?"CONNECTED":"refused ($m)")."\n";'
occ config:system:get has_internet_connection; occ config:system:get mail_smtpmode
curl -s -o /dev/null -w "control, as root: outbound 93.184.216.34:80 -> %{http_code} rc=" -m 5 http://93.184.216.34/; echo $?
sleep 2; echo "== kernel log"; journalctl -k --since -2min --no-pager | grep -o 'CHP-NC-EGRESS[^ ]* .*DST=[0-9.]* .*DPT=[0-9]*' | sed -E 's/ (SRC|LEN|TOS|PREC|TTL|ID|WINDOW|RES|SPT|MAC)=[^ ]*//g' | sort | uniq -c
nft list table inet chp_nextcloud_egress | grep -E 'counter' | sed 's/^\s*//'
echo "== break 1: table removed"; nft delete table inet chp_nextcloud_egress; echo "79: $(c79)"
systemctl restart php-fpm; echo "php-fpm restart rc=$? state=$(systemctl is-active php-fpm)"
systemctl restart httpd; echo "httpd restart rc=$? state=$(systemctl is-active httpd)"
systemctl restart chp-nextcloud-egress; systemctl start php-fpm httpd; echo "restored: egress=$(systemctl is-active chp-nextcloud-egress) php-fpm=$(systemctl is-active php-fpm) httpd=$(systemctl is-active httpd); 79: $(c79)"
echo "== break 2: table edited at run time (an accept rule added)"; nft insert rule inet chp_nextcloud_egress apache_out accept; echo "79: $(c79)"
systemctl restart chp-nextcloud-egress; echo "after egress restart 79: $(c79)"
echo "== break 3: address file widened"; f=/etc/chp/nextcloud-egress-addr.nft; cp -p $f /root/egress-addr.bak
echo 'define CHP_NC_SERVER_IP = 0.0.0.0/0' > $f; echo "79: $(c79)"
systemctl restart chp-nextcloud-egress; echo "egress restart rc=$? state=$(systemctl is-active chp-nextcloud-egress)"; journalctl -u chp-nextcloud-egress -n 3 --no-pager -o cat
echo "php-fpm=$(systemctl is-active php-fpm) httpd=$(systemctl is-active httpd)"
cp -p /root/egress-addr.bak $f; restorecon $f; systemctl restart chp-nextcloud-egress; systemctl start php-fpm httpd nextcloud-cron.timer
echo "restored: egress=$(systemctl is-active chp-nextcloud-egress) php-fpm=$(systemctl is-active php-fpm) httpd=$(systemctl is-active httpd); 79: $(c79)"
