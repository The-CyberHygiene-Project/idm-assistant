#!/bin/bash
# setup.sh STAGE (RUNS ON iso5-docs AS ROOT; staged by spike.sh): the NextCloud spike on a CHP server. Idempotent stages.
#   packages  Rocky-signed packages from the Rocky 9.8 DVD (attached read-only as a CD, mounted /mnt/dvd; gpgcheck on)
#             + the UNSIGNED spike RPM (/root/spike/nextcloud-chp-*.rpm, --nogpgcheck: the recorded trust decision)
#   db        PostgreSQL 16: initdb, peer auth over the Unix socket only (no TCP, no database password)
#   install   occ maintenance:install (data on /data/nextcloud/data); break-glass admin password -> /root/chp-escrow-pending
#   config    offline + hardening settings, apps on/off, logs (nextcloud.log, audit.log)
#   web       DNS name files.<domain>, step-ca certificate over ACME (like Kanidm), httpd + php-fpm, firewalld LAN-only 8443
#   trust     fapolicyd: config.php trust entry, filesystem marks, the NextCloud read rules
#   oidc      SELinux boolean, CA, user_oidc provider for Kanidm (after kanidm.sh oauth2)
#   egress    nftables: the web server user (apache) may reach only this server; everything else dropped AND logged
set -Eeuo pipefail
DOMAIN=$(chp-site get DOMAIN); SIP=$(chp-site get SERVER_IP); SUBNET=$(sed -n "s/^SUBNET=//p" /etc/chp/site.conf)   # chp-site get SUBNET drops the /prefix
FILES=files.$DOMAIN; IDM=$(chp-site get KANIDM_FQDN); PORT=8443
D=/data/nextcloud; P=/root/chp-escrow-pending
DVD=(--disablerepo='*' --repofrompath=dvd-appstream,file:///mnt/dvd/AppStream --repofrompath=dvd-baseos,file:///mnt/dvd/BaseOS
     --setopt=dvd-appstream.gpgcheck=1 --setopt=dvd-baseos.gpgcheck=1)
occ() { /usr/bin/occ "$@"; }
case ${1:-} in
  packages)
    mountpoint -q /mnt/dvd || { echo "mount the Rocky DVD on /mnt/dvd first"; exit 1; }
    dnf -y -q "${DVD[@]}" module enable php:8.3 postgresql:16
    dnf -y -q "${DVD[@]}" install httpd mod_ssl php-fpm php-cli php-gd php-mbstring php-intl php-xml php-pgsql php-process \
      php-bcmath php-gmp php-opcache php-pecl-zip php-pecl-apcu php-pdo postgresql-server
    # the trust decision: an UNSIGNED local package (localpkg_gpgcheck=1 refuses it otherwise); fapolicyd then trusts
    # its files through the rpm database like any installed package
    dnf -y -q --disablerepo='*' --nogpgcheck install /root/spike/nextcloud-chp-*.rpm
    rpm -q httpd mod_ssl php-fpm php-cli postgresql-server nextcloud-chp --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n' ;;
  db)
    [ -s /var/lib/pgsql/data/PG_VERSION ] || postgresql-setup --initdb >/dev/null
    # Unix socket only; peer authentication (the OS user IS the database user): no password anywhere
    sed -i "s/^#\?listen_addresses.*/listen_addresses = ''/" /var/lib/pgsql/data/postgresql.conf
    printf '%s\n' '# CHP spike: Unix socket only, peer authentication' 'local all postgres peer' 'local nextcloud apache peer' \
      > /var/lib/pgsql/data/pg_hba.conf
    systemctl enable -q --now postgresql; systemctl reload postgresql
    runuser -u postgres -- psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname='apache'" | grep -q 1 \
      || runuser -u postgres -- psql -qc "CREATE ROLE apache LOGIN"
    runuser -u postgres -- psql -qtAc "SELECT 1 FROM pg_database WHERE datname='nextcloud'" | grep -q 1 \
      || runuser -u postgres -- psql -qc "CREATE DATABASE nextcloud OWNER apache TEMPLATE template0 ENCODING 'UTF8'"
    runuser -u postgres -- psql -qtAc "SHOW password_encryption; SHOW listen_addresses; SELECT version();" ;;
  install)
    install -d -m 0750 -o apache -g apache $D $D/data; semanage fcontext -a -t httpd_sys_rw_content_t "$D(/.*)?" 2>/dev/null || true
    restorecon -R $D
    if ! occ status --output=json 2>/dev/null | grep -q '"installed":true'; then
      install -d -m 0700 $P; umask 077
      [ -s $P/nextcloud-admin.txt ] || python3 -c 'import secrets; print("NEXTCLOUD_ADMIN_PASSWORD=" + secrets.token_urlsafe(24))' > $P/nextcloud-admin.txt
      # no admin on the install command line (it would show in ps): install without one, then user:add reads OC_PASS
      runuser -u apache -- /usr/bin/php -d memory_limit=512M /usr/lib/nextcloud/occ maintenance:install \
        --database pgsql --database-name nextcloud --database-host /run/postgresql --database-user apache --database-pass '' \
        --disable-admin-user --data-dir $D/data
      # FIPS: PHP's Argon2id fails ("Password hashing failed"); bcrypt (PASSWORD_DEFAULT) for the one local account
      occ config:system:set hashing_default_password --type=boolean --value=true >/dev/null
    fi
    if ! occ user:info ncadmin >/dev/null 2>&1; then
      OC_PASS=$(sed -n 's/^NEXTCLOUD_ADMIN_PASSWORD=//p' $P/nextcloud-admin.txt) \
        runuser -u apache --whitelist-environment=OC_PASS -- /usr/bin/php /usr/lib/nextcloud/occ user:add --password-from-env \
        --display-name "Break-glass admin" --group admin ncadmin
    fi
    occ status ;;
  config)
    s() { occ config:system:set "$@" >/dev/null; }
    s trusted_domains 0 --value="$FILES"
    s overwrite.cli.url --value="https://$FILES:$PORT"
    s overwritehost --value="$FILES:$PORT"; s overwriteprotocol --value=https
    # no internet: the four switches NextCloud has, plus every feature that would call out
    s has_internet_connection --type=boolean --value=false
    s appstoreenabled --type=boolean --value=false
    s updatechecker --type=boolean --value=false
    s upgrade.disable-web --type=boolean --value=true
    s check_for_working_wellknown_setup --type=boolean --value=false
    s lookup_server --value=''
    s gs.enabled --type=boolean --value=false
    s knowledgebaseenabled --type=boolean --value=false
    s reference_opengraph --type=boolean --value=false
    s enable_previews --type=boolean --value=false
    s skeletondirectory --value=''; s templatedirectory --value=''
    s mail_smtpmode --value=null
    s memcache.local --value='\OC\Memcache\APCu'
    s filelocking.enabled --type=boolean --value=true
    s auth.bruteforce.protection.enabled --type=boolean --value=true
    s session_lifetime --type=integer --value=900; s session_keepalive --type=boolean --value=false
    s remember_login_cookie_lifetime --type=integer --value=0; s auto_logout --type=boolean --value=true
    s sharing.enable_share_accept --type=boolean --value=false
    s log_type --value=file; s logfile --value=/var/log/nextcloud/nextcloud.log; s loglevel --type=integer --value=2
    s log_type_audit --value=file; s logfile_audit --value=/var/log/nextcloud/audit.log
    occ config:system:set log.condition apps 0 --value=admin_audit >/dev/null   # else loglevel 2 drops every audit line (they are level 1)
    s logtimezone --value=UTC; s default_phone_region --value=US
    s maintenance_window_start --type=integer --value=8
    occ background:cron >/dev/null
    # apps: on = what the design needs; off = editors, outbound features, federation, extras
    for a in admin_audit groupfolders files_accesscontrol user_oidc chp_foldertag systemtags password_policy \
             bruteforcesettings files_downloadlimit workflowengine; do occ app:enable "$a" >/dev/null 2>&1 || echo "could not enable $a"; done
    for a in text office firstrunwizard recommendations survey_client nextcloud_announcements updatenotification federation \
             federatedfilesharing lookup_server_connector sharebymail weather_status support app_api webhook_listeners \
             files_external contactsinteraction dashboard circles photos related_resources user_status files_reminders \
             privacy suspicious_login twofactor_nextcloud_notification cloud_federation_api; do
      occ app:disable "$a" >/dev/null 2>&1 || true; done
    # sharing: no federation, no mail shares; public links only with password + expiry; no resharing
    a() { occ config:app:set core "$1" --value="$2" >/dev/null; }
    a shareapi_allow_resharing no; a shareapi_enforce_links_password yes; a shareapi_default_expire_date yes
    a shareapi_enforce_expire_date yes; a shareapi_expire_after_n_days 7; a shareapi_allow_public_upload no
    occ config:app:set files_sharing outgoing_server2server_share_enabled --value=no >/dev/null
    occ config:app:set files_sharing incoming_server2server_share_enabled --value=no >/dev/null
    occ config:app:set files_sharing lookupServerEnabled --value=no >/dev/null
    occ config:app:set files_sharing lookupServerUploadEnabled --value=no >/dev/null
    occ app:list --enabled --output=json | python3 -c 'import json,sys; print("enabled:", " ".join(sorted(json.load(sys.stdin)["enabled"])))' ;;
  web)
    Z=/var/named/$DOMAIN.zone
    if ! grep -q "^files " $Z; then
      sed -i "s/^\(@ IN SOA [^(]*( *\)\([0-9]*\)/\1$(date +%Y%m%d%H)/" $Z; echo "files IN A $SIP" >> $Z
      named-checkzone -q "$DOMAIN" $Z && rndc reload "$DOMAIN" >/dev/null
    fi
    getent hosts "$FILES" || { sleep 2; getent hosts "$FILES"; }
    install -d -m 0750 -g apache /etc/pki/nextcloud
    if [ ! -s /etc/pki/nextcloud/chain.pem ]; then
      export STEPPATH=/root/.step
      firewall-cmd -q --add-service=http
      step-cli ca certificate "$FILES" /etc/pki/nextcloud/chain.pem /etc/pki/nextcloud/key.pem --provisioner acme --kty EC --crv P-384 --force >/dev/null || rc=$?
      firewall-cmd -q --remove-service=http || true; [ "${rc:-0}" -eq 0 ]
      chmod 0640 /etc/pki/nextcloud/*.pem; chgrp apache /etc/pki/nextcloud/*.pem; restorecon -R /etc/pki/nextcloud
    fi
    openssl x509 -in /etc/pki/nextcloud/chain.pem -noout -subject -issuer -enddate
    # httpd: ONLY the NextCloud vhost on $PORT (Kanidm owns SERVER_IP:443; step-ca's ACME challenge needs :80 free)
    sed -i 's/^Listen 80$/# CHP: no plain HTTP listener\n#Listen 80/' /etc/httpd/conf/httpd.conf
    for f in ssl welcome userdir autoindex; do if [ -f /etc/httpd/conf.d/$f.conf ]; then mv /etc/httpd/conf.d/$f.conf /etc/httpd/conf.d/$f.conf.disabled; fi; done
    # php-fpm: only our pool (the stock www pool is not needed)
    if [ -f /etc/php-fpm.d/www.conf ]; then mv /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf.disabled; fi
    systemctl enable -q --now php-fpm httpd; systemctl restart php-fpm httpd
    fz=$(firewall-cmd --get-default-zone)
    firewall-cmd -q --permanent --zone="$fz" --add-rich-rule="rule family=ipv4 source address=$SUBNET port port=$PORT protocol=tcp accept"
    firewall-cmd -q --reload; firewall-cmd --zone="$fz" --list-rich-rules
    systemctl enable -q --now nextcloud-cron.timer
    curl -sS -o /dev/null -w "status.php over TLS: %{http_code}\n" --resolve "$FILES:$PORT:$SIP" "https://$FILES:$PORT/status.php" ;;
  trust)
    # fapolicyd (found in the spike): config.php is PHP that NextCloud itself writes -> a path trust entry (integrity=none);
    # filesystem marks so services in a private mount namespace (php-fpm, httpd: PrivateTmp=yes) are checked at all;
    # rules.d/65-chp-nextcloud.rules (staged in /root/spike) for users' script-type files read by php-fpm/php/rsync
    fapolicyd-cli --dump-db | grep -q " /etc/nextcloud/config.php " || { fapolicyd-cli --file add /etc/nextcloud/config.php --trust-file nextcloud; fapolicyd-cli --update; }
    install -m 0644 /root/spike/65-chp-nextcloud.rules /etc/fapolicyd/rules.d/65-chp-nextcloud.rules; restorecon /etc/fapolicyd/rules.d/65-chp-nextcloud.rules
    sed -i "s/^allow_filesystem_mark = 0/allow_filesystem_mark = 1/" /etc/fapolicyd/fapolicyd.conf
    fagenrules --load >/dev/null; systemctl restart fapolicyd; fapolicyd-cli --check-status | grep -E "Denied" ;;
  oidc)
    # NextCloud -> Kanidm (this server, :443): SELinux httpd_can_network_relay (http ports only; the egress rule limits
    # where); NextCloud's own CA bundle gets the site root; allow_local_remote_servers (Kanidm is a LAN address)
    setsebool -P httpd_can_network_relay on
    occ security:certificates:import /etc/pki/ca-trust/source/anchors/chp-root.crt
    occ config:system:set allow_local_remote_servers --type=boolean --value=true
    install -m 0640 -g apache /root/spike/oidc-secret /etc/nextcloud/oidc-secret; restorecon /etc/nextcloud/oidc-secret
    occ user_oidc:provider kanidm --clientid=nextcloud --clientsecret-file=/etc/nextcloud/oidc-secret \
      --discoveryuri="https://$IDM/oauth2/openid/nextcloud/.well-known/openid-configuration" --scope="openid profile email groups" \
      --unique-uid=0 --mapping-uid=preferred_username --mapping-display-name=name --mapping-email=email --mapping-groups=chp_groups \
      --group-provisioning=1 --group-whitelist-regex='^(cui-users|doc-reviewers|chp-users)$' --check-bearer=0 --send-id-token-hint=1
    occ config:app:set --value=0 user_oidc allow_multiple_user_backends ;;
  egress)
    # the rules come from stdin (spike.sh pipes nextcloud-egress.nft): fapolicyd denies nft opening an untrusted .nft file
    nft -f - ; nft list table inet chp_nextcloud_egress ;;
  *) echo "usage: $0 packages|db|install|config|web|trust|oidc|egress"; exit 2 ;;
esac
