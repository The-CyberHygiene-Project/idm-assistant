#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# server-firstboot.sh (root; chp-server-firstboot.service, once): turn an installed server into the identity server.
# Steps run in order; each is skipped when its marker /var/lib/chp/firstboot/<step>.done exists, so a failed first boot
# resumes where it stopped (systemctl restart chp-server-firstboot). Every site value comes from `chp-site get`/`render`.
# Recovery secrets (Kanidm admin passwords, the step-ca password, the ROOT CA key) go to /root/chp-escrow-pending/ only;
# `chp-site export-client` moves them onto the site stick. Nothing secret is printed or put on a command line.
set -Eeuo pipefail
M=/var/lib/chp/firstboot; P=/root/chp-escrow-pending; ANCHOR=/etc/pki/ca-trust/source/anchors/chp-root.crt
install -d -m 0700 "$M" "$P"
log() { echo "chp-server-firstboot: $*"; logger -t chp-server-firstboot -- "$*"; }
current=""
trap 'log "CHP: server first boot failed at ${current:-setup} (resume: systemctl restart chp-server-firstboot)"' ERR
step() { local n=$1; shift; current=$n; if [ -e "$M/$n.done" ]; then return 0; fi; log "step $n"; "$@"; touch "$M/$n.done"; }
g() { chp-site get "$1"; }
DOMAIN=$(g DOMAIN); SIP=$(g SERVER_IP); FQDN=$(g SERVER_FQDN); IDM=$(g KANIDM_FQDN); CA=$(g CA_FQDN)
export STEPPATH=/etc/step-ca
# One-way door, checked before ANY step: once Kanidm was initialised for a domain, a changed site DOMAIN is refused.
if [ -f /var/lib/chp/kanidm-domain ] && [ "$(cat /var/lib/chp/kanidm-domain)" != "$IDM" ]; then
  log "CHP: refusing: Kanidm was initialised for $(cat /var/lib/chp/kanidm-domain), site.conf now says $IDM (the domain is a one-way door)"
  exit 1
fi

do_bind() {
  chp-site render named-conf > /etc/named.conf.chp && install -o root -g named -m 0640 /etc/named.conf.chp /etc/named.conf && rm -f /etc/named.conf.chp
  chp-site render zone > "/var/named/$DOMAIN.zone.chp"
  install -o root -g named -m 0640 "/var/named/$DOMAIN.zone.chp" "/var/named/$DOMAIN.zone"; rm -f "/var/named/$DOMAIN.zone.chp"
  restorecon -R /var/named /etc/named.conf
  named-checkconf; named-checkzone "$DOMAIN" "/var/named/$DOMAIN.zone" >/dev/null
  systemctl enable --now named
  firewall-cmd -q --permanent --add-service=dns; firewall-cmd -q --reload
  [ "$(dig +short @"$SIP" "$IDM")" = "$SIP" ]
}

do_stepca() {
  if [ ! -f /etc/step-ca/config/ca.json ]; then
    install -d -m 0700 /etc/step-ca
    ( umask 077; head -c 32 /dev/urandom | base64 > /etc/step-ca/password )
    step-cli ca init --name "$DOMAIN CA" --dns "$CA" --dns "$FQDN" --address "$SIP:9000" --provisioner admin \
      --password-file /etc/step-ca/password --provisioner-password-file /etc/step-ca/password \
      --deployment-type standalone --acme >/dev/null
  fi
  # Decision 2: the ROOT key leaves the CA directory now (step-ca signs with the intermediate); export-client moves it offline.
  if [ -f /etc/step-ca/secrets/root_ca_key ]; then
    install -m 0600 /dev/null "$P/root_ca_key"; mv -f /etc/step-ca/secrets/root_ca_key "$P/root_ca_key"; chmod 0600 "$P/root_ca_key"
  fi
  install -m 0600 /etc/step-ca/password "$P/step-ca-password"
  chown -R step:step /etc/step-ca
  install -m 0644 /etc/step-ca/certs/root_ca.crt "$ANCHOR"; update-ca-trust
  systemctl enable --now step-ca
  firewall-cmd -q --permanent --add-port=9000/tcp; firewall-cmd -q --reload
  for _ in $(seq 30); do if step-cli ca health --ca-url "https://$CA:9000" --root "$ANCHOR" >/dev/null 2>&1; then break; fi; sleep 2; done
  step-cli ca health --ca-url "https://$CA:9000" --root "$ANCHOR" >/dev/null
}

do_kanidm_cert() {
  install -d -m 0700 /etc/pki/kanidm
  STEPPATH=/root/.step step-cli ca bootstrap --ca-url "https://$CA:9000" --fingerprint "$(step-cli certificate fingerprint "$ANCHOR")" --force >/dev/null
  /usr/libexec/chp/cert-renew-kanidm --issue
  systemctl enable --now cert-renew-kanidm.timer
}

do_kanidmd() {
  chp-site render kanidm-server > /etc/kanidm/server.toml; chmod 0644 /etc/kanidm/server.toml
  chp-site render kanidm-config > /etc/kanidm/config; chmod 0644 /etc/kanidm/config
  systemctl daemon-reload; systemctl enable --now kanidmd
  firewall-cmd -q --permanent --add-service=https; firewall-cmd -q --reload
  for _ in $(seq 30); do if curl -fsS --cacert "$ANCHOR" "https://$IDM/status" >/dev/null 2>&1; then break; fi; sleep 2; done
  curl -fsS --cacert "$ANCHOR" "https://$IDM/status" >/dev/null
  echo "$IDM" > /var/lib/chp/kanidm-domain      # the guard is set once Kanidm really runs (a typo fixed before this is fine)
}

do_recover() {
  # Passwords go kanidmd -> python (stdin) -> a 0600 JSON file. Nothing is printed.
  ( umask 077
    { kanidmd scripting -c /etc/kanidm/server.toml recover-account admin 2>/dev/null; echo "@@"
      kanidmd scripting -c /etc/kanidm/server.toml recover-account idm_admin 2>/dev/null; } \
    | python3 -c '
import json, sys
parts = sys.stdin.read().split("@@")
def pw(t):   # kanidmd scripting prints {"output":"<password>","status":"ok"}
    for line in reversed(t.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            d = json.loads(line)
            if d.get("status") == "ok" and isinstance(d.get("output"), str) and d["output"]:
                return d["output"]
    raise SystemExit("no password in kanidmd scripting recover-account output")
json.dump({"admin": pw(parts[0]), "idm_admin": pw(parts[1])}, open(sys.argv[1], "w"))' "$P/kanidm-admins.json" )
}

do_collector() {
  # Kanidm can still be busy right after recover (password hashing is deliberately slow): retry the login a few times.
  for try in 1 2 3 4 5; do
    if python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["idm_admin"])' "$P/kanidm-admins.json" \
         | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null; then break; fi
    if [ "$try" -eq 5 ]; then return 1; fi
    log "kanidm login not ready yet (try $try/5); retrying in 10 s"; sleep 10
  done
  k() { kanidm "$@" -D idm_admin >/dev/null 2>&1; }
  # capture first, then grep: piping kanidm into an early-exiting grep can fail on EPIPE under pipefail and look like "not found" on a resume
  existing=$(kanidm service-account get idm-collect -D idm_admin 2>/dev/null || true)
  if ! grep -qx 'name: idm-collect' <<< "$existing"; then
    k service-account create idm-collect "CHP read-only collector" idm_admins
  fi
  for grp in idm_service_desk idm_unix_admins; do k group add-members "$grp" idm-collect; done
  install -d -m 0700 /etc/idm-collect
  ( umask 077
    kanidm service-account api-token generate idm-collect collector-ro -D idm_admin 2>/dev/null \
      | grep -oE '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' | tail -n 1 > /etc/idm-collect/kanidm.token )
  [ -s /etc/idm-collect/kanidm.token ]
  chp-site render collect-conf > /etc/idm-collect/collect.conf; chmod 0644 /etc/idm-collect/collect.conf
  restorecon -R /etc/idm-collect
  kanidm logout -D idm_admin >/dev/null 2>&1 || true   # do not leave an idm_admin session token in /root/.cache
}

do_sshca() {
  install -d -m 0700 /etc/ssh-ca
  if [ ! -f /etc/ssh-ca/user_ca ]; then ssh-keygen -q -t ecdsa -b 384 -N '' -C "$DOMAIN user CA" -f /etc/ssh-ca/user_ca; fi
  install -d -m 0755 /var/lib/ssh-ca /var/lib/ssh-ca/keys /var/lib/ssh-ca/issued
  restorecon -R /etc/ssh-ca /var/lib/ssh-ca
}

do_cachekey() {
  # The server's key for `chp-site revoke`: clients (Plan 4) accept it only from this server's IP, only for the forced
  # command `sudo -n /usr/bin/kanidm-unix cache-invalidate` (ISSO #28). Public half goes to client.conf (CACHE_PUBKEY).
  install -d -m 0700 /var/lib/chp/cache-key
  if [ ! -f /var/lib/chp/cache-key/id_ecdsa ]; then
    ssh-keygen -q -t ecdsa -b 384 -N '' -C "chpcache@$FQDN" -f /var/lib/chp/cache-key/id_ecdsa
  fi
  restorecon -R /var/lib/chp/cache-key
}

step bind do_bind
step step-ca do_stepca
step kanidm-cert do_kanidm_cert
step kanidmd do_kanidmd
step recover do_recover
step collector do_collector
step ssh-ca do_sshca
step cache-key do_cachekey
current=done
touch "$M/server.done"
log "CHP: server first boot complete. Move the recovery secrets offline: plug in the site stick and run chp-site export-client"
