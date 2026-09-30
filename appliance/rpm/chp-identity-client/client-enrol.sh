#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# client-enrol [--role client|server] [--step NAME]: make this host a Kanidm client of the site (spec §7). Idempotent;
# each step is marked /var/lib/chp/firstboot/client-<step>.done. Every value comes from `chp-site get` (client.conf on a
# client; the server's own CA files with --role server). The unixd token (/etc/kanidm/token, 0600) is never read here.
set -Eeuo pipefail
ROLE=client; ONLY=""
while [ $# -gt 0 ]; do case $1 in --role) ROLE=$2; shift 2 ;; --step) ONLY=$2; shift 2 ;; *) echo "usage: client-enrol [--role client|server] [--step NAME]" >&2; exit 2 ;; esac; done
case $ROLE in client|server) ;; *) echo "client-enrol: --role client|server" >&2; exit 2 ;; esac
M=/var/lib/chp/firstboot; ANCHOR=/etc/pki/ca-trust/source/anchors/chp-root.crt; install -d -m 0700 "$M"
log() { echo "chp-client-enrol: $*"; logger -t chp-client-enrol -- "$*"; }
current=""; trap 'log "CHP: client enrolment failed at ${current:-setup} (resume: systemctl restart chp-client-firstboot)"' ERR
step() { local n=$1; shift; current=$n; if [ -n "$ONLY" ] && [ "$ONLY" != "$n" ]; then return 0; fi
         if [ -z "$ONLY" ] && [ -e "$M/client-$n.done" ]; then return 0; fi; log "step $n"; "$@"; touch "$M/client-$n.done"; }
g() { chp-site get "$1"; }
CA=$(g CA_FQDN); IDM=$(g KANIDM_FQDN); SIP=$(g SERVER_IP)
if [ "$ROLE" = server ]; then LOGIN_GROUP=chp_admins; else LOGIN_GROUP=chp_users; fi

do_trust() {
  if [ "$ROLE" = server ]; then [ -s "$ANCHOR" ]; return; fi       # the server made the root itself (first boot)
  PIN=$(g CA_ROOT_SHA256); T=$(mktemp -d); trap 'rm -rf "$T"' RETURN
  STEPPATH="$T" step-cli ca root "$T/root.pem" --ca-url "https://$CA:9000" --fingerprint "$PIN" --force >/dev/null 2>&1 \
    || { log "CHP: refusing: step-ca at $CA did not serve a root matching the pinned $PIN"; return 1; }
  got=$(openssl x509 -in "$T/root.pem" -outform DER | sha256sum | cut -d' ' -f1)
  [ "$got" = "$PIN" ] || { log "CHP: refusing: root fingerprint $got is not the pinned $PIN (client.conf)"; return 1; }
  install -m 0644 "$T/root.pem" "$ANCHOR"; restorecon "$ANCHOR"; update-ca-trust extract
}

do_unixd() {
  [ -s /etc/kanidm/token ] || { log "CHP: no unixd token at /etc/kanidm/token (installer staged none)"; return 1; }
  chmod 0600 /etc/kanidm/token; chown root:root /etc/kanidm/token
  chp-site render kanidm-config > /etc/kanidm/config
  sed "s/@LOGIN_GROUP@/$LOGIN_GROUP/" /usr/share/chp/client/unixd.toml.in > /etc/kanidm/unixd
  chmod 0644 /etc/kanidm/config /etc/kanidm/unixd                  # the CUI umask would leave them unreadable to unixd
  install -d -m 0755 /etc/systemd/system/kanidm-unixd.service.d
  printf '[Service]\nLoadCredential=unixd_token:/etc/kanidm/token\nEnvironment=KANIDM_SERVICE_ACCOUNT_TOKEN_PATH=%%d/unixd_token\n' \
    > /etc/systemd/system/kanidm-unixd.service.d/chp-token.conf
  restorecon -R /etc/kanidm /etc/systemd/system/kanidm-unixd.service.d
  systemctl daemon-reload; systemctl enable --now kanidm-unixd kanidm-unixd-tasks; systemctl restart kanidm-unixd
  for _ in $(seq 30); do if kanidm-unix status 2>/dev/null | grep -q "Kanidm: online"; then return 0; fi; sleep 2; done
  log "CHP: kanidm-unixd is not online (check https://$IDM reachability and the token)"; return 1
}

words() { tr ' ' '\n' | sed '/^$/d'; }
do_authselect() {
  O=/var/lib/chp/authselect-original
  # Record the ORIGINAL (CUI) profile once; a re-run never bases custom/kanidm on custom/kanidm itself.
  if [ ! -s "$O" ]; then
    cur=$(authselect current -r | words | head -1)
    [ "$cur" != custom/kanidm ] || { log "CHP: refusing: already custom/kanidm but no record of the original profile"; return 1; }
    authselect current -r | words > "$O"
  fi
  base=$(head -1 "$O"); mapfile -t feats < <(tail -n +2 "$O")
  [ "${#feats[@]}" -gt 0 ] || { log "CHP: refusing: the original profile $base has no features (CUI expects with-faillock)"; return 1; }
  case $base in custom/*) bdir=/etc/authselect/$base ;; *) bdir=/usr/share/authselect/default/$base ;; esac
  [ -d /etc/authselect/custom/kanidm ] || authselect create-profile kanidm -b "$base" >/dev/null
  for f in system-auth password-auth nsswitch.conf; do cp "$bdir/$f" "/etc/authselect/custom/kanidm/$f"; done
  python3 /usr/libexec/chp/authselect-patch /etc/authselect/custom/kanidm
  authselect select custom/kanidm "${feats[@]}" --force >/dev/null
  for f in "${feats[@]}"; do authselect current -r | words | grep -qx -- "$f" || { log "CHP: LOST authselect feature: $f"; return 1; }; done
  for db in passwd group initgroups; do
    [ "$(awk -v d="$db:" '$1==d{print $2}' /etc/nsswitch.conf)" = kanidm ] || { log "CHP: nsswitch $db does not start with kanidm"; return 1; }
  done
  authselect check >/dev/null
}

do_sshd() {
  D=/etc/ssh/sshd_config.d
  if [ "$ROLE" = server ]; then key=$(cut -d' ' -f1,2 /etc/ssh-ca/user_ca.pub); else key=$(g SSH_CA_PUBKEY); fi
  printf '%s chp-user-ca\n' "$key" > /etc/ssh/chp_user_ca.pub; chmod 0644 /etc/ssh/chp_user_ca.pub
  if [ "$ROLE" = client ]; then
    [ "$(ssh-keygen -lf /etc/ssh/chp_user_ca.pub | awk '{print $2}')" = "$(g SSH_CA_FPR)" ] \
      || { log "CHP: refusing: SSH user CA key does not match SSH_CA_FPR (client.conf)"; return 1; }
  fi
  install -m 0600 /usr/share/chp/client/sshd-10-chp.conf "$D/10-chp.conf"
  install -m 0600 /usr/share/chp/client/sshd-99-chp-exceptions.conf "$D/99-chp-exceptions.conf"
  restorecon /etc/ssh/chp_user_ca.pub "$D/10-chp.conf" "$D/99-chp-exceptions.conf"
  if ! sshd -t; then
    rm -f /etc/ssh/sshd_config.d/10-chp.conf /etc/ssh/sshd_config.d/99-chp-exceptions.conf
    log "CHP: sshd rejected the CHP drop-ins; removed them (sshd unchanged)"; return 1
  fi
  systemctl reload sshd
}

do_accounts() { /usr/libexec/chp/client-accounts --role "$ROLE"; }

step trust do_trust
step unixd do_unixd
step authselect do_authselect
step sshd do_sshd
step accounts do_accounts
if [ -z "$ONLY" ]; then current=done; touch "$M/client.done"; log "CHP: client enrolment complete ($ROLE; logins: $LOGIN_GROUP)"; fi
