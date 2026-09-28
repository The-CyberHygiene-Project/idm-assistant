#!/usr/bin/env bash
# client2: trust the lab root, install unixd from lab-local, configure the Kanidm client + unixd (service-account
# token via the upstream-documented LoadCredential), add Kanidm to a copy of the CUI 'hardening' authselect
# profile, and configure sshd (Kanidm SSH keys + the separate SSH user CA). Staged inputs in /tmp/client:
# kanidm-lab-root.crt, token, trusted_user_ca_keys.
set -Eeuo pipefail
C=/tmp/client
install -m 0644 $C/kanidm-lab-root.crt /etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt && update-ca-trust
dnf -y -q install kanidm-unixd kanidm-clients
printf 'uri = "https://idm.kanidm.lab.test"\nca_path = "/etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt"\n' > /etc/kanidm/config
printf "version = '2'\n\n[kanidm]\npam_allowed_login_groups = [\"lab_users\"]\n" > /etc/kanidm/unixd
chmod 0644 /etc/kanidm/config /etc/kanidm/unixd          # the CUI umask would leave them unreadable to unixd
if [[ -f $C/token ]]; then install -m 0600 $C/token /etc/kanidm/token && shred -u $C/token; fi   # re-runs keep the installed token
mkdir -p /etc/systemd/system/kanidm-unixd.service.d
cat > /etc/systemd/system/kanidm-unixd.service.d/token.conf <<'U'
[Service]
LoadCredential=unixd_token:/etc/kanidm/token
Environment=KANIDM_SERVICE_ACCOUNT_TOKEN_PATH=%d/unixd_token
U
systemctl daemon-reload
systemctl enable --now kanidm-unixd
sleep 3
kanidm-unix status || true
# authselect: copy of the CUI 'hardening' profile + Kanidm (keeps faillock/pam_access/mkhomedir and the features)
[[ -d /etc/authselect/custom/kanidm ]] || authselect create-profile kanidm -b custom/hardening
python3 $C/authselect_patch.py /etc/authselect/custom/kanidm
# Carry every authselect feature of the CUI profile (e.g. with-faillock, without-nullok) over to custom/kanidm, and
# refuse to continue if any is lost. `authselect current -r` output is split on spaces AND newlines to be safe.
words() { tr ' ' '\n' | sed '/^$/d'; }
if [[ $(authselect current -r | words | head -1) != custom/kanidm ]]; then authselect current -r | words > /root/authselect-before-kanidm; fi
mapfile -t feats < <(tail -n +2 /root/authselect-before-kanidm)
(( ${#feats[@]} > 0 )) || { echo "no authselect features recorded; refusing (CUI profile expects with-faillock)" >&2; exit 1; }
authselect select custom/kanidm "${feats[@]}" --force
for f in "${feats[@]}"; do authselect current -r | words | grep -qx -- "$f" || { echo "LOST authselect feature: $f" >&2; exit 1; }; done
install -m 0600 $C/10-kanidm.conf /etc/ssh/sshd_config.d/10-kanidm.conf
if [[ -f $C/trusted_user_ca_keys ]]; then install -m 0644 $C/trusted_user_ca_keys /etc/ssh/trusted_user_ca_keys && shred -u $C/trusted_user_ca_keys; fi
sshd -t && systemctl reload sshd
