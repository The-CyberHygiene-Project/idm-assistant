#!/usr/bin/env bash
# diag-access.sh HOST...  (RUNS ON THE MAC): create the read-only `diag` account on each HOST: SSH key only, and a
# single-command sudo rule for /usr/sbin/idm-collect (RPM, built by appliance/rpm/idm-collect/build-rpm.sh) and writes
# the collector's site config (lab values).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"; K=~/idm-lab-secrets/diag_ecdsa
[[ -f $K ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C 'idm-assistant diag' -f "$K"
# the CUI profile enforces localpkg_gpgcheck: install the SIGNED RPM and trust the project key first
RPM=idm-collect-0.1.0-5.chp.el9.noarch.rpm          # from the signed repo (RELEASE-RECORD-0.5.4.md)
scp -q aero:/data/chp-release/0.5.4/repo/$RPM /tmp/
for h in "$@"; do
  scp -q /tmp/$RPM "$K.pub" "$here/../appliance/release/RPM-GPG-KEY-cyberhygiene" "$h:/tmp/"
  ssh "$h" "sudo RPM=$RPM bash -s" <<'REMOTE'          # the remote half is quoted: RPM is passed in
set -euo pipefail
id diag >/dev/null 2>&1 || useradd -r -m -s /bin/bash -c "idm-assistant read-only collector" diag
install -d -o diag -g diag -m 0700 /home/diag/.ssh
install -o diag -g diag -m 0600 /tmp/diag_ecdsa.pub /home/diag/.ssh/authorized_keys
rm -f /usr/local/sbin/idm-collect /usr/local/sbin/idm-collect.redact.sed
install -m 0644 /tmp/RPM-GPG-KEY-cyberhygiene /etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
dnf -y -q install /tmp/$RPM
printf '%s\n' 'KANIDM_URL=https://idm.kanidm.lab.test' 'CA_ANCHOR=/etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt' > /etc/idm-collect/collect.conf
chmod 0644 /etc/idm-collect/collect.conf
restorecon -R /home/diag /etc/idm-collect
printf '%s\n' 'diag ALL=(root) NOPASSWD: /usr/sbin/idm-collect, /usr/sbin/idm-collect --user *' > /tmp/61-diag
visudo -cf /tmp/61-diag >/dev/null
install -o root -g root -m 0440 /tmp/61-diag /etc/sudoers.d/61-diag
rm -f /tmp/$RPM /tmp/RPM-GPG-KEY-cyberhygiene /tmp/diag_ecdsa.pub /tmp/61-diag
echo "diag ready on $(hostname -s)"
REMOTE
done
