#!/usr/bin/env bash
# iso1-install-test.sh (RUNS ON THE MAC): install the signed 0.1.0 repo's packages on srv1 + client2 with
# gpgcheck=1 and repo_gpgcheck=1; prove dnf refuses the repo without our key; check the services, the unixd lookup
# and fapolicyd. Finish with lab/reset.sh (golden restores the lab builds).
set -Eeuo pipefail
here="$(cd "$(dirname "$0")/../.." && pwd)"
trap 'echo "== restore golden"; bash "$here/lab/reset.sh"' EXIT   # always leave the lab at golden, pass or fail
REPO='[chp]
name=CyberHygiene Project Lab Installer packages 0.1.0
baseurl=http://192.168.100.1:8080/chp/0.1.0/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9'
for h in srv1 client2; do
  scp -q "$here"/appliance/release/RPM-GPG-KEY-cyberhygiene "$here"/appliance/release/RPM-GPG-KEY-EPEL-9 "$h:/tmp/"
  ssh "$h" "set -e; sudo install -m0644 /tmp/RPM-GPG-KEY-cyberhygiene /tmp/RPM-GPG-KEY-EPEL-9 /etc/pki/rpm-gpg/; printf '%s\n' '$REPO' | sudo tee /etc/yum.repos.d/chp.repo >/dev/null"
done
echo "== negative: without our key dnf must refuse the repo"
ssh client2 "set -e; sudo sed -i 's|^gpgkey=.*|gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9|' /etc/yum.repos.d/chp.repo; sudo dnf -q clean all"
if ssh client2 'sudo dnf -y -q --repo chp makecache' >/dev/null 2>&1; then echo "FAIL: repo accepted without our key"; exit 1; fi
echo "PASS: refused"
ssh client2 "set -e; sudo sed -i 's|^gpgkey=.*|gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9|' /etc/yum.repos.d/chp.repo; sudo dnf -q clean all"
start=$(ssh srv1 'date +%H:%M:%S')
echo "== srv1: server-side packages"
ssh srv1 'sudo dnf -y -q upgrade kanidm-server kanidm-clients step-ca step-cli && rpm -q kanidm-server step-ca step-cli && sudo systemctl restart kanidmd step-ca && sleep 5 && systemctl is-active kanidmd step-ca'
ssh srv1 'A=/etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt; curl -fsS --cacert $A https://idm.kanidm.lab.test/status; echo; step-cli ca health --ca-url https://ca.kanidm.lab.test:9000 --root $A'   # public anchor copy (/etc/step-ca is 0700 step)
echo "== client2: unixd (FIPS variant) against the FIPS-variant server"
ssh client2 'sudo dnf -y -q upgrade kanidm-unixd kanidm-clients && rpm -q kanidm-unixd && sudo systemctl restart kanidm-unixd kanidm-unixd-tasks && sleep 5 && sudo kanidm-unix status && getent passwd lab02'
for h in srv1 client2; do
  echo "== $h: signatures + fapolicyd"
  ssh "$h" 'for p in $(rpm -qa --qf "%{NAME}\n" | grep -E "^(kanidm|step|idm-collect)"); do rpm -q --qf "%{NAME}-%{VERSION}-%{RELEASE} %{RSAHEADER:pgpsig}\n" $p; done'
  ssh "$h" "sudo ausearch --input-logs -m FANOTIFY -ts $start </dev/null 2>/dev/null | grep -c type=FANOTIFY || true"
done

