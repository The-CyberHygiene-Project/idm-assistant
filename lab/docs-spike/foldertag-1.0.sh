#!/usr/bin/env bash
# foldertag-1.0.sh STAGE (RUNS ON THE MAC): ISO 0.7.0 Plan 2 Task 3 lab test of the PRODUCT chp_foldertag 1.0
# (appliance/rpm/nextcloud-chp/chp_foldertag) on the spike server iso5-docs, without the product RPM (that RPM
# drops the spike's web/cron/egress files, which move to chp-documents in Task 4).
#   install   back up the spike's 0.2.0 app to /root/spike/chp_foldertag-0.2.0 (once), copy 1.0 into
#             /usr/lib/nextcloud/apps/chp_foldertag (root:root 0644/0755, restorecon),
#             SPIKE-ONLY TRUST STEP: fapolicyd-cli --file add/update into trust file chp-spike + --update (the
#             product gets its trust from the signed RPM via the rpm database), php -l every file, then occ upgrade.
#             Undo: copy /root/spike/chp_foldertag-0.2.0 back is NOT enough (NextCloud refuses a version downgrade);
#             reinstall the spike RPM instead.
#   install-rpm  the same, but with the app files taken from the newest RPM built on chp-build (rpm2cpio)
#   config    contain_allow = [[CUI,Archive],[Archive,CUI]] (owner decision 3); prints rules/contain/contain_allow
#   audit N   the last N chp_foldertag lines of /var/log/nextcloud/audit.log
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/ssh_config"; APP="$here/../../appliance/rpm/nextcloud-chp/chp_foldertag"
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
case ${1:-} in
  install|install-rpm)
    if [ "$1" = install-rpm ]; then   # the app files exactly as packaged in the newest RPM built on chp-build
      ssh -F "$here/../build-vm/ssh_config" -o BatchMode=yes chp-build 'f=$(ls -t ~/nc-chp/RPMS/noarch/nextcloud-chp-*.rpm | head -1)
          echo "from $(basename $f) $(sha256sum $f | cut -c1-16)..." >&2; d=$(mktemp -d); cd $d
          rpm2cpio $f | cpio -idm "./usr/lib/nextcloud/apps/chp_foldertag/*" 2>/dev/null
          tar -C usr/lib/nextcloud/apps -cf - chp_foldertag; rm -rf $d' | X 'rm -rf ~/ft && mkdir ~/ft && tar -C ~/ft -xf -'
    else
      COPYFILE_DISABLE=1 tar --no-xattrs -C "$APP/.." -cf - --exclude .DS_Store chp_foldertag | X 'rm -rf ~/ft && mkdir ~/ft && tar -C ~/ft -xf -'
    fi
    X 'set -e
      A=/usr/lib/nextcloud/apps/chp_foldertag
      [ -d /root/spike/chp_foldertag-0.2.0 ] || sudo cp -a $A /root/spike/chp_foldertag-0.2.0
      sudo rm -rf $A && sudo cp -r ~/ft/chp_foldertag $A && sudo chown -R root:root $A
      sudo find $A -type d -exec chmod 755 {} + -o -type f -exec chmod 644 {} +
      sudo restorecon -RF $A
      echo "+ SPIKE-ONLY trust: fapolicyd-cli --file add/update $A/ (trust file chp-spike) + --update"
      sudo fapolicyd-cli --file add $A/ --trust-file chp-spike >/dev/null 2>&1 || true
      sudo fapolicyd-cli --file update $A/ --trust-file chp-spike 2>&1 | tail -1
      sudo fapolicyd-cli --update
      rm -rf ~/ft
      echo "+ php -l (on the trusted copy: fapolicyd denies php reading untrusted .php in a home folder)"
      for f in $(sudo find $A -name "*.php"); do sudo php -l "$f"; done
      sudo occ upgrade 2>&1 | tail -4
      sudo occ app:list --output=json | python3 -c "import json,sys; print(\"chp_foldertag\", json.load(sys.stdin)[\"enabled\"].get(\"chp_foldertag\"))"
      sudo rpm -V nextcloud-chp 2>&1 | grep -c chp_foldertag | sed "s/^/rpm -V lines for chp_foldertag (expected: the spike RPM no longer matches): /"' ;;
  config)
    X 'sudo occ config:app:set chp_foldertag contain_allow --value="[[1,3],[3,1]]" >/dev/null
       for k in rules contain contain_allow; do echo "$k = $(sudo occ config:app:get chp_foldertag $k)"; done' ;;
  audit) X "sudo grep '\"app\":\"chp_foldertag\"' /var/log/nextcloud/audit.log | tail -${2:-20}" ;;
  *) echo "usage: $0 install|install-rpm|config|audit [N]"; exit 2 ;;
esac
