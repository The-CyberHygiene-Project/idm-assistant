#!/usr/bin/env bash
# proto/ledger-setup.sh STAGE (RUNS ON THE MAC; Task 2 SPIKE, throwaway): install the two ledger prototypes on iso5-docs.
#   l1      the NextCloud app chp_ledger (OCS endpoint over NextCloud's own HTTPS) + /var/lib/chp-docs (spool, out,
#           ledger) + the root appender docs_ledger.py + chp-docs-ledger.path/.service; SELinux labels; fapolicyd trust
#   l2      the "Approvals" team folder (chp-users: read + create only) as the drop folder of route L2
#   stick   a directory standing for the mounted site stick (/root/spike/stick)
#   sh CMD  sudo bash -c CMD on the server
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; F="$here/../ssh_config"
X() { ssh -F "$F" -o BatchMode=yes docs "$@"; }
O() { echo "+ occ $*" >&2; X "sudo occ $(printf '%q ' "$@")"; }
case ${1:-} in
  l1)
    tar -C "$here" -cf - chp_ledger docs_ledger.py units | X 'rm -rf ~/l1 && mkdir ~/l1 && tar -C ~/l1 -xf -'
    X 'set -e; cd ~/l1
      sudo rm -rf /usr/lib/nextcloud/apps/chp_ledger
      sudo cp -r chp_ledger /usr/lib/nextcloud/apps/ && sudo chown -R root:root /usr/lib/nextcloud/apps/chp_ledger
      sudo find /usr/lib/nextcloud/apps/chp_ledger -type d -exec chmod 755 {} + -o -type f -exec chmod 644 {} +
      sudo install -d -m 0755 /usr/local/libexec/chp-spike && sudo install -m 0644 docs_ledger.py /usr/local/libexec/chp-spike/
      sudo install -m 0644 units/chp-docs-ledger.path units/chp-docs-ledger.service units/chp-docs-ledger-alert.service /etc/systemd/system/
      sudo install -d -m 0755 -o root -g root /var/lib/chp-docs
      sudo install -d -m 1730 -o root -g apache /var/lib/chp-docs/spool     # apache may add (and rename its own); not list
      sudo install -d -m 0750 -o root -g apache /var/lib/chp-docs/out        # results (0640 root:apache): apache reads, cannot write
      sudo install -d -m 0700 -o root -g root /var/lib/chp-docs/quarantine  # fix 5: requests that failed
      sudo install -d -m 0700 -o root -g root /var/lib/chp-docs/ledger      # the ledger: apache cannot even read it
      echo "+ semanage fcontext: spool = httpd_sys_rw_content_t, out = httpd_sys_content_t"
      sudo semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/chp-docs/spool(/.*)?" 2>/dev/null || true
      sudo semanage fcontext -a -t httpd_sys_content_t "/var/lib/chp-docs/out(/.*)?" 2>/dev/null || true
      sudo restorecon -RF /var/lib/chp-docs /usr/lib/nextcloud/apps/chp_ledger /usr/local/libexec/chp-spike
      echo "+ fapolicyd-cli --file add (trust file chp-spike) + --update"
      for f in /usr/lib/nextcloud/apps/chp_ledger/ /usr/local/libexec/chp-spike/docs_ledger.py; do
        sudo fapolicyd-cli --file add $f --trust-file chp-spike >/dev/null 2>&1 || true
        sudo fapolicyd-cli --file update $f --trust-file chp-spike 2>&1 | tail -1   # a changed file needs its new hash
      done
      sudo fapolicyd-cli --update
      sudo systemctl daemon-reload && sudo systemctl reset-failed chp-docs-ledger.path chp-docs-ledger.service 2>/dev/null; sudo systemctl enable chp-docs-ledger.path && sudo systemctl restart chp-docs-ledger.path
      ls -laZ /var/lib/chp-docs; systemctl is-active chp-docs-ledger.path; rm -rf ~/l1'
    O app:enable chp_ledger ;;
  l2)
    id=$(X 'sudo occ groupfolders:list --output=json' | python3 -c 'import json,sys; print(next((str(f["id"]) for f in json.load(sys.stdin) if f["mountPoint"]=="Approvals"), ""))')
    [[ -n $id ]] || id=$(O groupfolders:create Approvals)
    # team-folder permissions have no "create" (read write share delete; logs/54), so: read + write, then an ACL that
    # leaves create but takes write (change an existing file), delete and share away
    O groupfolders:group "$id" chp-users read write
    O groupfolders:permissions "$id" --enable
    O groupfolders:permissions "$id" --group chp-users -- / +read +create -write -delete -share
    echo "Approvals = team folder $id (chp-users: read + create; no write, delete or share)" ;;
  stick) X 'sudo install -d -m 0700 /root/spike/stick && echo "stick stand-in: /root/spike/stick"' ;;
  sh) X "sudo bash -c $(printf '%q' "$2")" ;;
  *) echo "usage: $0 l1|l2|stick|sh CMD"; exit 2 ;;
esac
