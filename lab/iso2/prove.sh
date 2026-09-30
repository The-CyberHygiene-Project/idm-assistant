#!/usr/bin/env bash
# prove.sh STAGE (RUNS ON THE MAC): ISO Plan 2 install proof on aero, one stage at a time. Every check prints
# "PASS <what>" or "FAIL <what>: <observed>"; the script exits 1 if any check in the stage failed.
#   prep       render the site (admin key in), validate it (+ ed25519 negative), push kickstarts/pyz/helpers, make the stick
#   neg1       an unknown MAC stops in %pre: no disk written, no escrow
#   server     install iso2-srv, unlock with the escrowed passphrase, check the host
#   export     export-client from srv1's PUBLIC CA files into the stick (client.conf)
#   neg2       a two-disk client with no disk named stops in %pre: both disks empty, no escrow
#   client     install iso2-cli, unlock, check the host (+ client.conf)
#   reinstall  install iso2-srv again on the same stick: previous escrow kept as *.old, new one differs
#   cleanup    remove every iso2-* VM, the stick, the helpers and the lab key copy on aero; shred the Mac render dir
# Secrets (escrow values) are only ever handled ON AERO, piped between helpers; nothing here prints or logs them.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"
R=~/idm-lab-secrets/iso2-render; KEY=~/idm-lab-secrets/iso2_chpadmin; STICK=/data/libvirt/images/iso2-stick.img
PYZ="$top/appliance/chp-site/dist/chp-site.pyz"; fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: ${2:-}"; fails=1; }
check() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1" "got '$2', want '$3'"; fi; }
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
V() { ssh -o BatchMode=yes -J aero -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 "chpadmin@$1" "${@:2}" 2>/dev/null; }

host_checks() {  # NAME IP FQDN ROLE
  local n=$1 ip=$2 fqdn=$3 role=$4 out
  for _ in $(seq 60); do if V "$ip" true; then break; fi; sleep 10; done
  check "$n: chpadmin logs in with the site key (key only)" "$(V "$ip" 'id -un')" "chpadmin"
  check "$n: FQDN" "$(V "$ip" 'hostname -f')" "$fqdn"
  check "$n: static IP on the matched NIC" "$(V "$ip" "ip -4 -o addr | grep -c ' $ip/'")" "1"
  check "$n: FIPS" "$(V "$ip" 'fips-mode-setup --check | grep -c "is enabled"')" "1"
  check "$n: SELinux" "$(V "$ip" getenforce)" "Enforcing"
  check "$n: root is LUKS2" "$(V "$ip" "lsblk -o FSTYPE -n | grep -c crypto_LUKS")" "1"
  check "$n: /etc/chp site files 0644" "$(V "$ip" 'stat -c %a /etc/chp/site.conf /etc/chp/hosts | sort -u')" "644"
  check "$n: no escrow on the host" "$(V "$ip" 'ls /etc/chp; find / -xdev -name escrow 2>/dev/null' | grep -c escrow)" "0"
  if [[ $role == client ]]; then
    check "$n: client.conf equals the stick's" "$(V "$ip" 'cat /etc/chp/client.conf' | shasum -a 256 | cut -c1-16)" "$(shasum -a 256 < "$R/client.conf" | cut -c1-16)"
  else
    check "$n: no client.conf on the server" "$(V "$ip" 'test -e /etc/chp/client.conf && echo yes || echo no')" "no"
  fi
  check "$n: chp-site from our signed RPM" "$(V "$ip" "rpm -q --qf '%{RSAHEADER:pgpsig}' chp-site" | grep -c 521276f43c908f8e)" "1"
  check "$n: chp-site runs under the host's python3 (fapolicyd enforcing)" "$(V "$ip" 'chp-site --version')" "chp-site 0.1.0"
  out=$(V "$ip" 'chp-site validate --site /etc/chp'); [[ $out == OK:* ]] && pass "$n: chp-site validate /etc/chp" || fail "$n: chp-site validate /etc/chp" "$out"
  out=$(A "sudo bash /tmp/iso2/stick.sh escrow $STICK ${n}.txt | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p' | expect /tmp/iso2/rootcheck.exp $ip /tmp/iso2/iso2_chpadmin")
  check "$n: su - with the escrowed root console password" "$(grep -o 'UID=[0-9]*' <<<"$out")" "UID=0"
  check "$n: no LUKS passphrase in /root or anaconda logs (row 16)" "$(grep -o 'PASSGREP=[0-9]*' <<<"$out")" "PASSGREP=0"
  check "$n: root has a SHA-512 hash" "$(grep -o 'SHADOW=[^ ]*' <<<"$out")" 'SHADOW=$6$'
  check "$n: CUI profile applied at install" "$(grep -o 'OSCAP=[a-z]*' <<<"$out")" "OSCAP=yes"
}

install_ok() {  # NAME MAC ROLE HOST
  local out; out=$(A "sudo bash /tmp/iso2/install.sh $1 $2 $3 $STICK 1")
  [[ $out == *"INSTALLED and started $1"* ]] && pass "$1: install finished, stick detached" || { fail "$1: install" "$out"; return 1; }
  out=$(A "sudo bash /tmp/iso2/unlock.sh $1 $STICK $4")
  [[ $out == *"passphrase sent"* ]] && pass "$1: escrowed LUKS passphrase unlocked the disk" || fail "$1: LUKS unlock" "$out"
}

stop_ok() {  # NAME MAC ROLE NDISKS WANT_MESSAGE HOST
  local out; out=$(A "sudo bash /tmp/iso2/install.sh $1 $2 $3 $STICK $4 --expect-stop")
  [[ $out == *STOPPED:*"$5"* ]] && pass "$1: stopped in %pre ($5)" || fail "$1: stop in %pre" "$out"
  [[ $(grep -c 'zero-check-failures=0' <<<"$out") == "$4" ]] \
    && pass "$1: every disk untouched (first and last MiB zero: no partition table)" || fail "$1: disks untouched" "$out"
  A "sudo bash /tmp/iso2/stick.sh has $STICK escrow/$6.txt" && fail "$1: no escrow written" "escrow/$6.txt exists" || pass "$1: no escrow written"
}

case ${1:-} in
  prep)
    bash "$top/appliance/chp-site/build.sh" >/dev/null
    rm -rf "$R"; (umask 077; mkdir -p "$R")
    sed "s|@ADMIN_PUBKEY@|$(cut -d' ' -f1,2 "$KEY.pub")|" "$here/site.conf.in" > "$R/site.conf"; cp "$here/hosts" "$R/hosts"
    out=$(python3 "$PYZ" validate --site "$R"); [[ $out == OK:* ]] && pass "chp-site validate (Mac)" || fail "validate" "$out"
    T=$(mktemp -d); cp "$R/hosts" "$T/"; sed 's|^ADMIN_SSH_PUBKEY=.*|ADMIN_SSH_PUBKEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGd1c3Nlc3Rlc3RnZXN0ZXN0Z2VzdGVzdGdlc3RlczE=|' "$R/site.conf" > "$T/site.conf"
    out=$(python3 "$PYZ" validate --site "$T" 2>&1); rm -rf "$T"
    [[ $out == *ed25519*FIPS* ]] && pass "ed25519 admin key refused before install (FIPS)" || fail "ed25519 refused" "$out"
    A 'rm -rf /tmp/iso2 && mkdir -p -m 700 /tmp/iso2'
    # Lab kickstarts = the committed ones + a FIRST %pre that writes the zipapp to /tmp/chp-site.pyz (files injected into the
    # initrd vanish at switch_root; on the ISO it sits at /run/install/repo/chp/). The committed .ks files are unchanged.
    for r in server client; do
      { echo "%pre --interpreter=/usr/bin/bash --erroronfail --log=/tmp/chp-lab-pre.log"
        echo 'echo "CHP-LAB: writing /tmp/chp-site.pyz" > /dev/console'
        # the installer image has no `base64` command (rc 127): decode with its python3
        echo "python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' > /tmp/chp-site.pyz 2>/dev/console <<'CHP_PYZ_B64'"
        base64 < "$PYZ" | fold -w 76; echo "CHP_PYZ_B64"
        echo 'echo "CHP-LAB: decode rc=$? size=$(stat -c %s /tmp/chp-site.pyz 2>&1)" > /dev/console'
        echo "%end"; echo; cat "$top/appliance/kickstart/$r.ks"; } > "$R/../iso2-$r.ks"
    done
    scp -q "$R/../iso2-server.ks" aero:/tmp/iso2/server.ks; scp -q "$R/../iso2-client.ks" aero:/tmp/iso2/client.ks
    rm -f "$R/../iso2-server.ks" "$R/../iso2-client.ks"
    scp -q "$PYZ" "$here/stick.sh" "$here/install.sh" \
      "$here/unlock.sh" "$here/rootcheck.exp" "$top/lab/host/luks-console-unlock.exp" "$KEY" aero:/tmp/iso2/
    scp -q -r "$R" aero:/tmp/iso2/site
    out=$(A "sudo bash /tmp/iso2/stick.sh make /tmp/iso2/site $STICK && sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./site.conf"* && $out == *"./hosts"* ]] && pass "stick image made (OEMDRV: site.conf, hosts)" || fail "stick" "$out" ;;
  neg1) stop_ok iso2-neg1 52:54:00:c4:02:3f client 1 "not in the hosts table" iso2-neg1 ;;
  server) install_ok iso2-srv 52:54:00:c4:02:30 server iso2-srv && host_checks iso2-srv 192.168.100.30 iso2-srv.iso2.lab.test server ;;
  export)
    T=$(mktemp -d)
    ssh srv1 'cat /etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt' > "$T/root_ca.crt" 2>/dev/null
    ssh srv1 'sudo cat /etc/ssh-ca/user_ca.pub' > "$T/user_ca.pub" 2>/dev/null
    out=$(python3 "$PYZ" export-client --stick "$R" --site "$R/site.conf" --root "$T/root_ca.crt" --ssh-ca "$T/user_ca.pub"); rm -rf "$T"
    [[ $out == *"SSH CA fingerprint: SHA256:"* ]] && pass "export-client wrote client.conf" || fail "export-client" "$out"
    out=$(python3 "$PYZ" validate --site "$R" --role client --mac 52:54:00:c4:02:31); [[ $out == OK:*iso2-cli* ]] && pass "client.conf validates" || fail "client.conf validates" "$out"
    scp -q "$R/client.conf" aero:/tmp/iso2/client.conf
    out=$(A "sudo bash /tmp/iso2/stick.sh add $STICK /tmp/iso2/client.conf && sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./client.conf"* && $out == *"./escrow/iso2-srv.txt"* ]] && pass "stick now holds client.conf (server escrow kept)" || fail "stick add" "$out" ;;
  neg2) stop_ok iso2-neg2 52:54:00:c4:02:39 client 2 "name one in the hosts table" iso2-neg2 ;;
  client) install_ok iso2-cli 52:54:00:c4:02:31 client iso2-cli && host_checks iso2-cli 192.168.100.31 iso2-cli.iso2.lab.test client ;;
  reinstall)
    old=$(A "sudo bash /tmp/iso2/stick.sh escrow $STICK iso2-srv.txt | sed -n 's/^LUKS_PASSPHRASE=//p' | sha256sum | cut -c1-16")
    install_ok iso2-srv 52:54:00:c4:02:30 server iso2-srv
    out=$(A "sudo bash /tmp/iso2/stick.sh list $STICK"); [[ $out == *"escrow/iso2-srv.txt."*".old"* ]] && pass "previous escrow kept as .old" || fail "previous escrow kept" "$out"
    new=$(A "sudo bash /tmp/iso2/stick.sh escrow $STICK iso2-srv.txt | sed -n 's/^LUKS_PASSPHRASE=//p' | sha256sum | cut -c1-16")
    [[ -n $old && -n $new && $old != "$new" ]] && pass "reinstall made a new passphrase (escrow differs)" || fail "new escrow" "old/new hash equal or empty" ;;
  cleanup)
    for v in iso2-srv iso2-cli iso2-neg1 iso2-neg2; do A "sudo virsh destroy $v >/dev/null 2>&1; sudo virsh undefine $v --nvram --remove-all-storage >/dev/null 2>&1"; done
    A "sudo rm -f $STICK; sudo shred -u /tmp/iso2/iso2_chpadmin 2>/dev/null; sudo rm -rf /tmp/iso2"
    rm -P "$R"/* 2>/dev/null; rm -rf "$R"; pass "cleanup (VMs, stick, helpers, lab key copy, render dir)" ;;
  *) echo "usage: prove.sh prep|neg1|server|export|neg2|client|reinstall|cleanup"; exit 2 ;;
esac
exit $fails
