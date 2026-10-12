#!/usr/bin/env bash
# prove-kit.sh (RUNS ON THE MAC): proof of the site-stick kit (appliance/site-stick-kit) for the RELEASED 0.1.0.
# A stick made ONLY from the kit's templates (filled the way the guide says) and checked with the RELEASED chp-site.pyz
# installs a fresh server from the RELEASED ISO bytes; then the guide's export step works as written (chpadmin + su -).
# Uses the iso5 lab helpers already on aero (/tmp/iso2: stick.sh, install-iso.sh, unlock.sh, rootrun.exp).
# Lab names: iso5-kit (server, .59) and iso5-kitc (client, .58, listed only, not installed). Domain kit.lab.test.
#   all       fill + validate + make stick + install + unlock + wait first boot + export + client validate
#   cleanup   remove the iso5-kit VM, its disk and the kit stick image on aero; shred the Mac render dir
# Every check prints PASS/FAIL; exits 1 on any FAIL. Secrets move over pipes only (stick image -> expect), never printed.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; top="$(cd "$here/../.." && pwd)"; kit="$top/appliance/site-stick-kit"
S=~/idm-lab-secrets; R=$S/kit-render; KEY=$S/iso2_chpadmin; PYZ=${KIT_PYZ:?set KIT_PYZ to the RELEASED chp-site.pyz}
STICK=/data/libvirt/images/kit-stick.img; VM=iso5-kit; IP=192.168.100.59; MAC=52:54:00:c4:05:59; CMAC=52:54:00:c4:05:58
ISO=/var/lib/libvirt/images/chp-iso/0.1.0-rc5/cyberhygiene-lab-installer-el9.iso
WANT_SHA=efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2   # released 0.1.0 (For Jeff SHA256SUMS)
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: ${2:-}"; fails=1; }
check() { if [[ $2 == "$3" ]]; then pass "$1"; else fail "$1" "got '$2', want '$3'"; fi; }
A() { ssh -o BatchMode=yes aero "$@" 2>/dev/null; }
Vh() { ssh -o BatchMode=yes -J aero -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "chpadmin@$IP" "$@" 2>/dev/null; }
# Root the way the guide says: chpadmin by key, then `su -` with ROOT_CONSOLE_PASSWORD from the stick's escrow.
Rv() { local b; b=$(printf '%s' "$1" | base64 | tr -d '\n')
  A "sudo bash /tmp/iso2/stick.sh escrow $STICK $VM.txt | sed -n 's/^ROOT_CONSOLE_PASSWORD=//p' | expect /tmp/iso2/rootrun.exp $IP /tmp/iso2/iso2_chpadmin $b" \
    | tr -d '\r' | sed '/^RC=/d' | sed '/^[[:space:]]*$/d'; }
# Fill a template the way a person does: set KEY=value on the template's own empty line (no other edits).
setkv() { python3 - "$1" "$2" "$3" <<'EOF'
import sys; p, k, v = sys.argv[1:]
lines = open(p).read().split("\n"); hit = [i for i, l in enumerate(lines) if l.split("=", 1)[0] == k]
assert len(hit) == 1, f"{k}: {len(hit)} lines"; lines[hit[0]] = f"{k}={v}"; open(p, "w").write("\n".join(lines))
EOF
}

case ${1:-} in
  all)
    rm -rf "$R"; mkdir -p "$R/stick"; chmod 700 "$R"
    cp "$kit/site.conf.template" "$R/stick/site.conf"; cp "$kit/hosts.template" "$R/stick/hosts"
    out=$(python3 "$PYZ" validate --site "$R/stick" 2>&1)
    [[ $out == *"DOMAIN is required"* ]] && pass "unfilled template is refused (DOMAIN is required)" || fail "unfilled template" "$out"
    f=$R/stick/site.conf
    setkv "$f" DOMAIN kit.lab.test; setkv "$f" SUBNET 192.168.100.0/24; setkv "$f" GATEWAY 192.168.100.1
    setkv "$f" NTP_UPSTREAM 192.168.100.1; setkv "$f" TIMEZONE America/Chicago; setkv "$f" ISSO_NAME "J. Shannon"
    setkv "$f" ADMIN_SSH_PUBKEY "$(ssh-keygen -y -f "$KEY")"
    printf '%s  iso5-kit   192.168.100.59  server\n%s  iso5-kitc  192.168.100.58  client\n' "$MAC" "$CMAC" >> "$R/stick/hosts"
    check "filled kit validates with the RELEASED chp-site" "$(python3 "$PYZ" validate --site "$R/stick" 2>&1)" "OK: kit.lab.test, 2 hosts, server iso5-kit"
    out=$(python3 "$PYZ" validate --site "$R/stick" --mac "$MAC" --role server 2>&1); rc=$?
    [[ $rc == 0 && $out == OK:* ]] && pass "--mac/--role server check as in the guide ($out)" || fail "--mac server" "$out"
    check "ISO on aero = released 0.1.0 bytes" "$(A "sha256sum $ISO | cut -d' ' -f1")" "$WANT_SHA"
    A "rm -rf /tmp/kit-stick && mkdir -p /tmp/kit-stick"; scp -q "$R/stick/site.conf" "$R/stick/hosts" aero:/tmp/kit-stick/
    out=$(A "sudo bash /tmp/iso2/stick.sh make /tmp/kit-stick $STICK && rm -rf /tmp/kit-stick")
    [[ $out == *"made $STICK"* ]] && pass "kit stick made (FAT, OEMDRV, the two files only)" || { fail "make stick" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/install-iso.sh $VM $MAC 2 $STICK 1 $ISO")
    [[ $out == *"BOOTED: inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/server.ks"* && $out == *"INSTALLED and started $VM"* ]] \
      && pass "$VM installed from the released ISO with the kit stick" || { fail "$VM install" "$out"; exit 1; }
    out=$(A "sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./escrow/$VM.txt"* && $out == *"INSTALL COMPLETED"* ]] && pass "escrow/$VM.txt written with INSTALL COMPLETED" || fail "escrow" "$out"
    out=$(A "sudo bash /tmp/iso2/unlock.sh $VM $STICK $VM")
    [[ $out == *"passphrase sent"* || $out == *"already unlocked"* ]] && pass "first boot unlocked with LUKS_PASSPHRASE from escrow" || fail "unlock" "$out"
    for _ in $(seq 60); do Vh true && break; sleep 10; done
    st=""; for _ in $(seq 80); do
      st=$(Vh 'systemctl status chp-server-firstboot --no-pager' | sed -n 's/^ *Active: \([a-z]*\).*/\1/p' | head -1)
      [[ $st == active || $st == failed ]] && break; sleep 15; done   # inactive = not started yet; activating = running
    full=$(Vh 'systemctl status chp-server-firstboot --no-pager' | grep -E "Active:|status=" | tr -s ' ' | tr '\n' ' ')
    [[ $st == active && $full == *"active (exited)"* && $full == *"status=0/SUCCESS"* ]] && pass "guide's finish check (chpadmin, no root): $full" || fail "first boot" "$full"
    check "first boot marker" "$(Rv 'test -e /var/lib/chp/firstboot/server.done && echo yes')" "yes"
    A "sudo virsh attach-disk $VM $STICK sdz --targetbus usb --type disk --live >/dev/null"; sleep 5
    out=$(Rv 'chp-site export-client')
    echo "$out" | grep -i -E "fingerprint|sha256|moved|token" | sed 's/^/  export: /'
    [[ $out == *"moved to the stick: kanidm-admins.json, root_ca_key, step-ca-password"* ]] && pass "export-client (chpadmin + su -) moved the server secrets" || fail "export secrets" "$out"
    [[ $out == *"tokens moved to the stick: iso5-kitc"* ]] && pass "export-client moved the listed client's token" || fail "export token" "$out"
    A "sudo virsh detach-disk $VM sdz --live >/dev/null"; sleep 3
    out=$(A "sudo bash /tmp/iso2/stick.sh list $STICK")
    [[ $out == *"./client.conf"* && $out == *"./tokens/iso5-kitc.token"* && $out == *"./escrow/$VM-server.txt"* ]] \
      && pass "stick now holds client.conf, the client token, escrow/$VM-server.txt" || fail "stick contents" "$out"
    check "server monitor quiet after export" "$(Rv '/usr/libexec/chp/monitor >/dev/null; echo $?')" "0"
    # The guide's client check, on the Mac, with the stick's NON-secret files only (client.conf has no secrets).
    A "sudo bash /tmp/iso2/stick.sh escrow $STICK ../client.conf" > "$R/stick/client.conf"
    out=$(python3 "$PYZ" validate --site "$R/stick" --mac "$CMAC" --role client 2>&1); rc=$?
    [[ $rc == 0 && $out == OK:* ]] && pass "guide's client check passes after export ($out)" || fail "client validate" "$out"
    exit $fails ;;
  cleanup)
    A "sudo virsh destroy $VM >/dev/null 2>&1; sudo virsh undefine $VM --nvram --snapshots-metadata >/dev/null 2>&1; sudo rm -f /data/libvirt/images/$VM-[0-9].qcow2 $STICK"
    check "iso5-kit gone" "$(A "sudo virsh dominfo $VM >/dev/null 2>&1 && echo present || echo gone")" "gone"
    rm -rf "$R"; echo "cleaned"; exit $fails ;;
  *) echo "usage: prove-kit.sh all|cleanup"; exit 2 ;;
esac
