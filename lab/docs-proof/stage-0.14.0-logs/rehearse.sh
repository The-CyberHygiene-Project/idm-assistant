#!/bin/bash
# Task 13b (RUNS ON AERO): rehearse sign-repo.sh on the REAL 0.14.0 stage with a THROWAWAY software key (temp GNUPGHOME,
# its own agent; no YubiKey, no project key). The keys dir is a copy of the tools' pinned keys with the throwaway key in
# the 'cyberhygiene' slot. Proves the classification (ours / pinned vendor re-sign / pinned third-party kept), the
# repodata + modules record and verify-repo on the full set. Output is thrown away.
set -u
W=/data/chp-release/tmp-c014/rehearsal; T=/data/chp-release/tools
rm -rf "$W"; mkdir -p "$W/keys"
export GNUPGHOME=$W/gnupg; mkdir -m 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'throwaway rehearsal <none@invalid>' rsa3072 sign 1d >/dev/null 2>&1
F=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr/{print $10; exit}')
echo "throwaway key: $F"
gpg --batch --armor --export "$F" > "$W/keys/RPM-GPG-KEY-cyberhygiene"
cp "$T"/RPM-GPG-KEY-EPEL-9 "$T"/RPM-GPG-KEY-Rocky-9 "$T"/RPM-GPG-KEY-WAZUH "$W/keys/"
sed "s/^2DE0D71BF37D8F5E4201A590521276F43C908F8E /$F /" "$T/trusted-keys.txt" > "$W/keys/trusted-keys.txt"
bash "$T/sign-repo.sh" /data/chp-release/0.14.0/stage "$W/out" "$F" "$W/keys" 2>&1 | grep -v -E '^/data/.*\.rpm:$' | tail -15
echo "rc=${PIPESTATUS[0]}"
[[ -d $W/out ]] && { echo "rpms: $(ls "$W"/out/*.rpm | wc -l)"; bash "$T/verify-repo.sh" "$W/out" "$W/keys"; echo "verify rc=$?";
  db=$(mktemp -d); chcon -t rpm_var_lib_t "$db" 2>/dev/null; rpm --dbpath "$db" --initdb; rpm --dbpath "$db" --import "$W/keys/RPM-GPG-KEY-cyberhygiene"
  echo "onlyoffice: $(rpm --dbpath "$db" -Kv "$W"/out/onlyoffice-*.rpm | grep -o 'Signature, key ID [0-9a-f]*: OK' | sort -u | tr '\n' ' ') header $(rpm -qp --nosignature --qf '%{SHA256HEADER}' "$W"/out/onlyoffice-*.rpm 2>/dev/null)"
  echo "boost-system (Rocky, kept): $(rpm -qp --qf '%{RSAHEADER:pgpsig}' "$W"/out/boost-system-*.rpm 2>/dev/null)"
  rm -rf "$db"; }
gpgconf --kill all; rm -rf "$W"
ls /data/chp-release/0.14.0/
