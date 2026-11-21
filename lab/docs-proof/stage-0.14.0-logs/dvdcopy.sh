#!/bin/bash
# 13b (repeat of 11b): copy the 9 Rocky 9.8 DVD packages of repo 0.14.0 (unchanged from 0.13.0) into the third-party dir; rpm -K with the Rocky key alone
# (private rpm db), cmp against the DVD file. Runs on aero.
set -Eeuo pipefail
DVD=/data/lab-inputs/dvd/AppStream/Packages; T=/data/lab-inputs/rpms
db=$(mktemp -d); trap 'rm -rf "$db"' EXIT
chcon -t rpm_var_lib_t "$db" 2>/dev/null || true
rpm --dbpath "$db" --initdb; rpm --dbpath "$db" --import /data/lab-inputs/dvd/RPM-GPG-KEY-Rocky-9
for f in b/boost-filesystem-1.75.0-13.el9_7.x86_64.rpm b/boost-system-1.75.0-13.el9_7.x86_64.rpm \
         l/libXScrnSaver-1.2.3-10.el9.x86_64.rpm l/liberation-narrow-fonts-1.07.6-9.el9.noarch.rpm \
         x/xcb-util-image-0.4.0-19.el9.0.1.x86_64.rpm x/xcb-util-keysyms-0.4.0-17.el9.x86_64.rpm \
         x/xcb-util-renderutil-0.3.9-20.el9.0.1.x86_64.rpm x/xcb-util-wm-0.4.1-22.el9.x86_64.rpm \
         p/poppler-utils-21.01.0-24.el9.x86_64.rpm; do
  b=$(basename "$f")
  [[ -e $T/$b ]] || sudo -n install -m 0644 -o root -g root "$DVD/$f" "$T/$b"
  k=$(rpm --dbpath "$db" -K "$T/$b" 2>&1)
  grep -q 'digests signatures OK' <<<"$k" || { echo "BAD rpm -K: $k"; exit 1; }
  cmp "$DVD/$f" "$T/$b" || { echo "BAD cmp: $b"; exit 1; }
  echo "OK  $(rpm --dbpath "$db" -qp --qf '%{SIGPGP:pgpsig}' "$T/$b" | sed 's/.*Key ID //')  cmp=same  $(sha256sum "$T/$b" | cut -c1-64)  $b"
done
