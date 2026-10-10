#!/usr/bin/env bash
# stick.sh (RUNS ON AERO, sudo): the lab's OEMDRV "USB stick" as a 64 MB FAT image.
#   stick.sh make DIR IMG        new image labelled OEMDRV holding DIR/*
#   stick.sh add IMG FILE...     copy FILEs into an existing image (e.g. client.conf after export-client)
#   stick.sh list IMG            file list; escrow values MASKED (safe for logs)
#   stick.sh escrow IMG NAME     print escrow/NAME raw on stdout (for the proof's expect; never logged)
#   stick.sh has IMG PATH        exit 0 if PATH exists on the stick
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
cmd=$1; img=$2; shift 2
m=$(mktemp -d); trap 'mountpoint -q "$m" && umount "$m"; rmdir "$m"' EXIT
case $cmd in
  make)
    dir=$img; img=$1
    rm -f "$img"; truncate -s 64M "$img"; mkfs.vfat -n OEMDRV "$img" >/dev/null
    mount -o loop "$img" "$m"; cp -r "$dir"/. "$m"/; sync
    echo "made $img from $dir: $(ls "$m" | tr '\n' ' ')" ;;
  add)
    mount -o loop "$img" "$m"; cp "$@" "$m"/; sync; echo "added: $*" ;;
  list)
    mount -o loop,ro "$img" "$m"
    (cd "$m" && find . -type f | sort)
    for f in "$m"/escrow/*; do [[ -f $f ]] || continue
      echo "--- ${f#"$m"/} (masked)"; sed -E 's/^(LUKS_PASSPHRASE|ROOT_CONSOLE_PASSWORD|GRUB_PASSWORD)=(.*)$/\1=<\2>/; s/<([^>]*)>/<\1>/' "$f" \
        | awk -F= '/^(LUKS_PASSPHRASE|ROOT_CONSOLE_PASSWORD|GRUB_PASSWORD)=/{v=$2; gsub(/[<>]/,"",v); print $1"=<"length(v)" chars>"; next} {print}'
    done ;;
  escrow)
    mount -o loop,ro "$img" "$m"; cat "$m/escrow/$1" ;;
  has)
    mount -o loop,ro "$img" "$m"; [[ -e "$m/$1" ]] ;;
  *) echo "usage: stick.sh make|add|list|escrow|has ..."; exit 2 ;;
esac
