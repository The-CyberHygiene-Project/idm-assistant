# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""USBGuard (CUI) blocks USB storage on installed hosts. export-client authorizes ONLY the site stick, temporarily
(`usbguard allow-device ID` without -p: nothing is written to the policy), and blocks it again afterwards."""
import re
import subprocess
import time
from pathlib import Path

from .sitefile import SiteError

_LINE = re.compile(r"^(\d+): (allow|block|reject) .*?with-interface (\{[^}]*\}|\S+)")
PIN_FILE = "/etc/chp/site-stick.id"          # written at install from the stick's USB identity (not secret)
HASH_FILE = "/etc/chp/site-stick.hash"       # USBGuard's full device hash, pinned on first use (not secret)


def _devices(list_output):
    for line in list_output.splitlines():
        line = line.strip()
        m = _LINE.match(line)
        if not m:
            continue
        idm = re.search(r"\bid ([0-9a-f]{4}:[0-9a-f]{4})", line)
        ser = re.search(r'\bserial "([^"]*)"', line)
        hsh = re.search(r'\bhash "([^"]*)"', line)
        yield {"dev": m.group(1), "status": m.group(2), "storage": bool(re.search(r"(^|[\s{])08:", m.group(3))),
               "id": idm.group(1) if idm else "", "serial": ser.group(1) if ser else "", "hash": hsh.group(1) if hsh else ""}


def pick_pinned(list_output, pin, pinned_hash):
    """(USBGuard id, device hash) of the blocked storage device that IS the site stick; anything else is refused."""
    if not pin:
        raise SiteError("no site-stick pin (/etc/chp/site-stick.id): this host was installed without one")
    blocked = [d for d in _devices(list_output) if d["status"] == "block" and d["storage"]]
    match = [d for d in blocked if d["id"] == pin.get("ID") and d["serial"] == pin.get("SERIAL")]
    if not match:
        raise SiteError("the plugged-in USB storage device is not the site stick this host was installed from "
                        f"(want id {pin.get('ID')} serial {pin.get('SERIAL')!r}); refused")
    if len(match) > 1:
        raise SiteError("more than one device matches the site-stick pin; leave only the site stick plugged in")
    d = match[0]
    if pinned_hash and d["hash"] != pinned_hash:
        raise SiteError("the device looks like the site stick but its USBGuard hash differs from the pinned one; refused")
    return d["dev"], d["hash"]


def blocked_mass_storage(list_output):
    """The USBGuard id of the one BLOCKED device with a mass-storage interface (class 08), None if there is none."""
    ids = []
    for line in list_output.splitlines():
        m = _LINE.match(line.strip())
        if m and m.group(2) == "block" and re.search(r"(^|[\s{])08:", m.group(3)):
            ids.append(m.group(1))
    if len(ids) > 1:
        raise SiteError(f"{len(ids)} blocked USB storage devices are plugged in; leave only the site stick")
    return ids[0] if ids else None


def _read_pin(path):
    try:
        return dict(line.split("=", 1) for line in Path(path).read_text().splitlines() if "=" in line)
    except FileNotFoundError:
        return None


def allow_stick(label_path, wait=20, pin_file=PIN_FILE, hash_file=HASH_FILE):
    """Authorize ONLY the pinned site stick, temporarily; returns its USBGuard id (to block again), or None if a
    stick is already visible (e.g. no USBGuard). The first successful use pins the USBGuard device hash."""
    if Path(label_path).exists():
        return None
    try:
        out = subprocess.run(["usbguard", "list-devices"], capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise SiteError("no site stick found (a USB volume labelled OEMDRV) and USBGuard is not available to authorize one") from None
    if not any(d["status"] == "block" and d["storage"] for d in _devices(out)):
        raise SiteError("no site stick found: plug in the USB stick labelled OEMDRV")
    hp = Path(hash_file)
    dev, dev_hash = pick_pinned(out, _read_pin(pin_file), hp.read_text().strip() if hp.exists() else None)
    if not hp.exists():
        hp.write_text(dev_hash + "\n"); hp.chmod(0o644)                   # first use: pin the full device hash
    subprocess.run(["usbguard", "allow-device", dev], check=True)          # temporary: no -p, the policy is unchanged
    subprocess.run(["logger", "-t", "chp-site", f"USBGuard: temporarily allowed device {dev} (site stick) for export-client"])
    for _ in range(wait * 2):
        if Path(label_path).exists():
            return dev
        time.sleep(0.5)
    block_stick(dev)
    raise SiteError("the allowed USB device has no volume labelled OEMDRV (is it the site stick?); blocked it again")


def block_stick(dev):
    if dev:
        subprocess.run(["usbguard", "block-device", dev])
        subprocess.run(["logger", "-t", "chp-site", f"USBGuard: blocked device {dev} again"])
