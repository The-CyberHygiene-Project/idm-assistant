#!/usr/bin/env python3
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Merge ET Open into one rules file for chp-suricata-rules (Suricata spec §2). Usage: build-rules.py RULES_DIR
DISABLE_CONF OUT_DIR. Listed SIDs are commented out with the reason; DISABLED.txt lists them; unknown SIDs are reported."""
import re
import shutil
import sys
from pathlib import Path

SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")


def load_disable(text):
    out = {}
    for ln in text.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if ln:
            sid, _, why = ln.partition(" ")
            out[sid] = why.strip() or "disabled"
    return out


def build(src, disable, out):
    src, out = Path(src), Path(out)
    lines, on, off, seen = [], 0, 0, set()
    for f in sorted(src.glob("*.rules")):
        for ln in f.read_text(errors="replace").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue                                   # upstream-commented rules stay out
            m = SID.search(s)
            sid = m.group(1) if m else None
            if sid in disable:
                lines.append(f"# chp-disabled: {disable[sid]}\n# {s}"); off += 1; seen.add(sid)
            else:
                lines.append(s); on += 1
    (out / "chp-suricata.rules").write_text("\n" + "\n".join(lines) + "\n")
    (out / "DISABLED.txt").write_text("".join(f"{s}\t{disable[s]}\n" for s in sorted(seen, key=int)))
    for name in ("classification.config", "reference.config"):
        if (src / name).exists():
            shutil.copy(src / name, out / name)
    return on, off, sorted(set(disable) - seen, key=int)


if __name__ == "__main__":
    s, d, o = sys.argv[1:4]
    on, off, unknown = build(s, load_disable(Path(d).read_text()), o)
    print(f"enabled {on} rules, disabled {off}" + (f"; NOT FOUND upstream: {', '.join(unknown)}" if unknown else ""))
