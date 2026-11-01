#!/usr/bin/env python3
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Compile signature-base into one rules file for chp-yara-rules (YARA spec §2). Runs on the build host, which has
yarac. Usage: build-rules.py SRC_DIR EXCLUDE_TXT OUT_DIR. Every file left out is listed in OUT_DIR/SKIPPED.txt."""
import re
import subprocess
import sys
from pathlib import Path

EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")
DEFINES = [f"--define={n}=" for n in EXTERNALS]


def load_excludes(text):
    out = {}
    for ln in text.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if ln:
            name, _, why = ln.partition(" ")
            out[name] = why.strip() or "excluded"
    return out


def _yarac(run, srcs, dest):
    return run(["yarac", "-w", *DEFINES, *map(str, srcs), str(dest)], capture_output=True, text=True)


def build(src, excludes, out, run=subprocess.run):
    src, out = Path(src), Path(out)
    kept, skipped = [], []
    for f in sorted(src.glob("*.yar")):
        if f.name in excludes:
            skipped.append((f.name, "false alarm on the appliance: " + excludes[f.name]))
            continue
        r = _yarac(run, [f], out / "probe.yarc")
        if r.returncode != 0:
            why = (r.stderr.strip().splitlines() or ["no message"])[-1]
            skipped.append((f.name, "does not compile with plain YARA: " + why))
            continue
        kept.append(f)
    (out / "probe.yarc").unlink(missing_ok=True)
    while True:
        r = _yarac(run, kept, out / "rules.yarc")
        if r.returncode == 0:
            break
        m = re.search(r"([^\s/]+\.yar)\(\d+\)", r.stderr)
        bad = next((f for f in kept if m and f.name == m.group(1)), None)
        if bad is None:
            raise SystemExit("combined compile failed: " + r.stderr[-500:])
        kept.remove(bad)
        skipped.append((bad.name, "clashes with another rule file: " + r.stderr.strip().splitlines()[-1]))
    (out / "SKIPPED.txt").write_text("".join(f"{n}\t{w}\n" for n, w in sorted(skipped)))
    return len(kept), len(skipped)


if __name__ == "__main__":
    s, e, o = sys.argv[1:4]
    k, n = build(s, load_excludes(Path(e).read_text()), o)
    print(f"compiled {k} rule files, skipped {n} (see SKIPPED.txt)")
