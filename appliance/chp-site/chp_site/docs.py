# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""docs: render the site's SSP and POA&M from the site stick's profile.ini with the installed chp-templates renderer
(spec 2026-10-24 §5.2). The renderer runs as a subprocess (an RPM-installed zipapp, trusted by fapolicyd); chp-site
never imports it. Output goes to a new root-only folder that is never overwritten."""
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .sitefile import SiteError


def _stamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _new_dir(out_root):
    out_root.mkdir(parents=True, exist_ok=True)
    out_root.chmod(0o700)
    base = out_root / _stamp()
    out, n = base, 1
    while out.exists():
        n += 1
        out = out_root / f"{base.name}-{n}"
    return out


def render(stick_dir, site_conf, templates, out_root, rev="rev2"):
    """Render into a new folder under out_root. Returns (folder, profile used?, renderer's summary line)."""
    templates, out_root = Path(templates), Path(out_root)
    renderer = templates / "chpfill.pyz"
    if not renderer.exists():
        raise SiteError(f"chp-templates is not installed ({renderer} missing): install chp-templates with "
                        "dnf --enablerepo=chp install chp-templates")
    lib = templates / rev
    if not (lib / "MANIFEST.json").exists():
        raise SiteError(f"{rev} is not in this chp-templates release")
    version = json.loads((lib / "MANIFEST.json").read_text())["content_version"]
    profile = Path(stick_dir) / "profile.ini" if stick_dir else None
    if profile is not None and not profile.exists():
        profile = None
    out = _new_dir(out_root)
    argv = [sys.executable or "python3", str(renderer), "fill", "--lib", str(lib), "--site-conf", str(site_conf),
            "--out", str(out), "--templates-version", version]
    if profile:
        argv += ["--profile", str(profile)]
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode != 0:
        shutil.rmtree(out, ignore_errors=True)
        raise SiteError((r.stderr or r.stdout).strip() or f"the renderer failed (exit {r.returncode})")
    out.chmod(0o700)
    for f in out.iterdir():
        f.chmod(0o600)
    return out, profile is not None, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
