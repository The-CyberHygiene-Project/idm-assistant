# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""profilecheck: `chp-site validate` checks a profile.ini on the site stick with the chp-templates renderer's own rules
(known names only, no secrets), when chp-templates can be found. The renderer is loaded by path, never bundled."""
import importlib
import importlib.util
import os
import sys
from pathlib import Path

from .sitefile import SiteError

DEFAULT_SEARCH = [Path("/usr/share/chp-templates")]
NOT_FOUND = "profile.ini not checked: chp-templates not found (set CHP_TEMPLATES)"


def _find(templates, site_dir, search):
    candidates = [Path(templates)] if templates else []
    if os.environ.get("CHP_TEMPLATES"):
        candidates.append(Path(os.environ["CHP_TEMPLATES"]))
    candidates += list(search) + [Path(site_dir).parent / "chp-templates"]
    for c in candidates:
        if (c / "chpfill.pyz").exists() or (c / "render" / "chpfill.py").exists():
            return c
    return None


def _load(t):
    if (t / "chpfill.pyz").exists():                    # the installed zipapp (works on Python 3.9 and later)
        sys.modules.pop("chpfill", None)
        sys.path.insert(0, str(t / "chpfill.pyz"))
        try:
            return importlib.import_module("chpfill")
        finally:
            sys.path.remove(str(t / "chpfill.pyz"))
    spec = importlib.util.spec_from_file_location("chp_templates_chpfill", t / "render" / "chpfill.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def check(site_dir, templates, search=DEFAULT_SEARCH):
    """'' when there is no profile.ini; a one-line result otherwise; SiteError when the profile breaks a rule."""
    site_dir = Path(site_dir)
    profile = site_dir / "profile.ini"
    if not profile.exists():
        return ""
    t = _find(templates, site_dir, search)
    if t is None:
        return NOT_FOUND
    fill = _load(t)
    conf = site_dir / "site.conf"
    try:
        values, facts, _ = fill.load_values(profile, conf if conf.exists() else None, None, t / "site-conf-mapping.csv")
        fill.check_values(values, facts, fill.load_vocabulary(t / "vocabulary.md"), public=False)
    except fill.FillError as e:
        raise SiteError(f"profile.ini: {e}") from None
    return f"profile.ini OK ({len(values)} values, {len(facts)} facts; checked with {t})"
