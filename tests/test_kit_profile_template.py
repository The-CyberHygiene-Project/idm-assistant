"""Kit: profile.ini.template (Automated_Compliance's form) and the guide section (Plan C3 Task 4)."""
import configparser
import importlib.util
import re
from pathlib import Path

import pytest

KIT = Path(__file__).resolve().parents[1] / "appliance" / "site-stick-kit"
TPL = KIT / "profile.ini.template"
REAL = Path.home() / "chp-templates" / "render" / "chpfill.py"


def keys():
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(TPL.read_text())
    return {f"{s}.{k}": v for s in cp.sections() for k, v in cp.items(s)}


@pytest.mark.skipif(not REAL.exists(), reason="no chp-templates checkout")
def test_every_template_key_is_in_the_vocabulary():
    spec = importlib.util.spec_from_file_location("cf", REAL)
    cf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cf)
    vocab = cf.load_vocabulary(REAL.parents[1] / "vocabulary.md")
    assert [k for k in keys() if cf.vocab_entry(k, vocab) is None] == []


def test_examples_are_fictional():
    text = TPL.read_text()
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert ip.startswith("192.0.2."), ip
    for dom in re.findall(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|gov|test|tech)\b", text):
        assert dom.endswith("example.test") or dom.lower() in {"sam.gov"}, dom
    assert re.search(r"(?i)password\s*=", text) is None
    assert "[system." in text and "[contract." in text          # Automated_Compliance's committed form


def test_guide_has_the_ssp_section():
    g = (KIT / "SITE-STICK.md").read_text()
    for s in ("chp-site docs", "/var/lib/chp/docs", "fill-report.md", "profile.ini.template",
              "next to `site.conf`", "never put passwords"):
        assert s.lower() in g.lower(), s
