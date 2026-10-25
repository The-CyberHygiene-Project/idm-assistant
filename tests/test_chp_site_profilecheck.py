"""chp-site validate checks profile.ini against the chp-templates vocabulary (Plan C3 Task 3)."""
from pathlib import Path

import pytest
from chp_site.profilecheck import check
from chp_site.sitefile import SiteError

STUB = '''
class FillError(Exception):
    pass
def load_vocabulary(p):
    return {"organization.legal_name": {}}
def load_values(profile, site_conf, defaults, mapping):
    import configparser
    cp = configparser.ConfigParser(); cp.read(profile)
    return {f"{s}.{k}": v for s in cp.sections() for k, v in cp.items(s)}, {}, {}
def check_values(values, facts, vocab, public):
    for k in values:
        if k not in vocab:
            raise FillError(f"{k} is not in vocabulary.md (add it there first)")
'''


def stub_templates(tmp_path):
    t = tmp_path / "tpl"
    (t / "render").mkdir(parents=True)
    (t / "render" / "chpfill.py").write_text(STUB)
    (t / "vocabulary.md").write_text("")
    (t / "site-conf-mapping.csv").write_text("site_conf_key,placeholder,visibility\n")
    return t


def site(tmp_path, profile=None):
    d = tmp_path / "stick"
    d.mkdir()
    (d / "site.conf").write_text("DOMAIN=example.test\n")
    if profile is not None:
        (d / "profile.ini").write_text(profile)
    return d


def test_no_profile_means_nothing_to_say(tmp_path):
    assert check(site(tmp_path), stub_templates(tmp_path)) == ""


def test_good_profile_is_ok(tmp_path):
    out = check(site(tmp_path, "[organization]\nlegal_name = Example Manufacturing LLC\n"), stub_templates(tmp_path))
    assert out.startswith("profile.ini OK")


def test_bad_key_is_a_site_error_with_the_renderer_message(tmp_path):
    with pytest.raises(SiteError, match="organisation.name is not in vocabulary.md"):
        check(site(tmp_path, "[organisation]\nname = x\n"), stub_templates(tmp_path))


def test_renderer_not_found_is_a_note_not_a_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("CHP_TEMPLATES", raising=False)
    out = check(site(tmp_path, "[organization]\nlegal_name = x\n"), None, search=[tmp_path / "nowhere"])
    assert out == "profile.ini not checked: chp-templates not found (set CHP_TEMPLATES)"


def test_env_var_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv("CHP_TEMPLATES", str(stub_templates(tmp_path)))
    assert check(site(tmp_path, "[organization]\nlegal_name = x\n"), None).startswith("profile.ini OK")


@pytest.mark.skipif(not (Path.home() / "chp-templates" / "render" / "chpfill.py").exists(), reason="no chp-templates checkout")
def test_with_the_real_chp_templates(tmp_path):
    real = Path.home() / "chp-templates"
    assert check(site(tmp_path, "[system.srv1]\nin_boundary = yes\n"), real).startswith("profile.ini OK")
    other = tmp_path / "b"
    other.mkdir()
    with pytest.raises(SiteError, match="named like a secret"):
        check(site(other, "[organization]\nadmin_password = x\n"), real)


def test_the_installed_zipapp_form_is_loaded(tmp_path):
    import zipapp
    t = stub_templates(tmp_path)
    src = tmp_path / "z"
    src.mkdir()
    (src / "chpfill.py").write_text(STUB)
    (src / "__main__.py").write_text("")
    zipapp.create_archive(src, t / "chpfill.pyz")
    (t / "render" / "chpfill.py").unlink()
    assert check(site(tmp_path, "[organization]\nlegal_name = x\n"), t).startswith("profile.ini OK")
