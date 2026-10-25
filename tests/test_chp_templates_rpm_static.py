"""chp-templates RPM (Plan C3 Task 1): built only from the SIGNED templates-1.2.0 release, sha256-pinned."""
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-templates"
SHA = "ca40b7ff4cfa95040f3dc5155fc8c238d71e3f1feade89380e5072381c75b389"


def test_spec_installs_only_the_shipped_library():
    s = (D / "chp-templates.spec").read_text()
    assert "Version:        1.2.0" in s and "BuildArch:      noarch" in s and "Requires:       python3" in s
    for p in ("rev2", "chpfill.pyz", "vocabulary.md", "site-conf-mapping.csv", "README.md"):
        assert f"%{{_datadir}}/chp-templates/{p}" in s, p
    assert "/tests" not in s and "/tools" not in s and "/render" not in s        # no raw .py: aero's fapolicyd (ruling)


def test_build_verifies_the_signed_release_before_use():
    b = (D / "build-rpm.sh").read_text()
    assert SHA in b and "${CHP_TEMPLATES_RELEASE:?" in b
    v, c, cp = b.index("gpg --verify"), b.index("shasum -a 256 -c"), b.index("scp ")
    assert v < cp and c < cp                                  # verified BEFORE anything is copied to aero


def test_package_is_in_the_repo_list():
    t = (Path(__file__).resolve().parents[1] / "appliance/release/PACKAGES.txt").read_text()
    assert "\nchp-templates ours" in t


def test_renderer_is_a_zipapp_built_from_the_verified_tarball():
    b = (D / "build-rpm.sh").read_text()
    assert "zipapp" in b and "sys.exit(chpfill.main())" in b
    assert b.index("shasum -a 256 -c") < b.index("zipapp")       # built only after verification
