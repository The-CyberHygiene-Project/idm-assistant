"""chp-templates RPM (Plan C3 Task 1): built only from the SIGNED templates release (1.4.0 from ISO 0.7.0), sha256-pinned."""
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-templates"
SHA = "ea793f1d376ee25a98722a511062767c8e3c93a74daf78fcf0a5db0a228c2cb9"   # templates-1.4.0 (local tag, unsigned until the owner releases)


def test_spec_installs_only_the_shipped_library():
    s = (D / "chp-templates.spec").read_text()
    assert "Version:        1.4.0" in s and "BuildArch:      noarch" in s and "Requires:       python3" in s
    for p in ("rev2", "doc", "chpfill.pyz", "vocabulary.md", "site-conf-mapping.csv", "README.md"):
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


def test_repack_carries_no_macos_metadata_and_the_rpm_is_checked():
    # final review I1: bsdtar on macOS adds ._* AppleDouble entries for files with xattrs unless told not to
    b = (D / "build-rpm.sh").read_text()
    assert "COPYFILE_DISABLE=1 tar --no-mac-metadata" in b
    assert 'grep -q "/\\._"' in b                       # the built RPM is refused if any ._ file slipped in (double quotes: inside ssh '...')


def test_one_version_pin_drives_the_build():                                        # ISO 0.5.0: no stray 1.2.0
    b = (D / "build-rpm.sh").read_text()
    assert "\nV=1.4.0\n" in b and "1.2.0" not in b and "1.3.1" not in b
    assert "chp-templates-$V.tar.gz" in b and "chp-templates-$V-rpm.tar.gz" in b


def test_document_templates_installed_under_their_plain_names():                     # Plan 3 Task 7 (ruling F2)
    s = (D / "chp-templates.spec").read_text()
    for area, prefix in (("cui", "CUI_"), ("noncui", "")):
        for ext in ("docx", "xlsx", "md"):
            line = (f"install -Dm0644 doc/{area}/{prefix}Template_v0.1-DRAFT.{ext} "
                    f"%{{buildroot}}%{{_datadir}}/chp-templates/doc/{area}/Template.{ext}")
            assert line in s, line
    assert "%{_datadir}/chp-templates/doc\n" in s                  # the whole folder is owned by the package
