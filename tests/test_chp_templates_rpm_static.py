"""chp-templates RPM (Plan C3 Task 1): built only from the SIGNED templates release (1.3.1 from ISO 0.5.0), sha256-pinned."""
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-templates"
SHA = "73682cfc17b1707e68cda99770ffb9a873efaad04c08058d8169313018f5a5df"   # templates-1.3.1


def test_spec_installs_only_the_shipped_library():
    s = (D / "chp-templates.spec").read_text()
    assert "Version:        1.3.1" in s and "BuildArch:      noarch" in s and "Requires:       python3" in s
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


def test_repack_carries_no_macos_metadata_and_the_rpm_is_checked():
    # final review I1: bsdtar on macOS adds ._* AppleDouble entries for files with xattrs unless told not to
    b = (D / "build-rpm.sh").read_text()
    assert "COPYFILE_DISABLE=1 tar --no-mac-metadata" in b
    assert 'grep -q "/\\._"' in b                       # the built RPM is refused if any ._ file slipped in (double quotes: inside ssh '...')


def test_one_version_pin_drives_the_build():                                        # ISO 0.5.0: no stray 1.2.0
    b = (D / "build-rpm.sh").read_text()
    assert "\nV=1.3.1\n" in b and "1.2.0" not in b
    assert "chp-templates-$V.tar.gz" in b and "chp-templates-$V-rpm.tar.gz" in b
