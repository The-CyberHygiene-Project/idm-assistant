"""chp-templates RPM (Plan C3 Task 1): built only from the SIGNED templates release (1.4.0 from ISO 0.7.0), sha256-pinned."""
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-templates"
SHA = "73964274430484e387a23e2cb95bee1747007841ecbd04c7f8c2f245dfc2c34f"   # templates-1.4.0 (local tag, unsigned until the owner releases)


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
    for area, prefix in (("cui", "CUI_"), ("fci", "FCI_"), ("noncui", "")):        # fci: Task 12 (owner 2026-11-20)
        for ext in ("docx", "xlsx", "md"):
            line = (f"install -Dm0644 doc/{area}/{prefix}Template_v0.1-DRAFT.{ext} "
                    f"%{{buildroot}}%{{_datadir}}/chp-templates/doc/{area}/Template.{ext}")
            assert line in s, line
    assert "%{_datadir}/chp-templates/doc\n" in s                  # the whole folder is owned by the package


# ---- Plan 3 Task 11b (owner decision 2026-11-20, option A): opt-in lab-candidate build from the local tag ----
import os, subprocess, textwrap  # noqa: E402

BUILD = D / "build-rpm.sh"


def _run(tmp_path, env_extra):
    fake = tmp_path / "bin"; fake.mkdir(exist_ok=True)
    for tool in ("ssh", "scp"):                         # must never be reached by a refused run
        f = fake / tool; f.write_text("#!/bin/sh\necho REACHED-$0; exit 99\n"); f.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("CHP_TEMPLATES_")}
    env["PATH"] = f"{fake}:{env['PATH']}"; env.update(env_extra)
    return subprocess.run(["bash", str(BUILD)], env=env, capture_output=True, text=True)


def _repo(tmp_path, tag=True):
    r = tmp_path / "tpl"; r.mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True)  # noqa: E731
    g("init", "-q"); (r / "README.md").write_text("not the real library\n"); g("add", ".")
    g("-c", "user.name=t", "-c", "user.email=t@invalid", "commit", "-q", "-m", "x")
    if tag:
        g("-c", "user.name=t", "-c", "user.email=t@invalid", "tag", "-a", "templates-1.4.0", "-m", "t")
    return r


def test_lab_candidate_refuses_an_archive_that_is_not_the_pin(tmp_path):
    p = _run(tmp_path, {"CHP_TEMPLATES_TAG": str(_repo(tmp_path))})
    assert p.returncode == 1 and "not the pinned" in p.stdout and "REACHED" not in p.stdout + p.stderr
    assert "LAB CANDIDATE BUILD" in p.stdout and "NO SIGNATURE PROVENANCE" in p.stdout


def test_lab_candidate_refuses_a_missing_tag_and_a_non_repo(tmp_path):
    p = _run(tmp_path, {"CHP_TEMPLATES_TAG": str(_repo(tmp_path, tag=False))})
    assert p.returncode == 1 and "tag templates-1.4.0 not found" in p.stdout and "REACHED" not in p.stdout
    (tmp_path / "plain").mkdir()
    p = _run(tmp_path, {"CHP_TEMPLATES_TAG": str(tmp_path / "plain")})
    assert p.returncode == 1 and "not a git working tree" in p.stdout and "REACHED" not in p.stdout


def test_lab_candidate_and_release_together_are_refused(tmp_path):
    p = _run(tmp_path, {"CHP_TEMPLATES_TAG": str(_repo(tmp_path)), "CHP_TEMPLATES_RELEASE": str(tmp_path)})
    assert p.returncode == 1 and "not both" in p.stdout and "REACHED" not in p.stdout


def test_opt_in_required_default_path_still_needs_the_signed_release(tmp_path):
    p = _run(tmp_path, {})                               # neither variable: the default (signed release) path
    assert p.returncode != 0 and "set CHP_TEMPLATES_RELEASE to the signed release folder" in p.stderr
    assert "LAB CANDIDATE" not in p.stdout and "REACHED" not in p.stdout
    p = _run(tmp_path, {"CHP_TEMPLATES_RELEASE": str(tmp_path)})   # a release folder without a good signature
    assert p.returncode == 1 and "refusing: bad signature" in p.stdout and "LAB CANDIDATE" not in p.stdout


def test_default_path_checks_unchanged():
    b = BUILD.read_text()
    rel = b[b.index("REL=${CHP_TEMPLATES_RELEASE:?"):b.index("\nfi\n# The renderer")]
    for line in ('gpg --verify "$REL/SHA256SUMS.asc" "$REL/SHA256SUMS" 2>&1 | grep -q "Good signature"',
                 'grep -q "VALIDSIG $FPR"', '(cd "$REL" && shasum -a 256 -c SHA256SUMS)',
                 '[[ $(shasum -a 256 "$REL/$TAR" | cut -d\' \' -f1) == "$SHA" ]]'):
        assert line in rel, line
    assert "git" not in rel                               # the tag path never runs in the default branch
    assert b.index('if [[ -n ${CHP_TEMPLATES_TAG:-} ]]') < b.index("scp ")


def test_changelog_says_lab_candidate():
    s = (D / "chp-templates.spec").read_text()
    assert "PRE-RELEASE LAB CANDIDATE: built from the UNSIGNED local tag templates-1.4.0" in s
