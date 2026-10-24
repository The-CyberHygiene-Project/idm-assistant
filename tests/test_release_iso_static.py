from pathlib import Path

R = Path(__file__).resolve().parents[1] / "appliance" / "release"


def test_release_script_contract():
    t = (R / "release-iso.sh").read_text()
    assert "set -Eeuo pipefail" in t and "refusing:" in t                       # an existing target is refused
    assert "--armor --detach-sign" in t and "2DE0D71BF37D8F5E4201A590521276F43C908F8E" in t
    assert "gpg --verify" in t and "SHA256SUMS.asc" in t
    for f in ("RPM-GPG-KEY-cyberhygiene", "NOTICE.txt", "VERIFY.md", "chp-repo-$REPO_V.tar.gz"):
        assert f in t
    assert "idm-lab-secrets" not in t                                            # the share's lab folder is never touched


def test_verify_doc_names_the_pin_and_the_stick_rule():
    v = (R / "VERIFY.md.in").read_text()
    assert "2DE0D71BF37D8F5E4201A590521276F43C908F8E" in v and "sha256sum -c SHA256SUMS" in v
    assert "never" in v.lower() and "site stick" in v.lower()


def test_release_script_versions_are_parameters():                      # Plan B Review Focus 5
    t = (R / "release-iso.sh").read_text()
    assert 'V=${V:?' in t and 'RC=${RC:?' in t and 'REPO_V=${REPO_V:?' in t and 'ISO_SHA=${ISO_SHA:?' in t
    assert '[[ -e $T ]] && { echo "refusing:' in t                           # 0.1.0/ (or any existing target) is never written
    assert "UPGRADE-FROM-0.1.0.md" in t                                      # spec §7 note ships with 0.2.0


def test_release_kit_never_touches_the_0_1_0_kit():
    t = (R / "release-kit.sh").read_text()
    assert 'T="$B/site-stick-kit-$V"' in t and '[[ -e $T ]] && { echo "refusing:' in t
    assert 'T="$B/site-stick-kit"' not in t                                 # the published 0.1.0 kit folder is never a target
    assert 'V=${V:?' in t and 'REPO_V=${REPO_V:?' in t


def test_upgrade_note_says_leave_the_stick_in():
    u = (R / "UPGRADE-FROM-0.1.0.md.in").read_text()
    assert "dnf --enablerepo=chp install chp-integrity" in u and "aide-pin" in u
    assert "leave the site stick plugged in" in u.lower()
