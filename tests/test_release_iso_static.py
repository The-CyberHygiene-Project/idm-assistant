from pathlib import Path

R = Path(__file__).resolve().parents[1] / "appliance" / "release"


def test_release_script_contract():
    t = (R / "release-iso.sh").read_text()
    assert "set -Eeuo pipefail" in t and "refusing:" in t                       # an existing target is refused
    assert "efcba98a4268ec35ccef0b66b78122b3c78246424f76186cfa45a1ba80ff81b2" in t  # the TESTED rc5 bytes, pinned
    assert "--armor --detach-sign" in t and "2DE0D71BF37D8F5E4201A590521276F43C908F8E" in t
    assert "gpg --verify" in t and "SHA256SUMS.asc" in t
    for f in ("RPM-GPG-KEY-cyberhygiene", "NOTICE.txt", "VERIFY.md", "chp-repo-$REPO_V.tar.gz"):
        assert f in t
    assert "REPO_V=0.6.3" in t and "RC=0.1.0-rc5" in t
    assert "idm-lab-secrets" not in t                                            # the share's lab folder is never touched


def test_verify_doc_names_the_pin_and_the_stick_rule():
    v = (R / "VERIFY.md.in").read_text()
    assert "2DE0D71BF37D8F5E4201A590521276F43C908F8E" in v and "sha256sum -c SHA256SUMS" in v
    assert "never" in v.lower() and "site stick" in v.lower()
