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


def test_release_repo_script_contract():                                # repo-only update (no ISO), e.g. 0.2.0-update1
    t = (R / "release-repo.sh").read_text()
    assert "set -Eeuo pipefail" in t and 'V=${V:?' in t and 'REPO_V=${REPO_V:?' in t
    assert 'T="$B/$V"' in t and '[[ -e $T ]] && { echo "refusing:' in t      # never overwrites a published folder
    assert "chp-repo-$REPO_V.tar.gz" in t and "UPDATE.md" in t and "RPM-GPG-KEY-cyberhygiene" in t
    assert "--armor --detach-sign" in t and "2DE0D71BF37D8F5E4201A590521276F43C908F8E" in t and "gpg --verify" in t
    assert ".iso" not in t and "idm-lab-secrets" not in t


def test_update_note_tells_the_isso_how_to_check_aide_conf():
    u = (R / "UPDATE.md.in").read_text()
    assert "dnf --enablerepo=chp upgrade chp-integrity" in u and "aide-accept" in u
    assert "cmp /etc/aide.conf /usr/share/chp-integrity/aide.conf" in u and "rpm -V chp-integrity" in u


def test_release_repo_note_is_selectable_and_default_unchanged():
    t = (R / "release-repo.sh").read_text()
    assert 'NOTE=${NOTE:-UPDATE.md.in}' in t                         # update1 behaviour unchanged
    assert '[[ -f "$here/$NOTE" ]] || { echo "refusing:' in t
    assert '"$here/$NOTE" > "$P/UPDATE.md"' in t


def test_update2_note_covers_install_use_and_aide():
    u = (R / "UPDATE-0.2.0-update2.md.in").read_text()
    for s in ("dnf --enablerepo=chp upgrade chp-site", "dnf --enablerepo=chp install chp-templates", "chp-site docs",
              "profile.ini.template", "aide-accept", "/var/lib/chp/docs"):
        assert s in u, s


def test_kit_ships_the_profile_template_and_readme_lists_every_folder():
    t = (R / "release-kit.sh").read_text()
    assert '"$kit/profile.ini.template"' in t and "profile.ini.template" in t.split("> SHA256SUMS")[0]
    for row in ("`0.2.0-update1/`", "`0.2.0-update2/`", "`site-stick-kit-0.2.0-update2/`", "`site-stick-kit-0.2.0/`"):
        assert row in t, row


def test_update3_note_covers_both_upgrades_and_aide():
    u = (R / "UPDATE-0.2.0-update3.md.in").read_text()
    for s in ("dnf --enablerepo=chp upgrade chp-identity-client chp-site", "chp-identity-client` 0.2.3",
              "chp-site` 0.7.3", "aide-accept", "Explained by signed package updates", "still denied"):
        assert s in u, s


def test_readme_lists_update3():
    assert "`0.2.0-update3/`" in (R / "release-kit.sh").read_text()


def test_wazuh_key_pinned_and_packages_listed():
    t = (R / "trusted-keys.txt").read_text()
    assert "0DCFCA5547B19D2A6099506096B3EE5F29111145 wazuh RPM-GPG-KEY-WAZUH" in t
    p = (R / "PACKAGES.txt").read_text()
    assert "wazuh-manager wazuh" in p and "wazuh-agent wazuh" in p and "chp-security ours" in p


def test_release_scripts_check_key_expiry_first():
    for s in ("release-repo.sh", "release-iso.sh", "release-kit.sh"):
        t = (R / s).read_text()
        assert 'bash "$here/check-key-expiry.sh"' in t, s


def test_notice_names_wazuh_gplv2():
    n = (R.parent / "branding" / "NOTICE.txt").read_text()
    assert "Wazuh" in n and "GPL" in n


def test_verify_repo_accepts_v3_signatures_from_pinned_keys():
    # W1 Task 6: Wazuh signs with V3 signature packets (RSA/SHA256, key 29111145); the check matched only V4. The key ID
    # must still be a pinned primary key, so this widens the packet format, never the trust.
    v = (R / "verify-repo.sh").read_text()
    assert r"Header V[34] RSA\/SHA256 Signature, key ID" in v
