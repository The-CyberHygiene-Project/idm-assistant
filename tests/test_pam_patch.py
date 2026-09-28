from pathlib import Path
from lab.client.authselect_patch import patch_pam, patch_nsswitch

FIX = Path(__file__).parent / "fixtures"


def lines(text, kind):
    return [l for l in text.splitlines() if l.startswith(kind)]


def test_pam_kanidm_goes_directly_before_pam_unix_in_auth_and_account():
    out = patch_pam((FIX / "authselect-hardening-system-auth").read_text())
    for kind, want in [("auth", "auth        sufficient                                   pam_kanidm.so ignore_unknown_user"),
                       ("account", "account     sufficient                                   pam_kanidm.so ignore_unknown_user")]:
        ls = lines(out, kind)
        i = next(n for n, l in enumerate(ls) if "pam_unix.so" in l)
        assert ls[i - 1] == want, kind


def test_cui_hardening_lines_are_kept_and_faillock_preauth_still_runs_first():
    src = (FIX / "authselect-hardening-system-auth").read_text()
    out = patch_pam(src)
    for l in src.splitlines():
        assert l in out.splitlines()
    auth = lines(out, "auth")
    assert auth.index(next(l for l in auth if "pam_faillock.so preauth" in l)) < auth.index(next(l for l in auth if "pam_kanidm" in l))


def test_patch_is_idempotent():
    once = patch_pam((FIX / "authselect-hardening-password-auth").read_text())
    assert patch_pam(once) == once


def test_nsswitch_puts_kanidm_first_for_passwd_and_group_only():
    src = (FIX / "authselect-hardening-nsswitch.conf").read_text()
    out = patch_nsswitch(src)
    get = {l.split(":")[0]: l for l in out.splitlines() if ":" in l and not l.startswith("#")}
    assert get["passwd"].split()[1] == "kanidm"
    assert get["group"].split()[1] == "kanidm"
    assert get["initgroups"].split()[1] == "kanidm"   # D9: CUI profile pins initgroups to files -> no Kanidm groups at login
    assert "kanidm" not in get["shadow"]
    assert get["passwd"].rstrip().endswith("{exclude if \"with-custom-passwd\"}")   # template markers kept
    assert patch_nsswitch(out) == out


def test_session_skip_rule_still_skips_pam_unix_for_crond():
    # CUI: "session [success=1 default=ignore] pam_succeed_if.so service in crond" must keep skipping pam_unix.
    out = patch_pam((FIX / "authselect-hardening-system-auth").read_text())
    sess = lines(out, "session")
    skip = next(i for i, l in enumerate(sess) if "pam_succeed_if.so service in crond" in l)
    assert "pam_unix.so" in sess[skip + 1]
    assert any("pam_kanidm" in l for l in sess[:skip])
