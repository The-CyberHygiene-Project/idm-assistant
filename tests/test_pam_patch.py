from pathlib import Path
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "authselect_patch", Path(__file__).resolve().parents[1] / "appliance/rpm/chp-identity-client/authselect_patch.py")
_m = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_m)
patch_pam, patch_nsswitch = _m.patch_pam, _m.patch_nsswitch

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


import pytest


@pytest.mark.parametrize("name", ["system-auth", "password-auth"])
def test_stock_sssd_profile_used_by_the_chp_kit_is_patched_the_same_way(name):
    # client1 (CHP kit) runs `authselect select sssd with-faillock with-pwhistory with-mkhomedir`.
    src = (FIX / f"authselect-sssd-{name}").read_text()
    out = patch_pam(src)
    for l in src.splitlines():
        assert l in out.splitlines()                      # nothing of the kit's profile is lost (pwhistory, faillock…)
    for kind in ("auth", "account"):
        ls = lines(out, kind)
        k = next(n for n, l in enumerate(ls) if "pam_kanidm.so" in l)
        u = next(n for n, l in enumerate(ls) if "pam_unix.so" in l)
        assert k < u and not jump_skips(ls, k), kind      # before pam_unix, and no jump (pam_localuser) can skip it
    get = {l.split(":")[0]: l for l in patch_nsswitch((FIX / "authselect-sssd-nsswitch.conf").read_text()).splitlines()
           if ":" in l and not l.startswith("#")}
    assert get["passwd"].split()[1] == "kanidm" and get["group"].split()[1] == "kanidm"
    assert "initgroups" not in get     # stock sssd has no initgroups line: glibc falls back to group (kanidm first)


def jump_skips(stack, target):
    """True if any line before `target` has a numeric jump ([x=N]) whose skipped range covers `target`."""
    import re
    for i, l in enumerate(stack[:target]):
        for n in re.findall(r"\[[^\]]*?=(\d+)", l) + re.findall(r"\s(\w+)=(\d+)", "") :
            if i < target <= i + int(n):
                return True
        m = re.search(r"\[([^\]]*)\]", l)
        if m:
            for part in m.group(1).split():
                k, _, v = part.partition("=")
                if v.isdigit() and i < target <= i + int(v):
                    return True
    return False


@pytest.mark.parametrize("fixture", ["authselect-sssd-system-auth", "authselect-sssd-password-auth",
                                     "authselect-hardening-system-auth", "authselect-hardening-password-auth"])
def test_no_numeric_jump_can_skip_pam_kanidm(fixture):
    # stock sssd: "auth [default=1 ...] pam_localuser.so" skips the next line for NON-local (i.e. Kanidm) users.
    out = patch_pam((FIX / fixture).read_text())
    for kind in ("auth", "account", "session"):
        st = lines(out, kind)
        k = next(i for i, l in enumerate(st) if "pam_kanidm" in l)
        assert not jump_skips(st, k), (fixture, kind, st[max(0, k - 2):k + 1])
