import pytest

from chp_site.authselect_ga import GA_LINES, patch_ga
from chp_site.sitefile import SiteError

CUI = """auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        required                                     pam_faillock.so preauth silent                         {include if "with-faillock"}
auth        sufficient                                   pam_kanidm.so ignore_unknown_user
auth        sufficient                                   pam_unix.so {if not "without-nullok":nullok}
auth        required                                     pam_faillock.so authfail                               {include if "with-faillock"}
auth        required                                     pam_deny.so
account     sufficient                                   pam_kanidm.so ignore_unknown_user
"""


def test_ga_goes_right_before_pam_kanidm_after_faillock_preauth():
    out = patch_ga(CUI).splitlines()
    i = next(n for n, l in enumerate(out) if "pam_kanidm.so" in l and l.startswith("auth"))
    assert out[i - 2] == GA_LINES[0] and out[i - 1] == GA_LINES[1]
    assert "preauth" in out[i - 3]


def test_local_users_skip_exactly_the_ga_line():
    out = patch_ga(CUI).splitlines()
    j = out.index(GA_LINES[0])
    assert "[success=1 default=ignore]" in out[j] and "pam_localuser.so" in out[j]
    assert "pam_google_authenticator.so" in out[j + 1] and "pam_kanidm.so" in out[j + 2]


def test_no_nullok_and_tokens_read_as_root_from_var_lib():
    ga = GA_LINES[1]
    assert "nullok" not in ga and "secret=/var/lib/google-authenticator/${USER}" in ga and "user=root" in ga
    assert "no_strict_owner" not in ga and "allowed_perm" not in ga


def test_idempotent():
    once = patch_ga(CUI)
    assert patch_ga(once) == once


def test_refuses_without_pam_kanidm():
    with pytest.raises(SiteError, match="pam_kanidm"):
        patch_ga("auth required pam_unix.so\n")


def test_refuses_when_an_earlier_line_jumps():
    text = "auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n" + CUI
    with pytest.raises(SiteError, match="jump"):
        patch_ga(text)
