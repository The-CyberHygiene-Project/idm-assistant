from chp_site import review_rules as r

H, D = 3600, 86400


def test_short_lived_cert_attention_below_half_and_immediate_below_quarter():
    nb = 0; na = 24 * H                                          # Kanidm: 24 h
    assert r.cert_state(nb, na, 1 * H)[:2] == ("OK", False)
    assert r.cert_state(nb, na, 13 * H)[:2] == ("ATTENTION", False)   # 11 h left < 12 h
    assert r.cert_state(nb, na, 19 * H)[:2] == ("ATTENTION", True)    # 5 h left < 6 h


def test_long_lived_cert_attention_at_30_days_immediate_at_7():
    nb, na = 0, 3650 * D
    assert r.cert_state(nb, na, na - 31 * D)[:2] == ("OK", False)
    assert r.cert_state(nb, na, na - 30 * D)[:2] == ("ATTENTION", False)
    assert r.cert_state(nb, na, na - 7 * D)[:2] == ("ATTENTION", True)


def test_expired_cert_is_attention_and_immediate():
    assert r.cert_state(0, 10 * D, 11 * D)[:2] == ("ATTENTION", True)


def test_key_state_90_days_and_never():
    assert r.key_state(None, 0)[0] == "OK" and r.key_state(91 * D, 0)[0] == "OK" and r.key_state(90 * D, 0)[0] == "ATTENTION"


def test_fresh_state_stale_after_twice_the_schedule_or_never():
    assert r.fresh_state(0, 300, 600)[0] == "OK" and r.fresh_state(0, 300, 601)[0] == "STALE"
    assert r.fresh_state(None, 300, 0)[0] == "STALE"


def test_worst():
    assert r.worst(["OK", "ATTENTION", "STALE"]) == "STALE" and r.worst([]) == "OK"


def test_details_are_plain_english():
    assert r.cert_state(0, 24 * H, 13 * H)[2] == "11 h left of 24 h"
    assert "days left" in r.cert_state(0, 3650 * D, 3640 * D)[2]
