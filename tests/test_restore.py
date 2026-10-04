import copy

from engine.findings import evaluate

BASE = {"schema": "idm-report/1", "host": "client2", "role": "client", "collected_at": "2026-10-04T13:20:00Z",
        "errors": [], "time": {"offset_s": 1e-8, "synced": True, "source": "192.168.100.1",
                                "source_offset_s": -50085.0, "source_state": "~"}}


def ids(**time):
    r = copy.deepcopy(BASE); r["time"].update(time)
    return {f.id: f for f in evaluate(r)}


def test_restored_clock_is_skew_even_while_synced():
    f = ids()["TOTP_TIME_SKEW"]
    assert ("chrony rejects its time source as too variable (-50085.0 s off): typical after restoring a snapshot or "
            "image (requirement row 18)") in f.evidence


def test_stale_sample_after_a_real_step_is_not_skew():
    assert "TOTP_TIME_SKEW" not in ids(source_state="*")


def test_unusable_source_is_not_the_restore_case():
    assert "TOTP_TIME_SKEW" not in ids(source_state="?")


def test_small_offset_with_tilde_is_not_skew():
    assert "TOTP_TIME_SKEW" not in ids(source_offset_s=-2.0)


def test_old_reports_without_the_field_behave_as_before():
    r = copy.deepcopy(BASE); del r["time"]["source_state"]
    assert "TOTP_TIME_SKEW" not in {f.id for f in evaluate(r)}
