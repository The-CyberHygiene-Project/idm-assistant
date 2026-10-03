"""The runbooks and repairs follow the ISSO decisions of 2026-09-29 (#28 revocation, #30 clock jumps, #32 re-enabling)."""
import importlib

from engine import runbooks
from engine.repairs import REGISTRY


def test_32_no_engine_repair_reenables_an_account():
    # #32: only the ISSO or a named delegate, with a written reason (chp-site unexpire). The engine never does it.
    assert "account-unexpire" not in REGISTRY
    assert not [r.id for r in REGISTRY.values() if "ACCOUNT_EXPIRED" in r.verify_absent]


def test_32_runbook_refers_to_chp_site_unexpire():
    rb = runbooks.load("ACCOUNT_EXPIRED")
    assert rb.default_repair is None
    assert "chp-site unexpire" in rb.excerpt and "#32" in rb.excerpt
    assert "manager" not in rb.excerpt


def test_32_scenario_l5_requires_a_decline():
    l5 = importlib.import_module("scenarios.l5")
    assert l5.REPAIRS == [] and not getattr(l5, "MODEL_MAY_DECLINE", False)   # expected [] -> the model must decline
    assert hasattr(l5, "restore")                                             # the operator re-enables, outside


def test_30_clock_step_is_person_approved_and_cites_the_decision():
    rb = runbooks.load("TOTP_TIME_SKEW")
    assert rb.default_repair == "time-resync"
    assert "#30" in rb.excerpt and "approv" in rb.excerpt


def test_28_stale_cache_means_the_fanout_missed_this_host():
    rb = runbooks.load("UNIXD_CACHE_STALE")
    assert "#28" in rb.excerpt and "every workstation" in rb.excerpt
