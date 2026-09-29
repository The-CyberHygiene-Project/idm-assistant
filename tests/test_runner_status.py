from engine.cli import final_status

OK = {"valid": True, "errors": []}


def test_green_when_clear_probe_ok_and_explained():
    assert final_status({"client2": []}, True, OK, False, 10, None) == "GREEN"


def test_findings_left_means_not_cleared():
    assert final_status({"client2": ["NSS_ORDER_WRONG"]}, True, OK, False, 10, None) == "NOT-CLEARED"


def test_probe_failure_means_not_cleared():
    assert final_status({"client2": []}, False, OK, False, 10, None) == "NOT-CLEARED"


def test_unavailable_model_fails_the_explain_step_unless_explicitly_skipped():
    down = {"valid": False, "errors": ["model unavailable: ConnectionError"]}
    assert final_status({"c": []}, True, down, False, 10, None) == "EXPLAIN-FAILED"
    assert final_status({"c": []}, True, down, True, 10, None) == "GREEN"


def test_unsure_or_invalid_model_is_still_explained_by_the_runbook():
    unsure = {"valid": False, "errors": ["repair_id 'x' is not on the allow-list"]}
    assert final_status({"c": []}, True, unsure, False, 10, None) == "GREEN"


def test_fault_that_would_have_healed_itself_is_not_credited_to_the_repair():
    assert final_status({"c": []}, True, OK, False, 130, 100) == "NOT-CLEARED-BY-REPAIR"
    assert final_status({"c": []}, True, OK, False, 40, 100) == "GREEN"


def test_allow_list_only_covers_roles_with_findings():
    from engine.cli import allowed_for_findings
    from engine.findings import Finding
    from engine.repairs import REGISTRY
    reps = {"srv1": {"role": "server"}, "client2": {"role": "client"}}
    got = allowed_for_findings({"srv1": [], "client2": [Finding("NSS_ORDER_WRONG", "nss", ("x",))]}, reps)
    assert got and all(REGISTRY[r].host_role == "client" for r in got)
