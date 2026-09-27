from probe.tools import TOOLS, TOOL_NAMES, validate_call


def test_five_tools_in_openai_format():
    assert len(TOOLS) == 5
    assert all(t["type"] == "function" and "parameters" in t["function"] for t in TOOLS)
    assert TOOL_NAMES == {t["function"]["name"] for t in TOOLS}


def test_each_tool_validates_against_its_own_schema():
    assert validate_call("get_service_status", '{"unit": "kanidm-unixd"}') == (True, "ok")
    assert validate_call("read_log", '{"unit": "sshd", "lines": 50}') == (True, "ok")
    assert validate_call("check_certificate", '{"host": "idm.kanidm.lab.test", "port": 443}') == (True, "ok")
    assert validate_call("check_time_sync", "{}") == (True, "ok")
    assert validate_call("list_failed_logins", '{"user": "alice"}') == (True, "ok")


def test_unknown_tool_is_rejected():
    ok, reason = validate_call("run_shell", '{"cmd": "id"}')
    assert not ok and "unknown tool" in reason


def test_missing_required_argument_is_rejected():
    ok, reason = validate_call("read_log", '{"unit": "sshd"}')
    assert not ok and "lines" in reason


def test_wrong_type_is_rejected():
    ok, _ = validate_call("check_certificate", '{"host": "x", "port": "443"}')
    assert not ok


def test_arguments_that_are_not_json_are_rejected():
    ok, reason = validate_call("check_time_sync", "not json")
    assert not ok and "json" in reason.lower()


def test_non_string_arguments_do_not_crash():
    ok, reason = validate_call("check_time_sync", {"not": "a string"})
    assert ok is False and "arguments" in reason
