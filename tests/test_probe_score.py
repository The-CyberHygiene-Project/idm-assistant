from probe.score import score


def _resp(content=None, tool_calls=None):
    return {"choices": [{"message": {"content": content, "tool_calls": tool_calls}}]}


def _call(name, args):
    return [{"type": "function", "function": {"name": name, "arguments": args}}]


def test_structured_valid_call():
    r = score(_resp(tool_calls=_call("check_time_sync", "{}")))
    assert r["category"] == "valid" and r["tool"] == "check_time_sync"


def test_structured_call_with_bad_arguments_is_invalid():
    r = score(_resp(tool_calls=_call("read_log", '{"unit": "sshd"}')))
    assert r["category"] == "invalid_call" and "lines" in r["detail"]


def test_structured_call_to_unknown_tool_is_invalid():
    assert score(_resp(tool_calls=_call("rm_rf", "{}")))["category"] == "invalid_call"


def test_json_in_content_is_not_a_structured_call():
    text = 'I will call {"name": "check_time_sync", "arguments": {}}'
    assert score(_resp(content=text))["category"] == "prose_json"


def test_plain_advice_is_prose():
    r = score(_resp(content="You should run chronyc tracking on the client."))
    assert r["category"] == "prose"


def test_transport_error_is_error():
    assert score(None, error="timeout")["category"] == "error"


def test_empty_choices_is_error():
    assert score({"choices": []})["category"] == "error"
