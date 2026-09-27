from probe import runner
from probe.client import build_request


def test_request_carries_tools_and_padding():
    req = build_request("m", 1000, 0.5)
    assert req["model"] == "m" and len(req["tools"]) == 5
    assert len(req["messages"][0]["content"]) > 3000


def _fake_transport(kind):
    def t(url, payload, timeout):
        if kind == "valid":
            msg = {"tool_calls": [{"type": "function", "function": {"name": "check_time_sync", "arguments": "{}"}}]}
        else:
            msg = {"content": "Run chronyc tracking."}
        return {"choices": [{"message": msg}], "usage": {"prompt_tokens": 1234}}
    return t


def test_run_point_counts_categories():
    r = runner.run_point("m", 1000, 4, transport=_fake_transport("valid"), loaded=lambda: ["m"])
    assert r["counts"]["valid"] == 4 and r["prompt_tokens_mean"] == 1234 and not r["aborted"]


def test_prose_is_counted_as_prose():
    r = runner.run_point("m", 1000, 3, transport=_fake_transport("prose"), loaded=lambda: ["m"])
    assert r["counts"]["prose"] == 3


def test_runner_aborts_when_loaded_models_change():
    states = iter([["m"], ["m", "other-model"]])
    r = runner.run_point("m", 1000, 5, transport=_fake_transport("valid"), loaded=lambda: next(states))
    assert r["aborted"] and "other-model" in r["reason"]
