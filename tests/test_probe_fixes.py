import json

from probe import lms, runner
from probe.client import build_request


def _t(msg, finish="stop"):
    def t(url, payload, timeout):
        return {"choices": [{"message": msg, "finish_reason": finish}], "usage": {"prompt_tokens": 2000}}
    return t


VALID = {"tool_calls": [{"type": "function", "function": {"name": "check_time_sync", "arguments": "{}"}}]}


def test_each_request_is_unique_so_prompt_cache_cannot_warm_it():
    a, b = build_request("m", 1000, 0.5), build_request("m", 1000, 0.5)
    assert a["messages"][0]["content"] != b["messages"][0]["content"]


def test_max_tokens_leaves_room_for_reasoning():
    assert build_request("m", 1000, 0.5)["max_tokens"] >= 4096


def test_run_point_writes_raw_jsonl(tmp_path):
    raw = tmp_path / "raw.jsonl"
    runner.run_point("m", 1000, 3, transport=_t(VALID), loaded=lambda: ["m"], raw_path=raw)
    rows = [json.loads(l) for l in raw.read_text().splitlines()]
    assert len(rows) == 3 and rows[0]["category"] == "valid" and rows[0]["finish_reason"] == "stop"
    assert rows[0]["prompt_tokens"] == 2000


def test_context_overflow_error_aborts_the_point():
    def t(url, payload, timeout):
        raise RuntimeError("400: prompt exceeds the model's context length")
    r = runner.run_point("m", 25000, 3, transport=t, loaded=lambda: ["m"])
    assert r["aborted"] and "context" in r["reason"]


def test_run_all_survives_a_failing_point_and_writes_after_each(tmp_path):
    calls, written = [], []

    def fake_point(model, size, n, **kw):
        calls.append(size)
        if size == 4000:
            raise RuntimeError("lms ps failed")
        return {"model": model, "pad_tokens": size, "n": n, "counts": {"valid": n},
                "prompt_tokens_mean": 1, "seconds_mean": 1, "aborted": False, "reason": ""}

    pts = runner.run_all(["m"], [1000, 4000, 8000], 2, point=fake_point,
                         load=lambda m, ctx: None, unload=lambda: None,
                         write=lambda points: written.append(len(points)), raw_dir=tmp_path)
    assert calls == [1000, 4000, 8000]
    assert pts[1]["aborted"] and "lms ps failed" in pts[1]["reason"]
    assert written == [1, 2, 3]


def test_load_sets_an_explicit_context_length(monkeypatch):
    seen = []
    monkeypatch.setattr(lms.subprocess, "run", lambda args, **kw: seen.append(args))
    lms.load("m", 33000)
    assert "-c" in seen[0] and "33000" in seen[0]
