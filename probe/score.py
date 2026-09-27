"""Classify one chat-completions response. Only a STRUCTURED tool_calls entry with a
known tool and schema-valid arguments counts as success (MFR F-7: under load the model
drifts into prose that describes what to run). A reply cut off by the token limit before
any call is "truncated", not a model choice to answer in prose."""
from probe.tools import TOOL_NAMES, validate_call


def _r(category, detail, tool=None, finish=None):
    return {"category": category, "detail": detail, "tool": tool, "finish_reason": finish}


def score(response, error=None):
    if error is not None or not response:
        return _r("error", error or "no response")
    choices = response.get("choices") or []
    if not choices:
        return _r("error", "no choices")
    finish = choices[0].get("finish_reason")
    msg = choices[0].get("message") or {}
    calls = msg.get("tool_calls") or []
    if calls:
        fn = calls[0].get("function") or {}
        name, args = fn.get("name", ""), fn.get("arguments", "")
        ok, reason = validate_call(name, args)
        return _r("valid" if ok else "invalid_call", reason, name, finish)
    content = msg.get("content") or ""
    if finish == "length":
        return _r("truncated", content[-200:], finish=finish)
    if any(n in content for n in TOOL_NAMES) and "{" in content:
        return _r("prose_json", content[:200], finish=finish)
    return _r("prose", content[:200], finish=finish)
