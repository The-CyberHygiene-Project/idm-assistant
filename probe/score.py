"""Classify one chat-completions response. Only a STRUCTURED tool_calls entry with a
known tool and schema-valid arguments counts as success (MFR F-7: under load the model
drifts into prose that describes what to run)."""
from probe.tools import TOOL_NAMES, validate_call


def score(response, error=None):
    if error is not None or not response:
        return {"category": "error", "detail": error or "no response", "tool": None}
    choices = response.get("choices") or []
    if not choices:
        return {"category": "error", "detail": "no choices", "tool": None}
    msg = choices[0].get("message") or {}
    calls = msg.get("tool_calls") or []
    if calls:
        fn = calls[0].get("function") or {}
        name, args = fn.get("name", ""), fn.get("arguments", "")
        ok, reason = validate_call(name, args)
        return {"category": "valid" if ok else "invalid_call", "detail": reason, "tool": name}
    content = msg.get("content") or ""
    if any(n in content for n in TOOL_NAMES) and "{" in content:
        return {"category": "prose_json", "detail": content[:200], "tool": None}
    return {"category": "prose", "detail": content[:200], "tool": None}
