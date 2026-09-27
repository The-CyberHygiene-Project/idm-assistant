"""One chat-completions call to LM Studio (localhost only)."""
import time
import uuid

import requests

from probe.padding import padding
from probe.tools import TOOLS

URL = "http://127.0.0.1:1234/v1/chat/completions"
SYSTEM = ("You are a Linux identity-systems administrator's assistant. Diagnose by calling the "
          "provided tools. Reference material follows.\n\n")
TASK = ("Users report they cannot log in to client2 since this morning. Start diagnosing now: "
        "call exactly one tool.")


def build_request(model, pad_tokens, temperature):
    # A unique first line per request stops LM Studio's prompt cache from warming repeats,
    # so every call pays its own prefill (review finding: cached repeats hid cold timings).
    nonce = f"[probe run {uuid.uuid4().hex[:12]}]\n"
    return {"model": model, "temperature": temperature, "max_tokens": 4096, "tools": TOOLS,
            "tool_choice": "auto",
            "messages": [{"role": "system", "content": nonce + SYSTEM + padding(pad_tokens)},
                         {"role": "user", "content": TASK}]}


def _post(url, payload, timeout):
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


def chat(request, transport=None, timeout=300):
    t0 = time.monotonic()
    try:
        return (transport or _post)(URL, request, timeout), None, time.monotonic() - t0
    except Exception as e:  # recorded as an "error" run, never raised
        return None, f"{type(e).__name__}: {e}", time.monotonic() - t0
