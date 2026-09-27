"""Models x sizes x runs. A point is aborted if the loaded-model set changes while it
runs (LM Studio JIT-loading another model skews memory and timing)."""
from collections import Counter
from statistics import mean

from probe import lms
from probe.client import build_request, chat
from probe.score import score


def run_point(model, pad_tokens, n, *, transport=None, loaded=lms.loaded, temperature=0.5):
    before = loaded()
    counts, ptoks, secs = Counter(), [], []
    for _ in range(n):
        resp, err, s = chat(build_request(model, pad_tokens, temperature), transport=transport)
        counts[score(resp, err)["category"]] += 1
        secs.append(s)
        if resp and resp.get("usage"):
            ptoks.append(resp["usage"].get("prompt_tokens", 0))
    after = loaded()
    aborted = after != before
    return {"model": model, "pad_tokens": pad_tokens, "n": n, "counts": dict(counts),
            "prompt_tokens_mean": round(mean(ptoks)) if ptoks else None,
            "seconds_mean": round(mean(secs), 1) if secs else None,
            "aborted": aborted,
            "reason": f"loaded models changed: {before} -> {after}" if aborted else ""}
