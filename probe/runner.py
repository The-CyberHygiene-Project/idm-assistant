"""Models x sizes x runs. Every call is logged raw (JSONL). A point is aborted if the
loaded-model set changes while it runs, or if the model reports a context overflow."""
import json
import re
from collections import Counter
from statistics import mean

from probe import lms
from probe.client import build_request, chat
from probe.score import score


def run_point(model, pad_tokens, n, *, transport=None, loaded=lms.loaded, temperature=0.5,
              raw_path=None):
    before = loaded()
    counts, ptoks, secs = Counter(), [], []
    reason = ""
    raw = open(raw_path, "a") if raw_path else None
    try:
        for i in range(n):
            resp, err, s = chat(build_request(model, pad_tokens, temperature), transport=transport)
            sc = score(resp, err)
            counts[sc["category"]] += 1
            secs.append(s)
            pt = (resp or {}).get("usage", {}).get("prompt_tokens") if resp else None
            if pt:
                ptoks.append(pt)
            if raw:
                raw.write(json.dumps({"model": model, "pad_tokens": pad_tokens, "i": i,
                                      "category": sc["category"], "finish_reason": sc["finish_reason"],
                                      "tool": sc["tool"], "detail": sc["detail"], "error": err,
                                      "prompt_tokens": pt, "seconds": round(s, 2)}) + "\n")
                raw.flush()
            if err and re.search(r"context", err, re.I):
                reason = f"context overflow: {err[:160]}"
                break
    finally:
        if raw:
            raw.close()
    after = loaded()
    if after != before:
        reason = reason or f"loaded models changed: {before} -> {after}"
    return {"model": model, "pad_tokens": pad_tokens, "n": n, "counts": dict(counts),
            "prompt_tokens_mean": round(mean(ptoks)) if ptoks else None,
            "seconds_mean": round(mean(secs), 1) if secs else None,
            "aborted": bool(reason), "reason": reason}


def _aborted(model, size, n, reason):
    return {"model": model, "pad_tokens": size, "n": n, "counts": {}, "prompt_tokens_mean": None,
            "seconds_mean": None, "aborted": True, "reason": reason}


def run_all(models, sizes, n, *, point=run_point, load=lms.load, unload=lms.unload_all,
            write=lambda points: None, raw_dir=None, context=None, temperature=0.5):
    """Never lets one failure lose the run: each point is caught, and results are written
    after every point."""
    points = []
    for model in models:
        try:
            unload()
            load(model, context)
            load_error = ""
        except Exception as e:  # noqa: BLE001 - recorded, never raised
            load_error = f"load failed: {type(e).__name__}: {e}"
        for size in sizes:
            if load_error:
                p = _aborted(model, size, n, load_error)
            else:
                raw = (raw_dir / f"{model.replace('/', '_')}-{size}.jsonl") if raw_dir else None
                try:
                    p = point(model, size, n, raw_path=raw, temperature=temperature)
                except Exception as e:  # noqa: BLE001
                    p = _aborted(model, size, n, f"{type(e).__name__}: {e}")
            points.append(p)
            write(points)
    return points
