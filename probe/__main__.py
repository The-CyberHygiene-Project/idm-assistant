"""uv run python -m probe --models M1 M2 --sizes 1000 4000 8000 15000 25000 --n 20 --i-have-permission"""
import argparse
import datetime as dt
import pathlib
import sys

from probe import lms
from probe.report import to_markdown
from probe.runner import run_all


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--sizes", nargs="+", type=int, default=[1000, 4000, 8000, 15000, 25000])
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--temperature", type=float, default=0.5)
    ap.add_argument("--i-have-permission", action="store_true",
                    help="the user has confirmed LM Studio is free (the probe unloads models)")
    a = ap.parse_args()
    if not a.i_have_permission:
        raise SystemExit("Refusing to run: needs --i-have-permission (the user must free LM Studio).")
    stamp = dt.datetime.now().strftime("%Y-%m-%d-%H%M")
    base = pathlib.Path(__file__).parent / "results"
    raw_dir = base / "raw" / stamp
    raw_dir.mkdir(parents=True, exist_ok=True)
    out = base / f"{stamp}.md"
    context = max(a.sizes) + 8192          # explicit, never LM Studio's default
    original = lms.loaded()
    meta = {"date": stamp, "temperature": a.temperature, "n per point": a.n,
            "requested context": context, "max_tokens": 4096, "raw per-call data": str(raw_dir)}

    def write(points):
        try:
            meta["context in effect"] = lms.contexts()
        except Exception:  # noqa: BLE001
            pass
        out.write_text(to_markdown(points, meta))

    try:
        points = run_all(a.models, a.sizes, a.n, write=write, raw_dir=raw_dir,
                         context=context, temperature=a.temperature)
        for p in points:
            print(p["model"], p["pad_tokens"], p["counts"], p["reason"], flush=True)
    finally:
        try:
            lms.unload_all()
            for m in original:
                lms.load(m)
            meta["restored models"] = original
        except Exception as e:  # noqa: BLE001 - never mask the run's own outcome
            print(f"WARNING: could not restore models {original}: {e}", file=sys.stderr)
    print("wrote", out)


if __name__ == "__main__":
    main()
