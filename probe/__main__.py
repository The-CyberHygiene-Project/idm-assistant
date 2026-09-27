"""uv run python -m probe --models M1 M2 --sizes 1000 4000 8000 15000 25000 --n 20 --i-have-permission"""
import argparse
import datetime as dt
import pathlib

from probe import lms
from probe.report import to_markdown
from probe.runner import run_point


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
    original = lms.loaded()
    points = []
    try:
        for model in a.models:
            lms.unload_all()
            lms.load(model)
            for size in a.sizes:
                p = run_point(model, size, a.n, temperature=a.temperature)
                points.append(p)
                print(model, size, p["counts"], "ABORTED" if p["aborted"] else "", flush=True)
    finally:
        lms.unload_all()
        for m in original:
            lms.load(m)
    stamp = dt.datetime.now().strftime("%Y-%m-%d-%H%M")
    out = pathlib.Path(__file__).parent / "results" / f"{stamp}.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(to_markdown(points, {"date": stamp, "temperature": a.temperature,
                                        "n per point": a.n, "restored models": original}))
    print("wrote", out)


if __name__ == "__main__":
    main()
