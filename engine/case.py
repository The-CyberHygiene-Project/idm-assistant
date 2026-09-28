"""Case files: cases/<ts>-<slug>/ = the audit record of one diagnosis (symptom, reports, findings, approval, repair
output, wall-clock time per step)."""
import json
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class Case:
    def __init__(self, root, slug, symptom):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self.dir = Path(root) / f"{ts}-{slug}"
        self.dir.mkdir(parents=True)
        self.timings = {}
        self.write("symptom.txt", symptom)

    def write(self, name, obj):
        p = self.dir / name
        p.write_text(obj if isinstance(obj, str) else json.dumps(obj, indent=1, default=str) + "\n")
        return p

    def log(self, line):
        with (self.dir / "repair.log").open("a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} {line}\n")

    @contextmanager
    def step(self, name):
        t0 = time.monotonic()
        try:
            yield
        finally:
            self.timings[name] = round(time.monotonic() - t0, 3)
            self.write("timings.json", self.timings)
