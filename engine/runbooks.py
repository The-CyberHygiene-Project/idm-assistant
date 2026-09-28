"""Runbooks: one short excerpt per finding id plus its default repair (the fallback when the model is unsure)."""
from dataclasses import dataclass
from pathlib import Path

DIR = Path(__file__).resolve().parents[1] / "runbooks"


@dataclass(frozen=True)
class Runbook:
    finding: str
    default_repair: object      # str | None
    excerpt: str


def load(finding_id):
    base = finding_id.split("(")[0]
    p = DIR / f"{base}.md"
    if not p.is_file():
        return None
    head, _, body = p.read_text().partition("\n---\n")
    meta = dict(line.split(":", 1) for line in head.splitlines() if ":" in line)
    d = meta.get("default_repair", "").strip()
    return Runbook(base, None if d in ("", "none") else d, body.strip())


def for_findings(findings):
    out, seen = [], set()
    for f in findings:
        rb = load(f.id)
        if rb and rb.finding not in seen:
            seen.add(rb.finding); out.append(rb)
    return out
