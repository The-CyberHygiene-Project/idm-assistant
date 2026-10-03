"""Runbooks: one short page per finding id. The header fields (shape approved 2026-10-03) fill the operator's decision
form by code: user_sees + means -> PROBLEM, evidence -> LIKELY CAUSE, repair -> PROPOSED ACTION, if_wrong + rollback ->
POTENTIAL DOWNSIDE, say_no_if -> SAY NO IF. The body after the header is the excerpt the model reads."""
from dataclasses import dataclass
import re as _re
from pathlib import Path

DIR = Path(__file__).resolve().parents[1] / "runbooks"
FIELDS = ("user_sees", "means", "evidence", "repair", "if_wrong", "rollback", "say_no_if")


@dataclass(frozen=True)
class Runbook:
    finding: str
    default_repair: object      # str | None
    excerpt: str
    decisions: str = ""         # ISSO decisions this page depends on, e.g. "30"
    user_sees: str = ""
    means: str = ""
    evidence: str = ""
    repair: str = ""
    if_wrong: str = ""
    rollback: str = ""
    say_no_if: str = ""

    @property
    def complete(self):
        return all(getattr(self, f).strip() for f in FIELDS)


def ids():
    """Runbook pages are named by finding id (upper case, words joined by _); anything else in the folder (README.md) is not a runbook."""
    return sorted(p.stem for p in DIR.glob("*.md") if _re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", p.stem))


def load(finding_id):
    base = finding_id.split("(")[0]
    p = DIR / f"{base}.md"
    if not p.is_file():
        return None
    text = p.read_text()
    if text.startswith("---\n"):                       # tolerate a leading front-matter fence
        text = text[4:]
    head, _, body = text.partition("\n---\n")
    meta = {k.strip(): v.strip() for k, v in (line.split(":", 1) for line in head.splitlines() if ":" in line)}
    d = meta.get("default_repair", "")
    extra = {f: meta.get(f, "") for f in ("decisions", *FIELDS)}
    return Runbook(base, None if d in ("", "none") else d, body.strip(), **extra)


def for_findings(findings):
    out, seen = [], set()
    for f in findings:
        rb = load(f.id)
        if rb and rb.finding not in seen:
            seen.add(rb.finding); out.append(rb)
    return out


def for_repair(repair_id, finding_ids):
    """The runbook whose finding this repair clears (and that names it as its repair), if any. A repair that declares no
    finding (selinux-restorecon checks labels itself) is matched by the one runbook that names it."""
    for fid in sorted(finding_ids):
        rb = load(fid)
        if rb and rb.default_repair == repair_id:
            return rb
    named = [rb for rb in (load(i) for i in ids()) if rb and rb.default_repair == repair_id]
    return named[0] if len(named) == 1 else None
