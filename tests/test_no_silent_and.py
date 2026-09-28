"""Under `set -e`, a statement `a && b` does NOT stop the script when `a` fails (review finding I2). Lab scripts that
change systems must not use it as a statement. Allowed: conditions (if/while/until), lines guarded with `||`,
and `test && continue|break|return|exit|die …` shortcuts whose left side is a test, not an action."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "lab"
SCRIPTS = [p for d in ("srv1", "client", "host") for p in (ROOT / d).glob("*.sh") if not p.name.startswith("test_")] \
    + list(ROOT.glob("*.sh"))
# Left side is a test or a query: when it is false the right side is meant to be skipped, and a failing right side
# still stops the script (set -e ignores failures only BEFORE the last &&).
QUERY = re.compile(r"^\s*(\[\[.*?\]\]|\(\(.*?\)\)|\[ .*? \]|test |command -v |grep -q|[a-z|/ .-]*\| *grep -q)")


def offenders():
    bad = []
    for p in SCRIPTS:
        for n, line in enumerate(p.read_text().splitlines(), 1):
            code = line.split(" #")[0]
            code = re.sub(r"'[^']*'", "''", code)   # && inside single quotes (awk programs, trap strings) is not a statement here
            code = re.sub(r"\b(if|elif|while|until)\b.*?;\s*(then|do)\b", " ", code)   # && inside a condition is fine
            if "&&" not in code or code.lstrip().startswith("#") or "||" in code:
                continue
            if re.match(r"^\s*(if|elif|while|until|for)\b", code) or QUERY.match(code) or "grep -q" in code.split("&&")[0]:
                continue
            if re.search(r"\$\(cd .*&& pwd\)", code) and code.count("&&") == 1:
                continue   # here="$(cd … && pwd)" idiom
            bad.append(f"{p.relative_to(ROOT.parent)}:{n}: {line.strip()}")
    return bad


def test_no_bare_and_statements_in_lab_scripts():
    assert offenders() == []
