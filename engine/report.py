"""Load and minimally validate an idm-report/1 document produced by collector/idm-collect."""
import json
from pathlib import Path

SCHEMA = "idm-report/1"
REQUIRED = ("schema", "host", "role", "collected_at")


def check_report(r):
    if not isinstance(r, dict) or r.get("schema") != SCHEMA:
        raise ValueError(f"not an {SCHEMA} report")
    missing = [k for k in REQUIRED if k not in r]
    if missing:
        raise ValueError(f"report missing {missing}")
    return r


def load_report(path):
    return check_report(json.loads(Path(path).read_text()))
