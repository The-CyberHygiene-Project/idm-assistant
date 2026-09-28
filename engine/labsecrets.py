"""Lab secrets live in ~/idm-lab-secrets only (0600). Helpers never print values."""
import json
import os
import secrets
from pathlib import Path

DIR = Path(os.path.expanduser("~/idm-lab-secrets"))


def path(name):
    return DIR / name


def write(name, text):
    p = path(name)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return p


def read_json(name):
    return json.loads(path(name).read_text())


def write_json(name, obj):
    return write(name, json.dumps(obj))


def new_password():
    return secrets.token_urlsafe(24)
