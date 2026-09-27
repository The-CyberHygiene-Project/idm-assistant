"""Thin wrapper over LM Studio's `lms` CLI."""
import json
import os
import subprocess

LMS = os.path.expanduser("~/.lmstudio/bin/lms")


def _ps():
    out = subprocess.run([LMS, "ps", "--json"], capture_output=True, text=True, check=True).stdout
    return json.loads(out or "[]")


def loaded():
    return sorted(m.get("identifier", "") for m in _ps())


def contexts():
    """identifier -> context length actually in effect (recorded in the report)."""
    return {m.get("identifier", ""): m.get("contextLength") for m in _ps()}


def unload_all():
    subprocess.run([LMS, "unload", "--all"], capture_output=True, check=True)


def load(model, context=None):
    args = [LMS, "load", model] + (["-c", str(context)] if context else []) + ["-y"]
    subprocess.run(args, capture_output=True, check=True)
