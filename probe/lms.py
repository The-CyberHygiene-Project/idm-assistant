"""Thin wrapper over LM Studio's `lms` CLI."""
import json
import os
import subprocess

LMS = os.path.expanduser("~/.lmstudio/bin/lms")


def loaded():
    out = subprocess.run([LMS, "ps", "--json"], capture_output=True, text=True, check=True).stdout
    return sorted(m.get("identifier", "") for m in json.loads(out or "[]"))


def unload_all():
    subprocess.run([LMS, "unload", "--all"], capture_output=True, check=True)


def load(model):
    subprocess.run([LMS, "load", model, "-y"], capture_output=True, check=True)
