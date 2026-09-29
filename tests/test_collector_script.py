import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "collector" / "idm-collect"


def _block():
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> redact-path"), lines.index("# <<< redact-path")
    return "\n".join(lines[i + 1:j])


def _redact_path(uid):
    sh = f'id() {{ echo {uid}; }}\nIDM_REDACT=/tmp/evil.sed\n{_block()}\necho "$REDACT"'
    return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()


def test_root_always_uses_the_installed_rules():
    assert _redact_path(0) == "/usr/local/sbin/idm-collect.redact.sed"


def test_non_root_may_point_at_test_rules():
    assert _redact_path(1000) == "/tmp/evil.sed"



def test_report_emits_the_client_sections():
    import re
    text = SCRIPT.read_text()
    for key in ("nss", "authselect", "user_nss", "source_offset_s", "memberof"):
        assert re.search(r'\\?"' + key + r'\\?":', text), key


def _source_offset(line):
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> source-offset"), lines.index("# <<< source-offset")
    sh = f"chronyc() {{ printf '%s\\n' 'MS Name/IP address Stratum Poll Reach LastRx Last sample' '{line}'; }}\n" \
         + "\n".join(lines[i + 1:j]) + '\necho "$soff"'
    return float(subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout)


import pytest  # noqa: E402


@pytest.mark.parametrize("line,want", [
    ("^* 192.168.100.1                10   6   377    12    -52us[  -58us] +/-  242us", -58e-6),
    ("^? 192.168.100.1                10   6   377     0   +600.0s[+600.0s] +/-  112us", 600.0),
    ("^* 192.168.100.1                10   6   377    40   +12ms[ +11ms] +/-  1ms", 0.011),
    ("^* 192.168.100.1                10   6   377    40   -3ns[   -4ns] +/-  1ns", -4e-9),
])
def test_source_offset_parses_chrony_units_and_padding(line, want):
    assert abs(_source_offset(line) - want) < 1e-6          # the collector prints microsecond precision


def _json_str(value):
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> json-helpers"), lines.index("# <<< json-helpers")
    red = SCRIPT.parent / "redact.sed"
    sh = f'REDACT={red}\n' + "\n".join(lines[i + 1:j]) + '\njson_str "$1"'
    return subprocess.run(["sh", "-c", sh, "sh", value], capture_output=True, text=True, check=True).stdout


@pytest.mark.parametrize("value", ["", "192.168.100.1", 'say "hi"\\there', "line1\nline2"])
def test_json_str_always_emits_a_valid_json_string(value):
    import json
    assert isinstance(json.loads(_json_str(value)), str)
