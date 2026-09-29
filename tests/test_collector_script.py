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


def _memberof(j):
    lines = SCRIPT.read_text().splitlines()
    i, k = lines.index("# >>> json-helpers"), lines.index("# <<< json-helpers")
    sh = "\n".join(lines[i + 1:k]) + '\nmemberof_json "$1"'
    return subprocess.run(["sh", "-c", sh, "sh", j], capture_output=True, text=True, check=True).stdout


@pytest.mark.parametrize("j,want", [
    ('{"attrs":{"directmemberof":["a@x"],"memberof":["a@x","b_c@x"]}}', ["a@x", "b_c@x"]),
    ('{"attrs":{"memberof":[]}}', []),
    ('{"attrs":{"name":["lab01"]}}', None),                          # hidden by ACP: unknown, not "no groups"
    ('{"attrs":{"memberof":["a b@x"]}}', None),                      # unexpected characters
])
def test_memberof_is_a_list_or_unknown(j, want):
    import json
    assert json.loads(_memberof(j)) == want


def test_group_names_are_not_globbed():
    text = SCRIPT.read_text()
    assert "set -f" in text and "timeout 15 id -Gn" in text


def _parser(fn, *args):
    lines = SCRIPT.read_text().splitlines()
    i, k = lines.index("# >>> parsers"), lines.index("# <<< parsers")
    red = SCRIPT.parent / "redact.sed"
    h, e = lines.index("# >>> json-helpers"), lines.index("# <<< json-helpers")
    sh = f"REDACT={red}\n" + "\n".join(lines[h + 1:e] + lines[i + 1:k]) + f'\n{fn} "$@"'
    return subprocess.run(["sh", "-c", sh, "sh", *args], capture_output=True, text=True, check=True).stdout


CERT_L = """/var/lib/ssh-ca/issued/lab02-cert.pub:
        Type: ecdsa-sha2-nistp384-cert-v01@openssh.com user certificate
        Public key: ECDSA-CERT SHA256:abc
        Signing CA: ECDSA SHA256:fnyFGHP/iyOJEEzyd52gwSdf9GJuJZAEnS5z2hxGgmE (using ecdsa-sha2-nistp384)
        Key ID: "lab02-cert"
        Serial: 0
        Valid: from 2026-09-29T05:12:00 to 2026-09-29T13:13:05
        Principals: 
                lab02
                lab02@idm.kanidm.lab.test
        Critical Options: (none)
        Extensions: 
                permit-pty
"""


@pytest.mark.parametrize("j,want", [
    ('{"attrs":{"account_expire":["2026-09-29T11:00:53.490250633Z"],"name":["lab06"]}}', "2026-09-29T11:00:53Z"),
    ('{"attrs":{"name":["lab06"]}}', None),
    ('{"attrs":{"account_expire":["now; rm -rf /"]}}', None),
])
def test_validity_is_a_plain_utc_time_or_unknown(j, want):
    import json
    assert json.loads(_parser("validity_json", j, "account_expire")) == want


def test_cert_validity_and_principals_are_parsed():
    import json
    assert _parser("cert_validity", CERT_L).split() == ["2026-09-29T05:12:00", "2026-09-29T13:13:05"]
    assert _parser("cert_validity", "        Valid: forever\n").split() == ["-", "forever"]
    assert json.loads(_parser("principals_json", CERT_L)) == ["lab02", "lab02@idm.kanidm.lab.test"]


def test_restorecon_dry_run_becomes_types_only():
    import json
    out = ("Would relabel /run/kanidm-unixd/sock from system_u:object_r:var_run_t:s0 to "
           "system_u:object_r:kanidm_unixd_var_run_t:s0\n")
    assert json.loads(_parser("relabel_json", out)) == [
        {"path": "/run/kanidm-unixd/sock", "have": "var_run_t", "want": "kanidm_unixd_var_run_t"}]
    assert json.loads(_parser("relabel_json", "")) == []


def test_certificate_times_are_read_in_utc():
    # live 2026-09-29: srv1 is America/Denver; ssh-keygen -L prints zone-less LOCAL time and iso() (date -u -d) reads
    # a zone-less time as UTC, so validity came out 6 h early. ssh-keygen must print UTC.
    text = SCRIPT.read_text()
    assert 'TZ=UTC ssh-keygen -L' in text and 'cl=$(ssh-keygen -L' not in text


def test_an_unconvertible_certificate_time_is_emitted_as_null():
    text = SCRIPT.read_text()
    assert 'isoj()' in text and 'json_str "$(iso "$cf")"' not in text and 'json_str "$(iso "$ct")"' not in text
