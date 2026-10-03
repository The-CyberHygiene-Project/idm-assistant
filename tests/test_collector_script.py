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
    assert _redact_path(0) == "/usr/share/idm-collect/redact.sed"


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


def _kanidm_url(conf_text, uid=1000):
    import tempfile, os
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> kanidm-url"), lines.index("# <<< kanidm-url")
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(conf_text)
    try:
        sh = f'id() {{ echo {uid}; }}\nIDM_COLLECT_CONF={f.name}\n' + "\n".join(lines[i + 1:j]) + '\necho "$KANIDM_URL"'
        return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()
    finally:
        os.unlink(f.name)


def test_kanidm_url_comes_from_the_config():
    assert _kanidm_url("KANIDM_URL=https://idm.example.test\n") == "https://idm.example.test"


def test_kanidm_url_allows_a_port():
    assert _kanidm_url("KANIDM_URL=https://idm.example.test:8443\n") == "https://idm.example.test:8443"


def test_kanidm_url_last_assignment_wins():
    assert _kanidm_url("KANIDM_URL=https://a.test\nKANIDM_URL=https://b.test\n") == "https://b.test"


import pytest


@pytest.mark.parametrize("bad", [
    "KANIDM_URL=http://idm.example.test",            # not TLS
    "KANIDM_URL=https://idm.example.test/v1",        # a path
    "KANIDM_URL=https://x.test;touch /tmp/pwn",      # shell metacharacters
    "KANIDM_URL=https://$(id).test",                 # command substitution text
    "KANIDM_URL=https://IDM.EXAMPLE.TEST",           # upper case: not the form we write
    "KANIDM_URL=",                                   # empty
    "",                                              # missing
])
def test_kanidm_url_rejects_anything_else(bad):
    assert _kanidm_url(bad + "\n") == ""


def test_root_always_reads_the_installed_config():
    # as root the installed config is used whatever the environment says (same rule as redact.sed)
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> kanidm-url"), lines.index("# <<< kanidm-url")
    sh = 'id() { echo 0; }\nIDM_COLLECT_CONF=/tmp/evil.conf\n' + "\n".join(lines[i + 1:j]) + '\necho "$CONF"'
    out = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "/etc/idm-collect/collect.conf"


def test_no_site_value_is_baked_in():
    assert "kanidm.lab.test" not in SCRIPT.read_text()


def test_shipped_script_carries_the_file_header():
    head = SCRIPT.read_text().splitlines()[1:4]
    assert head == [
        "# CyberHygiene Project Lab Installer — based on Rocky Linux 9.",
        "# Not an official Rocky Linux product.",
        "# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.",
    ]



def _conf_block(conf_text, echo):
    import tempfile, os
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> kanidm-url"), lines.index("# <<< kanidm-url")
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(conf_text)
    try:
        sh = f'id() {{ echo 1000; }}\nIDM_COLLECT_CONF={f.name}\n' + "\n".join(lines[i + 1:j]) + f'\necho "{echo}"'
        return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout.strip()
    finally:
        os.unlink(f.name)


def test_tls_target_defaults_to_port_443():
    assert _conf_block("KANIDM_URL=https://idm.example.test\n", "$KANIDM_HOSTPORT") == "idm.example.test:443"


def test_tls_target_keeps_an_explicit_port():
    assert _conf_block("KANIDM_URL=https://idm.example.test:8443\n", "$KANIDM_HOSTPORT") == "idm.example.test:8443"


def test_tls_target_is_empty_without_a_valid_url():
    assert _conf_block("KANIDM_URL=http://idm.example.test\n", "$KANIDM_HOSTPORT") == ""


def test_ca_anchor_comes_from_the_config():
    conf = "CA_ANCHOR=/etc/pki/ca-trust/source/anchors/site-root.crt\n"
    assert _conf_block(conf, "$CA_ANCHOR") == "/etc/pki/ca-trust/source/anchors/site-root.crt"


@pytest.mark.parametrize("bad", [
    "CA_ANCHOR=/etc/passwd",                                        # outside the anchors directory
    "CA_ANCHOR=/etc/pki/ca-trust/source/anchors/../../../shadow",   # traversal
    "CA_ANCHOR=/etc/pki/ca-trust/source/anchors/x;rm -rf /",        # shell metacharacters
    "CA_ANCHOR=",
    "",
])
def test_ca_anchor_rejects_anything_else(bad):
    assert _conf_block(bad + "\n", "$CA_ANCHOR") == ""


def _block_run(marker, prelude, echo=""):
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index(f"# >>> {marker}"), lines.index(f"# <<< {marker}")
    sh = 'err() { printf "ERR %s\\n" "$1"; }\n' + prelude + "\n" + "\n".join(lines[i + 1:j]) + (f'\necho "{echo}"' if echo else "")
    return subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout


def test_unusable_config_values_are_reported_as_config_errors():
    out = _block_run("config-errors", 'KANIDM_URL=""; CA_ANCHOR=""')
    assert "ERR collect.conf: KANIDM_URL missing or invalid" in out
    assert "ERR collect.conf: CA_ANCHOR missing or invalid" in out


def test_good_config_values_report_nothing():
    out = _block_run("config-errors", 'KANIDM_URL=https://idm.example.test; CA_ANCHOR=/etc/pki/ca-trust/source/anchors/x.crt')
    assert out == ""


def test_no_tls_probe_and_no_unreachable_error_without_a_usable_url():
    out = _block_run("tls", 'KANIDM_HOSTPORT=""; openssl() { echo PROBED; }; timeout() { shift; "$@"; }', "$tls")
    assert "PROBED" not in out and "could not fetch" not in out and out.strip() == "{}"


def test_trust_is_unknown_not_false_without_an_anchor():
    out = _block_run("trust", 'CA_ANCHOR=""', "$tr_ok")
    assert out.strip() == "null"


FAILLOCK_OUT = """lab04:
When                Type  Source                                           Valid
2026-10-03 14:00:01 RHOST 192.168.100.20                                       V
2026-10-03 14:01:02 TTY   tty1                                                 V
2026-10-03 14:02:03 SVC                                                        I
"""


def _faillock(out, conf="deny = 5\nunlock_time = 900\n", has_tool=True, user="lab04", tmp=None):
    import json as _j
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> json-helpers"), lines.index("# <<< json-helpers")
    k, m = lines.index("# >>> faillock"), lines.index("# <<< faillock")
    conf_path = tmp / "faillock.conf"
    conf_path.write_text(conf)
    out_path = tmp / "faillock.out"
    out_path.write_text(out)
    stub = (f'faillock() {{ cat "{out_path}"; }}\n' if has_tool else "")
    # The Mac's date is BSD (no -d): stand in for the two GNU forms the block uses, reading the faillock time as UTC.
    stub += ("date() { if [ \"$1\" = -d ]; then python3 -c 'import sys,calendar,time; print(calendar.timegm("
             "time.strptime(sys.argv[1], \"%Y-%m-%d %H:%M:%S\")))' \"$2\"; else python3 -c 'import sys,time; "
             "print(time.strftime(\"%Y-%m-%dT%H:%M:%SZ\", time.gmtime(int(sys.argv[1][1:]))))' \"$3\"; fi; }\n")
    sh = (f'REDACT={SCRIPT.parent / "redact.sed"}\nid() {{ echo 1000; }}\nuser={user}\nTZ=UTC; export TZ\n'
          f'FAILLOCK_CONF={conf_path}\n{stub}' + "\n".join(lines[i + 1:j]) + "\n"
          + ("" if has_tool else 'command() { return 1; }\n') + "\n".join(lines[k + 1:m]) + '\nprintf "%s" "$flk"')
    raw = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout
    return _j.loads(raw)


def test_faillock_parses_limit_lock_time_and_failures(tmp_path):
    f = _faillock(FAILLOCK_OUT, tmp=tmp_path)
    assert f["deny"] == 5 and f["unlock_time_s"] == 900
    assert f["failures"][0] == {"when": "2026-10-03T14:00:01Z", "type": "RHOST", "source": "192.168.100.20", "valid": True}
    assert f["failures"][1]["source"] == "tty1"
    assert f["failures"][2] == {"when": "2026-10-03T14:02:03Z", "type": "SVC", "source": "", "valid": False}


def test_faillock_defaults_when_unset(tmp_path):
    f = _faillock(FAILLOCK_OUT, conf="# deny = 4\n", tmp=tmp_path)
    assert f["deny"] == 3 and f["unlock_time_s"] == 600


def test_faillock_unlock_never_is_null(tmp_path):
    assert _faillock(FAILLOCK_OUT, conf="unlock_time = never\n", tmp=tmp_path)["unlock_time_s"] is None


def test_faillock_unknown_without_tool_or_user(tmp_path):
    assert _faillock(FAILLOCK_OUT, has_tool=False, tmp=tmp_path) is None
    assert _faillock(FAILLOCK_OUT, user="", tmp=tmp_path) is None


def test_faillock_time_is_read_as_local_and_printed_in_utc():
    # srv1 runs America/Denver (2026-09-29 lesson): faillock prints zone-less LOCAL time; reading it with `date -u -d`
    # would shift it by the zone offset. Read it as local (+%s), then print UTC.
    text = SCRIPT.read_text()
    assert 'fs=$(date -d "$fw" +%s' in text and 'date -u -d "@$fs"' in text and 'date -u -d "$fw"' not in text


def test_report_emits_faillock():
    assert '\\"faillock\\":' in SCRIPT.read_text() or '"faillock":' in SCRIPT.read_text()


def _name(tmp, role="client", hostport="idm.kanidm.lab.test:443", getent="192.168.100.10 STREAM idm.kanidm.lab.test\n",
          hosts="127.0.0.1 localhost\n", resolv="search kanidm.lab.test\nnameserver 192.168.100.10\n", curl_rc=0,
          hostname_i="192.168.100.10 fe80::1 "):
    import json as _j
    lines = SCRIPT.read_text().splitlines()
    i, j = lines.index("# >>> json-helpers"), lines.index("# <<< json-helpers")
    k, m = lines.index("# >>> name"), lines.index("# <<< name")
    (tmp / "hosts").write_text(hosts); (tmp / "resolv.conf").write_text(resolv); (tmp / "getent.out").write_text(getent)
    (tmp / "curl.args").write_text("")
    sh = (f'REDACT={SCRIPT.parent / "redact.sed"}\nid() {{ echo 1000; }}\nrole={role}\nKANIDM_HOSTPORT={hostport}\n'
          f'IDM_HOSTS_FILE={tmp / "hosts"}\nIDM_RESOLV_CONF={tmp / "resolv.conf"}\n'
          f'timeout() {{ shift; "$@"; }}\ngetent() {{ cat "{tmp / "getent.out"}"; }}\n'
          f'curl() {{ echo "$*" >> "{tmp / "curl.args"}"; return {curl_rc}; }}\nhostname() {{ echo "{hostname_i}"; }}\n'
          + "\n".join(lines[i + 1:j]) + "\n" + "\n".join(lines[k + 1:m]) + '\nprintf "%s|%s" "$nm" "$own"')
    out = subprocess.run(["sh", "-c", sh], capture_output=True, text=True, check=True).stdout
    nm, own = out.split("|")
    return _j.loads(nm), _j.loads(own), (tmp / "curl.args").read_text()


def test_name_from_dns_with_a_reachable_resolver(tmp_path):
    nm, own, curl = _name(tmp_path)
    assert nm == {"host": "idm.kanidm.lab.test", "addresses": ["192.168.100.10"], "source": "dns",
                  "resolvers": ["192.168.100.10"], "resolver_state": "answers"}
    assert own is None and "telnet://192.168.100.10:53" in curl


def test_name_from_the_hosts_file_including_an_alias(tmp_path):
    nm, _, _ = _name(tmp_path, hosts="192.168.100.99 other idm.kanidm.lab.test\n",
                     getent="192.168.100.99 STREAM other\n")
    assert nm["source"] == "files" and nm["addresses"] == ["192.168.100.99"]


def test_a_commented_hosts_line_does_not_count(tmp_path):
    nm, _, _ = _name(tmp_path, hosts="# 192.168.100.99 idm.kanidm.lab.test\n")
    assert nm["source"] == "dns"


def test_no_answer_and_resolver_states(tmp_path):
    for rc, state in ((0, "answers"), (7, "refused"), (28, "unreachable")):
        nm, _, _ = _name(tmp_path, getent="", curl_rc=rc)
        assert nm["addresses"] == [] and nm["source"] is None and nm["resolver_state"] == state


def test_no_resolver_is_unknown(tmp_path):
    nm, _, _ = _name(tmp_path, resolv="search x\n")
    assert nm["resolvers"] == [] and nm["resolver_state"] is None


def test_ipv6_resolver_is_bracketed(tmp_path):
    _, _, curl = _name(tmp_path, resolv="nameserver fd00::1\n")
    assert "telnet://[fd00::1]:53" in curl


def test_non_address_strings_are_dropped(tmp_path):
    nm, _, _ = _name(tmp_path, getent="SYSTEM: STREAM x\n192.168.100.10 STREAM y\n", resolv="nameserver evil;rm\n")
    assert nm["addresses"] == ["192.168.100.10"] and nm["resolvers"] == []


def test_no_url_means_unknown(tmp_path):
    nm, _, _ = _name(tmp_path, hostport="")
    assert nm is None


def test_server_reports_its_own_addresses(tmp_path):
    nm, own, _ = _name(tmp_path, role="server")
    assert nm is None and own == ["192.168.100.10", "fe80::1"]


def test_report_emits_name_and_own_addresses():
    text = SCRIPT.read_text()
    assert '"name":%s,"own_addresses":%s,' in text
