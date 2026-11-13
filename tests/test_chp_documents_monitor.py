"""Monitor checks 77-79 of the chp-documents package (fake systemctl / nft / unshare / openssl on PATH)."""
import os
import subprocess
import time
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-documents"
M = D / "monitor.d"
NOW = 1_800_000_000
H, DAY = 3600, 86400
UNITS = "httpd php-fpm postgresql nextcloud-cron.timer"
ADDR = "define CHP_NC_SERVER_IP = 192.0.2.10\n"
CONF = "ENABLED=yes\nFQDN=files.example.test\nSERVER_IP=192.0.2.10\n"
EXPECTED = ('table inet chp_nextcloud_egress {\n\tchain apache_out {\n\t\tip daddr { 127.0.0.0/8, 192.0.2.10 } accept\n'
            '\t\tlog prefix "CHP-NC-EGRESS " level warn flags skuid counter packets %d bytes %d reject\n\t}\n}\n')


def run(tmp, name, conf=CONF, active=UNITS, live=None, expected=EXPECTED % (0, 0), addr=ADDR, cert=None,
        now=NOW, backup_status=None):
    """One monitor run in its own state under tmp (state persists across calls with the same tmp)."""
    b = tmp / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text("#!/bin/bash\n" + f'case " {active} " in *" $3 "*) exit 0;; esac\nexit 3\n')
    (b / "nft").write_text("#!/bin/bash\n" + (f"cat <<'EOF'\n{live}EOF\n" if live is not None else "exit 1\n"))
    # the fake unshare stands for "build the expected table from the files in a throwaway netns"
    (b / "unshare").write_text("#!/bin/bash\n" + (f"cat <<'EOF'\n{expected}EOF\n" if expected is not None else "exit 1\n"))
    if cert:
        f = lambda t: time.strftime("%b %e %H:%M:%S %Y GMT", time.gmtime(t))
        (b / "openssl").write_text("#!/bin/bash\n" + f'echo "notBefore={f(cert[0])}"; echo "notAfter={f(cert[1])}"\n')
    for x in b.iterdir():
        x.chmod(0o755)
    c = tmp / "documents.conf"
    if conf is not None:
        c.write_text(conf)
    a = tmp / "addr.nft"
    if addr is not None:
        a.write_text(addr)
    (tmp / "chain.pem").write_text("x") if cert else None
    st = tmp / "state"; st.mkdir(exist_ok=True)
    if backup_status is not None:
        (st / "backup.status").write_text(backup_status)
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_DOCUMENTS_CONF=str(c), CHP_NC_CERT=str(tmp / "chain.pem"),
               CHP_NC_ADDR=str(a), CHP_NC_NFT="/unused", CHP_NC_VALIDATE=str(D / "nextcloud-egress-validate.sh"),
               CHP_DOCS_STATE=str(st), CHP_NOW=str(now), CHP_DOCS_LIB=str(D / "chp-documents-lib.sh"))
    r = subprocess.run(["bash", str(M / name)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def fresh(tmp_path, n):
    d = tmp_path / n; d.mkdir(); return d


def test_all_silent_ok_when_documents_off(tmp_path):
    for n in ("77-nextcloud-services.sh", "78-nextcloud-cert.sh", "79-nextcloud-egress.sh"):
        out = run(fresh(tmp_path, n), n, conf=None)
        assert out.startswith("OK") and "ALERT" not in out, n


def test_77_all_active_ok(tmp_path):
    assert run(tmp_path, "77-nextcloud-services.sh").startswith("OK")


def test_77_each_unit_down_alerts(tmp_path):
    for unit in UNITS.split():
        out = run(fresh(tmp_path, unit), "77-nextcloud-services.sh", active=" ".join(u for u in UNITS.split() if u != unit))
        assert f"ALERT NextCloud: {unit} is not active" in out, unit


def test_77_suppressed_alert_never_prints_all_clear(tmp_path):
    a = "httpd php-fpm postgresql"
    assert "ALERT NextCloud: nextcloud-cron.timer is not active" in run(tmp_path, "77-nextcloud-services.sh", active=a)
    held = run(tmp_path, "77-nextcloud-services.sh", active=a, now=NOW + 3600)
    assert "ALERT" not in held
    assert "OK NextCloud: nextcloud-cron.timer is not active - still failing (alerted 2027-01-15T08:00:00Z)" in held
    assert "services (httpd" not in held                       # no false "services active"
    assert "ALERT" in run(tmp_path, "77-nextcloud-services.sh", active=a, now=NOW + DAY)
    assert run(tmp_path, "77-nextcloud-services.sh", now=NOW + DAY + 100).startswith("OK NextCloud services")   # recovered
    assert "ALERT" in run(tmp_path, "77-nextcloud-services.sh", active=a, now=NOW + DAY + 200)


def test_77_failed_backup_alerts(tmp_path):
    out = run(tmp_path, "77-nextcloud-services.sh", backup_status="FAILED 1 not enough space in /backup\n")
    assert "ALERT NextCloud backup failed: not enough space in /backup" in out
    assert run(fresh(tmp_path, "ok"), "77-nextcloud-services.sh", backup_status="OK 1 backup x\n").startswith("OK")


def test_78_cert_lifetime_relative(tmp_path):
    ok = run(fresh(tmp_path, "a"), "78-nextcloud-cert.sh", cert=(NOW - 16 * H, NOW + 8 * H))
    assert ok.startswith("OK")
    assert "ALERT NextCloud certificate" in run(fresh(tmp_path, "b"), "78-nextcloud-cert.sh", cert=(NOW - 20 * H, NOW + 4 * H))
    assert "ALERT" in run(fresh(tmp_path, "c"), "78-nextcloud-cert.sh", cert=(NOW - 30 * H, NOW - 6 * H))
    band = run(fresh(tmp_path, "d"), "78-nextcloud-cert.sh", cert=(NOW - 17 * H, NOW + 7 * H))
    assert band.startswith("OK") and "renewal overdue (ATTENTION; see daily review)" in band


def test_78_long_lived_cert(tmp_path):
    assert run(fresh(tmp_path, "a"), "78-nextcloud-cert.sh", cert=(NOW - 100 * DAY, NOW + 265 * DAY)).startswith("OK")
    assert "ALERT" in run(fresh(tmp_path, "b"), "78-nextcloud-cert.sh", cert=(NOW - 300 * DAY, NOW + 5 * DAY))


def test_78_missing_cert_alerts(tmp_path):
    assert "ALERT NextCloud certificate" in run(tmp_path, "78-nextcloud-cert.sh")


def test_78_suppressed_expired_alert_never_says_valid(tmp_path):
    cert = (NOW - 30 * H, NOW - 6 * H)
    assert "ALERT" in run(tmp_path, "78-nextcloud-cert.sh", cert=cert)
    held = run(tmp_path, "78-nextcloud-cert.sh", cert=cert, now=NOW + 3600)
    assert "ALERT" not in held and "still failing (alerted" in held and "valid" not in held


def test_79_intact_table_ok_even_as_counters_move(tmp_path):
    assert run(tmp_path, "79-nextcloud-egress.sh", live=EXPECTED % (7, 420)).startswith("OK")


def test_79_missing_table_alerts(tmp_path):
    assert "ALERT NextCloud egress table chp_nextcloud_egress is missing" in run(tmp_path, "79-nextcloud-egress.sh", live=None)


def test_79_live_table_edited_alerts(tmp_path):
    live = (EXPECTED % (0, 0)).replace("127.0.0.0/8, 192.0.2.10", "0.0.0.0/0")
    assert "ALERT NextCloud egress table chp_nextcloud_egress differs" in run(tmp_path, "79-nextcloud-egress.sh", live=live)


def test_79_shipped_file_changed_but_unit_not_reloaded_alerts(tmp_path):
    changed = (EXPECTED % (0, 0)).replace("192.0.2.10", "192.0.2.99")      # what the files now say
    assert "differs from the shipped rules" in run(tmp_path, "79-nextcloud-egress.sh", live=EXPECTED % (0, 0), expected=changed)


def test_79_cannot_build_expected_alerts(tmp_path):
    assert "ALERT NextCloud egress: cannot build the expected table" in run(tmp_path, "79-nextcloud-egress.sh",
                                                                           live=EXPECTED % (0, 0), expected=None)


def test_79_widened_or_extra_content_in_address_file_alerts(tmp_path):
    for n, addr in enumerate(("define CHP_NC_SERVER_IP = 0.0.0.0/0\n", ADDR + "table ip x {}\n", "define CHP_NC_SERVER_IP = 192.0.2.10, 0.0.0.0/0\n",
                              "define CHP_NC_SERVER_IP = 192.0.2.99\n", "define CHP_NC_SERVER_IP = 0.0.0.0\n", "\n")):
        out = run(fresh(tmp_path, str(n)), "79-nextcloud-egress.sh", live=EXPECTED % (0, 0), addr=addr)
        assert "ALERT NextCloud egress address file invalid" in out, addr


def test_79_server_ip_missing_from_documents_conf_alerts(tmp_path):
    out = run(tmp_path, "79-nextcloud-egress.sh", conf="ENABLED=yes\n", live=EXPECTED % (0, 0))
    assert "SERVER_IP is not set" in out
