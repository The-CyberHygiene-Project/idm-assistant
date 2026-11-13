"""Monitor checks 77-79 of the chp-documents package (fake systemctl / nft / openssl on PATH)."""
import os
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-documents"
M = D / "monitor.d"
NOW = 1_800_000_000
TABLE = ("table inet chp_nextcloud_egress {\n\tchain apache_out {\n\t\tlog prefix \"CHP-NC-EGRESS \" level warn flags skuid "
         "counter packets %d bytes %d reject\n\t}\n}\n")


def run(tmp, name, conf="ENABLED=yes\nFQDN=files.example.test\n", active="httpd php-fpm postgresql nextcloud-cron.timer",
        table=None, golden=None, cert=None, fresh=True, now=NOW):
    b = tmp / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text("#!/bin/bash\n" + f'case " {active} " in *" $3 "*) exit 0;; esac\nexit 3\n')
    nft = f"cat <<'EOF'\n{table}EOF\n" if table is not None else "exit 1\n"
    (b / "nft").write_text("#!/bin/bash\n" + nft)
    if cert:  # cert = (not_before, not_after) epochs; the fake openssl prints them as openssl does
        import time
        f = lambda t: time.strftime("%b %e %H:%M:%S %Y GMT", time.gmtime(t))
        (b / "openssl").write_text("#!/bin/bash\n" + f'echo "notBefore={f(cert[0])}"; echo "notAfter={f(cert[1])}"\n')
    for x in b.iterdir():
        x.chmod(0o755)
    c = tmp / "documents.conf"
    if conf is not None:
        c.write_text(conf)
    certp = tmp / "chain.pem"
    if cert is not None:
        certp.write_text("x")
    g = tmp / "golden"
    if golden is not None:
        g.write_text(golden)
    if not fresh:
        pass
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_DOCUMENTS_CONF=str(c), CHP_NC_CERT=str(certp),
               CHP_NC_GOLDEN=str(g), CHP_STATE_DIR=str(tmp / "state"), CHP_NOW=str(now),
               CHP_DOCS_LIB=str(D / "chp-documents-lib.sh"))
    r = subprocess.run(["bash", str(M / name)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_all_silent_ok_when_documents_off(tmp_path):
    for n in ("77-nextcloud-services.sh", "78-nextcloud-cert.sh", "79-nextcloud-egress.sh"):
        out = run(tmp_path, n, conf=None)
        assert out.startswith("OK") and "ALERT" not in out, n


def test_77_all_active_ok(tmp_path):
    assert run(tmp_path, "77-nextcloud-services.sh").startswith("OK")


def test_77_each_unit_down_alerts(tmp_path):
    for unit in ("httpd", "php-fpm", "postgresql", "nextcloud-cron.timer"):
        active = " ".join(u for u in "httpd php-fpm postgresql nextcloud-cron.timer".split() if u != unit)
        out = run(tmp_path / unit, "77-nextcloud-services.sh", active=active) if (tmp_path / unit).mkdir() is None else ""
        assert f"ALERT NextCloud: {unit} is not active" in out, unit


def test_77_alert_is_once_per_change_then_repeats_daily(tmp_path):
    a = "httpd php-fpm postgresql"
    assert "ALERT" in run(tmp_path, "77-nextcloud-services.sh", active=a)
    assert "ALERT" not in run(tmp_path, "77-nextcloud-services.sh", active=a, now=NOW + 3600)
    assert "ALERT" in run(tmp_path, "77-nextcloud-services.sh", active=a, now=NOW + 86400)
    assert run(tmp_path, "77-nextcloud-services.sh", now=NOW + 86500).startswith("OK")   # recovered: forgotten
    assert "ALERT" in run(tmp_path, "77-nextcloud-services.sh", active=a, now=NOW + 86600)


H = 3600
def test_78_cert_lifetime_relative(tmp_path):
    life = 24 * H   # step-ca ACME certificate, renewed at 8 h left (33 %)
    assert run(tmp_path, "78-nextcloud-cert.sh", cert=(NOW - 16 * H, NOW + 8 * H)).startswith("OK")
    out = run(tmp_path / "a" if (tmp_path / "a").mkdir() is None else tmp_path, "78-nextcloud-cert.sh", cert=(NOW - 20 * H, NOW + 4 * H))
    assert "ALERT NextCloud certificate" in out          # 4 h of 24 h left = 17 % < 25 %
    (tmp_path / "b").mkdir()
    assert "ALERT" in run(tmp_path / "b", "78-nextcloud-cert.sh", cert=(NOW - 30 * H, NOW - 6 * H))   # expired
    (tmp_path / "c").mkdir()
    out = run(tmp_path / "c", "78-nextcloud-cert.sh", cert=(NOW - 17 * H, NOW + 7 * H))              # 29 %: renewal window
    assert out.startswith("OK") and "renewal" in out


def test_78_long_lived_cert(tmp_path):
    day = 24 * H
    assert run(tmp_path, "78-nextcloud-cert.sh", cert=(NOW - 100 * day, NOW + 265 * day)).startswith("OK")
    (tmp_path / "d").mkdir()
    assert "ALERT" in run(tmp_path / "d", "78-nextcloud-cert.sh", cert=(NOW - 300 * day, NOW + 5 * day))


def test_78_missing_cert_alerts(tmp_path):
    assert "ALERT NextCloud certificate" in run(tmp_path, "78-nextcloud-cert.sh")


NORM = TABLE % (0, 0)


def test_79_intact_table_ok_even_as_counters_move(tmp_path):
    golden = "table inet chp_nextcloud_egress {\n\tchain apache_out {\n\t\tlog prefix \"CHP-NC-EGRESS \" level warn flags skuid counter reject\n\t}\n}\n"
    assert run(tmp_path, "79-nextcloud-egress.sh", table=TABLE % (7, 420), golden=golden).startswith("OK")


def test_79_missing_table_alerts(tmp_path):
    out = run(tmp_path, "79-nextcloud-egress.sh", table=None, golden="x\n")
    assert "ALERT NextCloud egress table chp_nextcloud_egress is missing" in out


def test_79_changed_rules_alert(tmp_path):
    golden = "table inet chp_nextcloud_egress {\n}\n"
    assert "ALERT NextCloud egress table chp_nextcloud_egress differs" in run(tmp_path, "79-nextcloud-egress.sh", table=TABLE % (0, 0), golden=golden)


def test_79_no_snapshot_alerts(tmp_path):
    assert "ALERT" in run(tmp_path, "79-nextcloud-egress.sh", table=TABLE % (0, 0), golden=None)
