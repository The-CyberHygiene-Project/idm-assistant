"""Static checks on the chp-documents package (ISO 0.7.0 Plan 2 Task 4)."""
import os
import re
import subprocess
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-documents"
SPEC = (D / "chp-documents.spec").read_text().replace("%{_sysconfdir}", "/etc").replace("%{_prefix}", "/usr")


def t(n):
    return (D / n).read_text()


def test_egress_table_is_apache_only_loopback_and_server():
    n = t("nextcloud-egress.nft")
    assert 'meta skuid "apache"' in n and 'oifname "lo" accept' in n
    assert re.search(r"ip daddr \{ 127\.0\.0\.0/8, \$CHP_NC_SERVER_IP \} accept", n)
    assert re.search(r'th dport 53 log prefix "CHP-NC-EGRESS-DNS ".*reject', n)
    assert re.search(r'log prefix "CHP-NC-EGRESS " .*reject', n)
    assert 'include "/etc/chp/nextcloud-egress-addr.nft"' in n
    assert "@SERVER_IP@" not in n and not re.search(r"\b\d+\.\d+\.\d+\.\d+\b", re.sub(r"#.*", "", n).replace("127.0.0.0", ""))


def test_egress_unit_refuses_without_rendered_address_and_snapshots():
    u = t("chp-nextcloud-egress.service")
    assert "AssertPathExists=/etc/chp/nextcloud-egress-addr.nft" in u
    assert "Before=php-fpm.service httpd.service nextcloud-cron.service" in u
    assert "ExecStartPost=/usr/libexec/chp/nextcloud-egress-snapshot" in u


def test_bindsto_dropins_for_phpfpm_and_httpd():
    for f in ("nextcloud-bindsto.conf", "nextcloud-bindsto-httpd.conf"):
        c = t(f)
        assert "BindsTo=chp-nextcloud-egress.service" in c and "After=chp-nextcloud-egress.service" in c
        assert "ExecStartPre=/usr/sbin/nft list table inet chp_nextcloud_egress" in c
    assert "/etc/systemd/system/php-fpm.service.d/chp-egress.conf" in SPEC
    assert "/etc/systemd/system/httpd.service.d/chp-egress.conf" in SPEC
    cron = t("nextcloud-cron.service")
    assert "BindsTo=chp-nextcloud-egress.service" in cron and "ExecStartPre=/usr/sbin/nft list table" in cron


def test_httpd_listens_on_8443_only_and_fails_closed():
    c = t("nextcloud-httpd.conf")
    assert re.findall(r"^\s*Listen\s+(.*)$", c, re.M) == ["8443 https"]
    assert "Include /etc/httpd/conf.d/chp-nextcloud-lan.inc" in c and "Require all granted" not in c
    assert t("nextcloud-lan.inc").strip().splitlines()[-1] == "Require all denied"
    assert "/etc/pki/nextcloud/chain.pem" in c
    assert "nextcloud-httpd-stock-off" in t("nextcloud-bindsto-httpd.conf")


def test_stock_off_script_comments_listeners_idempotently(tmp_path):
    (tmp_path / "conf").mkdir(); (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf/httpd.conf").write_text("ServerRoot /etc/httpd\nListen 80\nIncludeOptional conf.d/*.conf\n")
    (tmp_path / "conf.d/ssl.conf").write_text("Listen 443 https\n<VirtualHost _default_:443>\n</VirtualHost>\n")
    env = dict(os.environ, CHP_HTTPD_ROOT=str(tmp_path))
    for _ in range(2):
        assert subprocess.run(["bash", str(D / "nextcloud-httpd-stock-off.sh")], env=env).returncode == 0
    for f in ("conf/httpd.conf", "conf.d/ssl.conf"):
        assert not re.search(r"^\s*Listen\b", (tmp_path / f).read_text(), re.M), f
    assert "ServerRoot" in (tmp_path / "conf/httpd.conf").read_text()
    assert "#CHP-off #CHP-off" not in (tmp_path / "conf/httpd.conf").read_text()


def test_backup_keeps_configured_days_and_includes_db_and_data(tmp_path):
    b = t("chp-nextcloud-backup")
    assert "DOCUMENTS_BACKUP_DAYS" in b and "pg_dump" in b and "$D/" in b and "/backup/nextcloud" in b
    assert "-mtime +\"$KEEP\"" in b
    conf = tmp_path / "c"
    def keep(content):
        conf.write_text(content)
        return subprocess.run(["bash", str(D / "chp-nextcloud-backup"), "keep-days"], capture_output=True, text=True,
                              env=dict(os.environ, CHP_DOCUMENTS_CONF=str(conf))).stdout.strip()
    assert keep("DOCUMENTS_BACKUP_DAYS=30\n") == "30" and keep("ENABLED=yes\n") == "14" and keep("DOCUMENTS_BACKUP_DAYS=x\n") == "14"


def test_cert_renew_opens_port_80_only_during_issue():
    s = t("cert-renew-nextcloud.sh")
    assert s.index("--add-service=http") < s.index("ca certificate") < s.index("--remove-service=http")
    assert "/etc/pki/nextcloud" in s and "FQDN" in s
    assert "ConditionPathExists=/etc/chp/documents.conf" in t("chp-nextcloud-cert-renew.service")


def test_fapolicyd_rule_shipped():
    r = t("65-chp-nextcloud.rules")
    assert "exe=/usr/sbin/php-fpm" in r and "dir=/data/nextcloud/data/" in r
    assert "/etc/fapolicyd/rules.d/65-chp-nextcloud.rules" in SPEC


def test_snapshot_and_check_79_normalise_identically():
    pat = "s/counter packets [0-9]+ bytes [0-9]+/counter/"
    assert pat in t("nextcloud-egress-snapshot.sh") and pat in (D / "monitor.d/79-nextcloud-egress.sh").read_text()


def test_no_file_references_the_internet():
    for f in D.rglob("*"):
        if f.is_file() and f.suffix not in (".rpm",) and f.name != "build-rpm.sh":
            txt = f.read_text()
            assert not re.search(r"https?://(?!github\.com/The-CyberHygiene)", txt), f.name
            assert not re.search(r"\b(apps\.nextcloud\.com|updates\.nextcloud|1\.1\.1\.1|8\.8\.8\.8)\b", txt), f.name


def test_monitor_checks_and_units_in_spec():
    for n in ("77-nextcloud-services.sh", "78-nextcloud-cert.sh", "79-nextcloud-egress.sh"):
        assert f"/usr/lib/chp/monitor.d/{n}" in SPEC.replace("%{_prefix}", "/usr")
    assert "Requires:" in SPEC and "nextcloud-chp" in SPEC and "Release:        1.chp%{?dist}" in SPEC
    for p in ("/etc/chp/nextcloud-egress-addr.nft", "/etc/httpd/conf.d/chp-nextcloud-lan.inc", "/etc/pki/nextcloud"):
        assert p in SPEC.split("%install")[0], p      # rendered paths documented in %description
    assert (D / "README.md").exists() and "CUI" in (D / "README.md").read_text()
