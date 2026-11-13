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


def test_egress_unit_refuses_without_valid_rendered_address():
    u = t("chp-nextcloud-egress.service")
    assert "AssertPathExists=/etc/chp/nextcloud-egress-addr.nft" in u
    assert "Before=php-fpm.service httpd.service nextcloud-cron.service" in u
    assert "ExecStartPre=/usr/libexec/chp/nextcloud-egress-validate" in u and "Snapshot" not in u


def test_httpd_lan_include_is_a_location_and_no_cgi_bin(tmp_path):
    c = t("nextcloud-httpd.conf")
    assert re.search(r'<Location "/">\s*Include /etc/httpd/conf.d/chp-nextcloud-lan.inc\s*</Location>', c)
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf/httpd.conf").write_text('ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"\n')
    subprocess.run(["bash", str(D / "nextcloud-httpd-stock-off.sh")], env=dict(os.environ, CHP_HTTPD_ROOT=str(tmp_path)), check=True)
    assert not re.search(r"^\s*ScriptAlias", (tmp_path / "conf/httpd.conf").read_text(), re.M)


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
    assert "/run/chp-acme.lock" in s and s.index("flock") < s.index("--add-service=http")
    assert "/run/chp-acme.lock" in (D.parent / "chp-identity-server/cert-renew-kanidm.sh").read_text()
    assert "refusing" in s and "$S/fqdn" in s
    assert s.index("--add-service=http") < s.index("ca certificate") < s.index("--remove-service=http")
    assert "/etc/pki/nextcloud" in s and "FQDN" in s
    assert "ConditionPathExists=/etc/chp/documents.conf" in t("chp-nextcloud-cert-renew.service")


def test_fapolicyd_rule_shipped():
    r = t("65-chp-nextcloud.rules")
    assert "ftype=" not in re.sub(r"#.*", "", r)
    assert "exe=/usr/sbin/php-fpm" in r and "dir=/data/nextcloud/data/" in r
    assert "/etc/fapolicyd/rules.d/65-chp-nextcloud.rules" in SPEC


def test_no_file_references_the_internet():
    for f in D.rglob("*"):
        if f.is_file() and f.suffix not in (".rpm",) and f.name != "build-rpm.sh":
            txt = f.read_text()
            assert not re.search(r"https?://(?!github\.com/The-CyberHygiene)", txt), f.name
            assert not re.search(r"\b(apps\.nextcloud\.com|updates\.nextcloud|1\.1\.1\.1|8\.8\.8\.8)\b", txt), f.name


def test_monitor_checks_and_units_in_spec():
    for n in ("77-nextcloud-services.sh", "78-nextcloud-cert.sh", "79-nextcloud-egress.sh", "81-documents-tags.sh"):
        assert f"/usr/lib/chp/monitor.d/{n}" in SPEC.replace("%{_prefix}", "/usr")
    assert "Requires:" in SPEC and "nextcloud-chp" in SPEC and "Release:        4.chp%{?dist}" in SPEC
    for p in ("/etc/chp/nextcloud-egress-addr.nft", "/etc/httpd/conf.d/chp-nextcloud-lan.inc", "/etc/pki/nextcloud"):
        assert p in SPEC.split("%install")[0], p      # rendered paths documented in %description
    assert (D / "README.md").exists() and "CUI" in (D / "README.md").read_text()


def test_spec_scriptlets_state_dir_and_backup_umask():
    assert "%systemd_post chp-nextcloud-egress.service" in SPEC and "%systemd_preun" in SPEC
    assert "%systemd_postun_with_restart chp-nextcloud-egress.service" in SPEC
    assert re.search(r"%triggerin -- httpd, mod_ssl\n.*nextcloud-httpd-stock-off", SPEC)
    assert "/var/lib/chp/documents" in SPEC.replace("%{_sharedstatedir}", "/var/lib") and "Release:        4.chp" in SPEC
    assert "UMask=0077" in t("chp-nextcloud-backup.service")
    assert "chmod 0700 \"$docs_sd\"" in t("chp-documents-lib.sh") and "/var/lib/chp/documents" in t("chp-documents-lib.sh")


def _backup(tmp, free_kb, stamps, name="backup", rsync_rc=0, partial=(), flock_rc=0):
    """Run chp-nextcloud-backup with fake occ/runuser/rsync/df/logger; returns (rc, out, calls)."""
    b = tmp / "bin"; b.mkdir(exist_ok=True)
    calls = tmp / "calls"
    (b / "occ").write_text("#!/bin/bash\necho occ \"$@\" >> " + str(calls) + "\n")
    (b / "runuser").write_text("#!/bin/bash\necho DUMP\n")
    (b / "rsync").write_text("#!/bin/bash\necho rsync \"$@\" >> " + str(calls) + "\nfor a; do last=$a; done; mkdir -p \"$last\"; echo f > \"$last/f\"\nexit " + str(rsync_rc) + "\n")
    (b / "df").write_text(f"#!/bin/bash\necho Filesystem; echo x 1 1 {free_kb} 1% /backup\n")
    (b / "logger").write_text("#!/bin/bash\nexit 0\n")
    (b / "flock").write_text(f"#!/bin/bash\nexit {flock_rc}\n")
    for x in b.iterdir():
        x.chmod(0o755)
    B = tmp / "backup"; B.mkdir(exist_ok=True)
    for st in stamps:
        (B / st / "data").mkdir(parents=True); (B / st / "data/f").write_text("x" * 4096)
        (B / st / "MANIFEST").write_text("m")
    for st in partial:   # a run killed before MANIFEST (SIGKILL skips the trap)
        (B / st / "data").mkdir(parents=True); (B / st / "data/f").write_text("x" * 4096)
    data = tmp / "data"; data.mkdir(exist_ok=True)
    conf = tmp / "c"; conf.write_text("DOCUMENTS_BACKUP_DAYS=14\n")
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_NC_BACKUP=str(B), CHP_NC_DATA=str(data), CHP_OCC=str(b / "occ"),
               CHP_DOCS_STATE=str(tmp / "st"), CHP_DOCUMENTS_CONF=str(conf))
    r = subprocess.run(["bash", str(D / "chp-nextcloud-backup"), name], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr, calls.read_text() if calls.exists() else ""


def test_backup_is_a_link_dest_incremental_of_the_previous_copy(tmp_path):
    rc, out, calls = _backup(tmp_path, 10**9, ["20260101T000000Z", "20260102T000000Z"])
    assert rc == 0, out
    assert f"--link-dest={tmp_path}/backup/20260102T000000Z/data" in calls
    assert (tmp_path / "st/backup.status").read_text().startswith("OK ")
    assert "occ maintenance:mode --off" in calls


def test_backup_prunes_oldest_when_space_is_short_but_keeps_two(tmp_path):
    rc, out, _ = _backup(tmp_path, 1, ["20260101T000000Z", "20260102T000000Z", "20260103T000000Z", "20260104T000000Z"])
    assert rc == 75 and "not enough space" in out
    left = sorted(p.name for p in (tmp_path / "backup").iterdir())
    assert left == ["20260103T000000Z", "20260104T000000Z"]                  # oldest pruned, never below 2
    assert (tmp_path / "st/backup.status").read_text().startswith("FAILED ")


def test_backup_with_enough_space_prunes_nothing(tmp_path):
    rc, out, _ = _backup(tmp_path, 10**9, ["20260101T000000Z", "20260102T000000Z", "20260103T000000Z"])
    assert rc == 0 and len(list((tmp_path / "backup").iterdir())) == 4


def test_backup_failure_midway_records_failed_and_leaves_no_partial_copy(tmp_path):
    rc, out, _ = _backup(tmp_path, 10**9, ["20260101T000000Z"], rsync_rc=23)
    assert rc != 0
    assert (tmp_path / "st/backup.status").read_text().startswith("FAILED ")
    assert [p.name for p in (tmp_path / "backup").iterdir()] == ["20260101T000000Z"]


def test_backup_ignores_and_deletes_a_killed_runs_partial_copy(tmp_path):
    # the newest dir has no MANIFEST: it is not the --link-dest base and is deleted at the start
    rc, out, calls = _backup(tmp_path, 10**9, ["20260101T000000Z", "20260102T000000Z"], partial=["20260103T000000Z"])
    assert rc == 0, out
    assert f"--link-dest={tmp_path}/backup/20260102T000000Z/data" in calls and "20260103T000000Z" not in calls
    assert "deleting the incomplete copy" in out
    left = sorted(p.name for p in (tmp_path / "backup").iterdir() if p.is_dir())
    assert left[:2] == ["20260101T000000Z", "20260102T000000Z"] and "20260103T000000Z" not in left and len(left) == 3
    assert all((tmp_path / "backup" / d / "MANIFEST").exists() for d in left)


def test_backup_partials_do_not_count_toward_min_keep(tmp_path):
    # two complete copies + two partials, no space: partials go first and the two complete copies are kept
    rc, out, _ = _backup(tmp_path, 1, ["20260101T000000Z", "20260102T000000Z"], partial=["20260103T000000Z", "20260104T000000Z"])
    assert rc == 75 and re.search(r"only +2 copies kept", out)
    left = sorted(p.name for p in (tmp_path / "backup").iterdir() if p.is_dir())
    assert left == ["20260101T000000Z", "20260102T000000Z"]


def test_backup_manifest_written_last_by_rename_and_single_run_lock(tmp_path):
    b = t("chp-nextcloud-backup")
    assert "> MANIFEST.tmp && mv MANIFEST.tmp MANIFEST" in b
    assert b.index('flock -n 9') < b.index('for d in $(partials)')
    rc, out, calls = _backup(tmp_path, 10**9, ["20260101T000000Z"], partial=["20260102T000000Z"], flock_rc=1)
    assert rc == 75 and "another backup is running" in out and calls == ""
    assert (tmp_path / "backup/20260102T000000Z").is_dir()   # a running backup's dir is never deleted


def test_readme_says_du_overestimates_hardlinked_incrementals():
    r = re.sub(r"\s+", " ", t("README.md"))
    assert "du -sk" in r and "overestimates" in r and "hardlink" in r


def test_nightly_check_timer_and_service():
    svc, tim = t("chp-documents-check.service"), t("chp-documents-check.timer")
    assert "ExecStart=/usr/bin/chp-site documents check" in svc and "Type=oneshot" in svc and "UMask=0077" in svc
    assert "ConditionPathExists=/etc/chp/documents.conf" in svc and "postgresql.service" in svc
    assert "OnCalendar=*-*-* 03:10:00" in tim                               # after the 01:40 backup (maintenance mode)
    # no catch-up run at boot: an out-of-window enable of chp-canary pages at 12 (Wazuh 100609); a missed night is
    # reported by check 81 as stale instead
    assert "Persistent=true" not in tim
    assert "ExecStopPost=/usr/bin/chp-site documents canary-off" in svc     # after a failure, timeout or kill too
    for u in ("chp-documents-check.service", "chp-documents-check.timer"):
        assert "%{_unitdir}/" + u in SPEC
    assert "%systemd_post chp-nextcloud-egress.service nextcloud-cron.timer chp-nextcloud-backup.timer " \
           "chp-nextcloud-cert-renew.timer chp-documents-check.timer" in SPEC
    assert re.search(r"^Requires:.*\bchp-site >= 0\.14\.0\b", SPEC, re.M)
