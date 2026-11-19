"""Monitor checks 77-79 of the chp-documents package (fake systemctl / nft / unshare / openssl on PATH)."""
import json
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
        now=NOW, backup_status=None, result=None, cron_result="success", lastcron="default", conf_age=DAY):
    """One monitor run in its own state under tmp (state persists across calls with the same tmp). cron_result: the
    last nextcloud-cron.service run (systemctl show -p Result); lastcron: NextCloud's core/lastcron (None = no row,
    "ERR" = the query fails); conf_age: seconds since documents.conf last changed."""
    b = tmp / "bin"; b.mkdir(exist_ok=True)
    (b / "systemctl").write_text("#!/bin/bash\n" + f'if [ "$1" = show ]; then echo "{cron_result}"; exit 0; fi\n'
                                 + f'case " {active} " in *" $3 "*) exit 0;; esac\nexit 3\n')
    lc = str(now - 300) if lastcron == "default" else lastcron
    (b / "runuser").write_text("#!/bin/bash\n" + f'echo "$*" >> {tmp}/runuser.calls\n'
                               + ("echo 'psql: error' >&2; exit 2\n" if lc == "ERR" else
                                  f"echo '{lc}'\n" if lc is not None else "exit 0\n"))
    # coreutils timeout (absent on the Mac that runs these tests): record it, run the command
    (b / "timeout").write_text("#!/bin/bash\n" + f'echo "$*" >> {tmp}/timeout.calls\nshift\nexec "$@"\n')
    (b / "nft").write_text("#!/bin/bash\n" + (f"cat <<'EOF'\n{live}EOF\n" if live is not None else "exit 1\n"))
    # the fake unshare stands for "build the expected table from the files in a throwaway netns"
    if expected is not None and expected.startswith("ERR:"):
        (b / "unshare").write_text("#!/bin/bash\n" + f"echo '{expected[4:]}' >&2; exit 1\n")
    else:
        (b / "unshare").write_text("#!/bin/bash\n" + (f"cat <<'EOF'\n{expected}EOF\n" if expected is not None else "exit 1\n"))
    if cert:
        f = lambda t: time.strftime("%b %e %H:%M:%S %Y GMT", time.gmtime(t))
        (b / "openssl").write_text("#!/bin/bash\n" + f'echo "notBefore={f(cert[0])}"; echo "notAfter={f(cert[1])}"\n')
    for x in b.iterdir():
        x.chmod(0o755)
    c = tmp / "documents.conf"
    if conf is not None:
        c.write_text(conf)
        os.utime(c, (now - conf_age, now - conf_age))
    a = tmp / "addr.nft"
    if addr is not None:
        a.write_text(addr)
    (tmp / "chain.pem").write_text("x") if cert else None
    st = tmp / "state"; st.mkdir(exist_ok=True)
    if backup_status is not None:
        (st / "backup.status").write_text(backup_status)
    if result is not None:
        (st / "check.json").write_text(result if isinstance(result, str) else json.dumps(result))
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}", CHP_DOCUMENTS_CONF=str(c), CHP_NC_CERT=str(tmp / "chain.pem"),
               CHP_NC_ADDR=str(a), CHP_NC_NFT="/unused", CHP_NC_VALIDATE=str(D / "nextcloud-egress-validate.sh"),
               CHP_DOCS_STATE=str(st), CHP_NOW=str(now), CHP_DOCS_LIB=str(D / "chp-documents-lib.sh"))
    r = subprocess.run(["bash", str(M / name)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def fresh(tmp_path, n):
    d = tmp_path / n; d.mkdir(); return d


def test_all_silent_ok_when_documents_off(tmp_path):
    for n in ("77-nextcloud-services.sh", "78-nextcloud-cert.sh", "79-nextcloud-egress.sh", "81-documents-tags.sh"):
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
    assert run(fresh(tmp_path, "ok"), "77-nextcloud-services.sh",
               backup_status=f"OK {NOW - 3600} backup x\n").startswith("OK")       # epoch: M2 checks the age


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
    out = run(tmp_path, "79-nextcloud-egress.sh", live=EXPECTED % (0, 0), expected=None)
    assert "ALERT NextCloud egress: the expected table could not be built" in out
    assert "broken?" not in out and "unshare -n / nft failed: no error output" in out and "not compared" in out


def test_79_cannot_build_expected_names_the_error(tmp_path):
    out = run(tmp_path, "79-nextcloud-egress.sh", live=EXPECTED % (0, 0), expected="ERR:unshare: unshare failed: Operation not permitted")
    assert "the expected table could not be built" in out and "Operation not permitted" in out


def test_79_widened_or_extra_content_in_address_file_alerts(tmp_path):
    for n, addr in enumerate(("define CHP_NC_SERVER_IP = 0.0.0.0/0\n", ADDR + "table ip x {}\n", "define CHP_NC_SERVER_IP = 192.0.2.10, 0.0.0.0/0\n",
                              "define CHP_NC_SERVER_IP = 192.0.2.99\n", "define CHP_NC_SERVER_IP = 0.0.0.0\n", "\n")):
        out = run(fresh(tmp_path, str(n)), "79-nextcloud-egress.sh", live=EXPECTED % (0, 0), addr=addr)
        assert "ALERT NextCloud egress address file invalid" in out, addr


def test_79_server_ip_missing_from_documents_conf_alerts(tmp_path):
    out = run(tmp_path, "79-nextcloud-egress.sh", conf="ENABLED=yes\n", live=EXPECTED % (0, 0))
    assert "SERVER_IP is not set" in out


# ---------- 81: the nightly tag check and share canary (result of chp-site documents check) ----------

def res(alerts=(), epoch=NOW - 3600, degraded=False):
    return {"version": 1, "epoch": epoch, "time": "x", "ok": not alerts, "degraded": degraded,
            "md5": "DEGRADED: database MD5 unavailable (folder moves/renames/deletes refused)" if degraded
            else "database MD5: available (folder moves, renames and deletes allowed)",
            "alerts": [{"key": k, "text": t} for k, t in alerts], "canary": {"public": "refused", "internal": "refused"}}


T81 = "81-documents-tags.sh"


def test_81_fresh_clean_result_ok(tmp_path):
    out = run(tmp_path, T81, result=res())
    assert out.startswith("OK") and "ALERT" not in out


def test_81_silent_ok_when_enable_has_not_finished(tmp_path):
    out = run(tmp_path, T81, conf="ENABLED=no\nFQDN=x\n")
    assert out.startswith("OK") and "ALERT" not in out


def test_81_each_failure_alerts_once_then_again_after_24h(tmp_path):
    one = res([("untagged:47", "file CUI/a.docx (id 47) in team folder CUI has no CUI tag")])
    out = run(tmp_path, T81, result=one)
    assert "ALERT NextCloud check: file CUI/a.docx (id 47) in team folder CUI has no CUI tag" in out
    held = run(tmp_path, T81, result=one, now=NOW + 3600)
    assert "ALERT" not in held and "still failing (alerted 2027-01-15T08:00:00Z)" in held
    assert "NextCloud check OK" not in held                              # never a false all-clear
    two = res([("untagged:47", "file CUI/a.docx (id 47) in team folder CUI has no CUI tag"),
               ("canary:public", "share canary: a public link on the CUI canary file was CREATED")])
    out = run(tmp_path, T81, result=two, now=NOW + 7200)
    assert out.count("ALERT") == 1 and "ALERT NextCloud check: share canary" in out       # only the new one
    assert "ALERT" in run(tmp_path, T81, result=one, now=NOW + DAY + 10)
    assert run(tmp_path, T81, result=res(), now=NOW + DAY + 20).startswith("OK")
    assert "ALERT" in run(tmp_path, T81, result=one, now=NOW + DAY + 30)  # recovered, then failing again: new


def test_81_missing_or_broken_result_alerts(tmp_path):
    assert "ALERT NextCloud check: no result" in run(fresh(tmp_path, "a"), T81, conf_age=27 * H)
    assert "ALERT NextCloud check: no result" in run(fresh(tmp_path, "b"), T81, result="{not json")
    assert "ALERT NextCloud check: no result" in run(fresh(tmp_path, "c"), T81, result="{not json", conf_age=600)


def test_81_result_older_than_26h_alerts(tmp_path):
    assert "ALERT" not in run(fresh(tmp_path, "a"), T81, result=res(epoch=NOW - 25 * H))
    out = run(fresh(tmp_path, "b"), T81, result=res(epoch=NOW - 27 * H))
    assert "ALERT NextCloud check: last result is 27 h old" in out


def test_81_degraded_is_shown_not_alerted(tmp_path):
    out = run(tmp_path, T81, result=res(degraded=True))
    assert "ALERT" not in out and "DEGRADED: database MD5 unavailable" in out


def test_81_text_from_the_result_is_cleaned(tmp_path):
    out = run(tmp_path, T81, result=res([("untagged:9", "evil\x1b[31m\nALERT forged")]))
    assert "\x1b" not in out and not any(x.startswith("ALERT forged") for x in out.splitlines())
    assert len([x for x in out.splitlines() if x.startswith("ALERT")]) == 1


# ---- Task 9d, D11: check 77 also sees background jobs that do not run (the timer alone said OK) ----
def test_77_failed_cron_run_alerts(tmp_path):
    out = run(tmp_path, "77-nextcloud-services.sh", cron_result="exit-code")
    assert "ALERT NextCloud: the last nextcloud-cron.service run failed (exit-code)" in out


def test_77_stale_or_missing_lastcron_alerts(tmp_path):
    out = run(fresh(tmp_path, "stale"), "77-nextcloud-services.sh", lastcron=str(NOW - 3 * H))
    assert "ALERT NextCloud: background jobs last ran 2027-01-15T05:00:00Z" in out and "cron.php" in out
    out = run(fresh(tmp_path, "never"), "77-nextcloud-services.sh", lastcron="0")
    assert "ALERT NextCloud: background jobs have never run" in out
    out = run(fresh(tmp_path, "norow"), "77-nextcloud-services.sh", lastcron=None)
    assert "ALERT NextCloud: background jobs have never run" in out


def test_77_never_run_is_not_alerted_right_after_enable(tmp_path):
    assert run(tmp_path, "77-nextcloud-services.sh", lastcron=None, conf_age=600).startswith("OK NextCloud services")


def test_77_recent_lastcron_and_success_is_ok(tmp_path):
    out = run(tmp_path, "77-nextcloud-services.sh", lastcron=str(NOW - 600))
    assert out.startswith("OK NextCloud services") and "background jobs" in out


def test_77_unreadable_lastcron_alerts(tmp_path):
    out = run(tmp_path, "77-nextcloud-services.sh", lastcron="ERR")
    assert "ALERT NextCloud: cannot read when background jobs last ran" in out


def test_77_lastcron_not_checked_while_enable_has_not_finished(tmp_path):
    out = run(tmp_path, "77-nextcloud-services.sh", conf=CONF.replace("ENABLED=yes", "ENABLED=no"), lastcron=None)
    assert "ALERT" not in out


# ---- Plan 3 Task 1: final review M1, M2; Task 9d review minors 4, 5 ----
def test_81_pending_first_run_after_enable(tmp_path):
    """M1: after enable there is no result until the first 03:10 run: OK "pending first run", not an ALERT, while
    documents.conf is younger than 26 h (enable writes it); after that, no result alerts as before."""
    out = run(fresh(tmp_path, "new"), T81, conf_age=600)
    assert "ALERT" not in out and out.startswith("OK NextCloud check: pending first run")
    out = run(fresh(tmp_path, "day"), T81, conf_age=25 * H)
    assert "ALERT" not in out and "pending first run" in out
    assert "ALERT NextCloud check: no result" in run(fresh(tmp_path, "late"), T81, conf_age=27 * H)


def test_77_stale_backup_alerts(tmp_path):
    """M2: a backup timer that is off or never fires leaves an old OK status: older than 26 h alerts; no status at all
    alerts once documents.conf is that old (a fresh enable waits for the first 01:40 run)."""
    out = run(fresh(tmp_path, "old"), "77-nextcloud-services.sh", backup_status=f"OK {NOW - 27 * H} backup x\n")
    assert "ALERT NextCloud backup: the last backup ran 2027-01-14T05:00:00Z (more than 26 h ago" in out
    assert run(fresh(tmp_path, "ok"), "77-nextcloud-services.sh",
               backup_status=f"OK {NOW - 3 * H} backup x\n").startswith("OK NextCloud services")
    out = run(fresh(tmp_path, "never"), "77-nextcloud-services.sh", conf_age=27 * H)
    assert "ALERT NextCloud backup: no backup has run" in out
    assert run(fresh(tmp_path, "fresh"), "77-nextcloud-services.sh", conf_age=600).startswith("OK NextCloud services")
    out = run(fresh(tmp_path, "junk"), "77-nextcloud-services.sh", backup_status="OK notanumber x\n")
    assert "ALERT NextCloud backup: cannot read" in out


def test_77_psql_has_no_psqlrc_and_a_timeout(tmp_path):
    """9d minor 4: psql -X (as documents.py) and a timeout: a wedged PostgreSQL must not hang the monitor run."""
    run(tmp_path, "77-nextcloud-services.sh")
    rc = (tmp_path / "runuser.calls").read_text()
    assert " psql -d nextcloud -qtAXc " in rc
    assert (tmp_path / "timeout.calls").read_text().split()[0].isdigit()


def test_77_each_cron_state_has_its_own_key(tmp_path):
    """9d minor 4: "never ran", "cannot read" and "stale" are different keys: a switch from one to another alerts at
    once, not 24 h later."""
    assert "ALERT NextCloud: background jobs have never run" in run(tmp_path, "77-nextcloud-services.sh", lastcron="0")
    out = run(tmp_path, "77-nextcloud-services.sh", lastcron=str(NOW + 600 - 3 * H), now=NOW + 600)
    assert "ALERT NextCloud: background jobs last ran" in out
    out = run(tmp_path, "77-nextcloud-services.sh", lastcron="ERR", now=NOW + 1200)
    assert "ALERT NextCloud: cannot read when background jobs last ran" in out


def test_77_postgresql_down_is_one_alert(tmp_path):
    """9d minor 5: PostgreSQL down: one alert naming the cause, not a second one for the lastcron query."""
    out = run(tmp_path, "77-nextcloud-services.sh", active="httpd php-fpm nextcloud-cron.timer", lastcron="ERR")
    assert out.count("ALERT") == 1 and "ALERT NextCloud: postgresql is not active" in out
    assert not (tmp_path / "runuser.calls").exists()
