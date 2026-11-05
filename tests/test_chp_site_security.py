import ipaddress
from pathlib import Path

import pytest

from chp_site import security as sec
from chp_site import suricata_conf as sc
from chp_site import wazuh as w
from chp_site.hosts import Host
from chp_site.sitefile import SiteError

FX = Path(__file__).parent / "fixtures" / "wazuh"
FPR_COLONS = f"pub:-:4096:1:96B3EE5F29111145:1470009600:1810339200::-:\nfpr:::::::::{w.WAZUH_FPR}:\n"
EPEL_COLONS = f"pub:-:4096:1:8A3872BF3228467C:1631033579:::-:\nfpr:::::::::{sec.EPEL_FPR}:\n"


class Run:
    def __init__(self, fpr=FPR_COLONS, rules="", epel=EPEL_COLONS):
        self.calls, self.fpr, self.rules, self.epel = [], fpr, rules, epel

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        out = self.fpr if argv[:1] == ["gpg"] and "--show-keys" in argv else (self.rules if "--list-rich-rules" in argv else "")
        if argv[:2] == ["ip", "-o"]:
            out = IP_ADDR
        if argv[:1] == ["gpg"] and argv[-1].endswith("RPM-GPG-KEY-EPEL-9"):
            out = self.epel
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()


IP_ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
           "2: enp1s0    inet 192.0.2.10/24 brd 192.0.2.255 scope global enp1s0\\       valid_lft forever\n"
           "3: enp2s0    inet 192.0.2.21/24 brd 192.0.2.255 scope global enp2s0\\       valid_lft forever\n")
SITE = {"ALERT_HOOK": "", "SUBNET": ipaddress.IPv4Network("192.0.2.0/24")}
INSTALL = ["chp-security", "yara", "chp-yara-rules", "suricata", "chp-suricata-rules"]


def hosts():
    return [Host("aa:aa:aa:aa:aa:01", "srv1", "192.0.2.10", "server", "vda"),
            Host("aa:aa:aa:aa:aa:02", "ws1", "192.0.2.21", "client", "vda")]


def root(tmp_path, role):
    r = tmp_path / "root"
    (r / "var/ossec/etc").mkdir(parents=True)
    (r / "var/ossec/api/configuration").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH").write_text("key")
    (r / "etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9").write_text("epel key")
    (r / "etc/fstab").write_text("UUID=x / xfs defaults 0 0\n")
    (r / "var/ossec/etc/ossec.conf").write_text((FX / f"{'manager' if role == 'server' else 'agent'}-ossec.conf").read_text())
    return r


def enable(tmp_path, role, run=None, stick=None):
    r = root(tmp_path, role) if not (tmp_path / "root").exists() else tmp_path / "root"
    s = stick or (tmp_path / "stick"); s.mkdir(exist_ok=True)
    run = run or Run()
    done = sec.enable(role, "srv1" if role == "server" else "ws1", dict(SITE), hosts(), stick=s, run=run,
                      root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None,
                      api=Api(), sleep=lambda x: None)
    return r, s, run, done


def test_server_enable_writes_hardened_config_keys_and_firewall(tmp_path):
    r, s, run, done = enable(tmp_path, "server")
    conf = (r / "var/ossec/etc/ossec.conf").read_text()
    assert w.setting(w.parse_conf(conf), "auth/disabled") == "yes"
    assert (r / "var/ossec/api/configuration/api.yaml").read_text() == w.API_YAML
    keys = (r / "var/ossec/etc/client.keys").read_text().split("\n")[0].split()
    assert keys[:3] == ["001", "ws1", "192.0.2.21"] and len(keys[3]) == 64
    assert (s / "wazuh/ws1.key").read_text().strip() == " ".join(keys)
    assert "/srv/wazuh /var/ossec none bind 0 0" in (r / "etc/fstab").read_text()
    assert any("--add-rich-rule" in " ".join(c) and "192.0.2.21/32" in " ".join(c) for c in run.calls)
    assert ["dnf", "--enablerepo=chp", "install", "-y", "wazuh-manager", *INSTALL] in run.calls
    assert "ROLE=server" in (r / "etc/chp/security.conf").read_text()


def test_second_enable_keeps_keys_and_adds_nothing_twice(tmp_path):
    r, s, run, _ = enable(tmp_path, "server")
    keys1 = (r / "var/ossec/etc/client.keys").read_text()
    rule = w.rich_rules(hosts())[0]
    r, s, run2, _ = enable(tmp_path, "server", run=Run(rules=rule + "\n"), stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == keys1
    assert (r / "etc/fstab").read_text().count("/var/ossec") == 1
    assert not any("--add-rich-rule" in c for c in run2.calls)


def test_client_enable_reads_its_key_from_the_stick(tmp_path):
    s = tmp_path / "stick"; (s / "wazuh").mkdir(parents=True)
    (s / "wazuh/ws1.key").write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    r, _, run, _ = enable(tmp_path, "client", stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == "001 ws1 192.0.2.21 " + "ab" * 32 + "\n"
    assert w.setting(w.parse_conf((r / "var/ossec/etc/ossec.conf").read_text()), "client/server/address") == "192.0.2.10"
    assert "agent.remote_conf=0" in (r / "var/ossec/etc/local_internal_options.conf").read_text()
    assert not any("firewall-cmd" in c for c in run.calls)


def test_client_without_its_key_on_the_stick_is_refused(tmp_path):
    with pytest.raises(SiteError, match="security enable on the server first"):
        enable(tmp_path, "client")


def test_wrong_key_fingerprint_refuses_before_any_change(tmp_path):
    bad = FPR_COLONS.replace(w.WAZUH_FPR, "0" * 40)
    with pytest.raises(SiteError, match="fingerprint"):
        enable(tmp_path, "server", run=Run(fpr=bad))
    assert not (tmp_path / "root/var/ossec/etc/client.keys").exists()


def test_keys_never_reach_the_audit_record(tmp_path):
    rec = []
    r = root(tmp_path, "server"); s = tmp_path / "stick"; s.mkdir()
    sec.enable("server", "srv1", dict(SITE), hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
               chown=lambda *a: None, record=lambda *a, **k: rec.append(a), api=Api(), sleep=lambda x: None)
    key = (r / "var/ossec/etc/client.keys").read_text().split()[3]
    assert rec and key not in repr(rec)


def test_existing_alert_level_is_kept(tmp_path):
    r = root(tmp_path, "server"); (r / "etc/chp").mkdir(parents=True)
    (r / "etc/chp/security.conf").write_text("ROLE=server\nALERT_LEVEL=12\nRETENTION_DAYS=180\nDATA_DIR=/srv/wazuh\n")
    enable(tmp_path, "server")
    t = (r / "etc/chp/security.conf").read_text()
    assert "ALERT_LEVEL=12" in t and "RETENTION_DAYS=180" in t


def test_status_reports_role_and_services(tmp_path):
    r, _, _, _ = enable(tmp_path, "server")
    out = sec.status(r, Run())
    assert "role: server" in out and "wazuh-manager" in out


def test_a_failing_step_is_a_clear_error_not_a_traceback(tmp_path):
    import subprocess
    class Fails(Run):
        def __call__(self, argv, **kw):
            if argv[:3] == ["systemctl", "enable", "--now"] and kw.get("check"):
                raise subprocess.CalledProcessError(1, argv)
            return super().__call__(argv, **kw)
    with pytest.raises(SiteError, match="systemctl enable --now wazuh-manager .* failed .*re-run chp-site security enable"):
        enable(tmp_path, "server", run=Fails())


# ---- final-review fix pass (W1) ----
class Api:
    """Fake Wazuh API: default logins work until the passwords are changed."""
    def __init__(self, defaults_work=True):
        self.defaults_work, self.changed = defaults_work, {}

    def __call__(self, method, path, user=None, token=None, body=None):
        if path.startswith("/security/user/authenticate"):
            ok = self.defaults_work and user in (("wazuh", "wazuh"), ("wazuh-wui", "wazuh-wui"))
            return (200, "tok") if ok else (401, "")
        if method == "PUT" and path.startswith("/security/users/") and token == "tok":
            self.changed[path.rsplit("/", 1)[1]] = body["password"]
            return 200, ""
        return 404, ""


def test_server_enable_locks_the_api_default_logins(tmp_path):
    # final review C1 (confirmed on the lab): default wazuh:wazuh / wazuh-wui:wazuh-wui gave any local user an
    # administrator token; enable replaces both with random passwords that are never stored or printed
    api = Api()
    r = root(tmp_path, "server"); s = tmp_path / "stick"; s.mkdir()
    done = sec.enable("server", "srv1", dict(SITE), hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
                      chown=lambda *a: None, record=lambda *a, **k: None, api=api, sleep=lambda x: None)
    assert set(api.changed) == {"1", "2"} and len(set(api.changed.values())) == 2
    assert any("API logins locked" in d for d in done)
    assert not any(pw in repr(done) for pw in api.changed.values())


def test_api_lock_is_idempotent(tmp_path):
    api = Api(defaults_work=False)                    # already locked by an earlier run
    r = root(tmp_path, "server"); s = tmp_path / "stick"; s.mkdir()
    done = sec.enable("server", "srv1", dict(SITE), hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
                      chown=lambda *a: None, record=lambda *a, **k: None, api=api, sleep=lambda x: None)
    assert api.changed == {} and any("already locked" in d for d in done)


def test_key_check_uses_a_private_gnupg_home(tmp_path):
    # final review I6: gpg --show-keys without GNUPGHOME created /root/.gnupg (an AIDE change after enable)
    run = Run()
    enable(tmp_path, "server", run=run)
    gpg = [c for c in run.calls if c[:1] == ["gpg"]]
    assert gpg and all("--homedir" in c for c in gpg)


# ---- security bundle W2: --firstboot ----
def repo(r):
    (r / "var/lib/chp/repo/repodata").mkdir(parents=True, exist_ok=True)
    (r / "var/lib/chp/repo/repodata/repomd.xml").write_text("<repomd/>")
def test_firstboot_server_writes_keys_to_pending_not_a_stick(tmp_path):
    r = root(tmp_path, "server"); pend = tmp_path / "pending"; repo(r)
    sec.enable("server", "srv1", {**SITE, "SECURITY_ALERT_LEVEL": 12}, hosts(), stick=None, pending=pend,
               run=Run(), root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None,
               api=Api(), sleep=lambda x: None)
    k = (pend / "wazuh" / "ws1.key")
    assert k.read_text().split()[:3] == ["001", "ws1", "192.0.2.21"]
    assert oct(k.stat().st_mode & 0o777) == "0o600" and oct((pend / "wazuh").stat().st_mode & 0o777) == "0o700"
    assert "ALERT_LEVEL=12" in (r / "etc/chp/security.conf").read_text()


def test_firstboot_client_reads_and_shreds_its_staged_key(tmp_path):
    r = root(tmp_path, "client"); kf = tmp_path / "agent.key"; repo(r)
    kf.write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=kf, run=Run(), root=r,
               data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None, sleep=lambda x: None)
    assert (r / "var/ossec/etc/client.keys").read_text().startswith("001 ws1 192.0.2.21 ")
    assert not kf.exists()


def test_firstboot_client_without_a_staged_key_is_refused(tmp_path):
    r = root(tmp_path, "client"); repo(r)
    with pytest.raises(SiteError, match="no staged Wazuh key"):
        sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=tmp_path / "none.key",
                   run=Run(), root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None)


def test_staged_key_must_be_this_hosts(tmp_path):
    r = root(tmp_path, "client"); kf = tmp_path / "agent.key"; repo(r)
    kf.write_text("002 ws2 192.0.2.22 " + "ab" * 32 + "\n")
    with pytest.raises(SiteError, match="not ws1's"):
        sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=kf, run=Run(), root=r,
                   data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None)
    assert kf.exists()                                  # refused before anything changed


def test_firstboot_without_a_local_repo_is_refused(tmp_path):
    # owner 2026-10-29: the ISO may be on another device; a network install copies no repo -> a clear refusal
    r = root(tmp_path, "server")
    with pytest.raises(SiteError, match="no local package repo"):
        sec.enable("server", "srv1", dict(SITE), hosts(), stick=None, pending=tmp_path / "p", run=Run(),
                   root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None, api=Api(),
                   sleep=lambda x: None)


def test_firstboot_client_waits_for_the_agents_first_sync(tmp_path):
    # W2 lab: the shared bundle arrived after AIDE's first baseline; first boot now waits for it (bounded)
    r = root(tmp_path, "client"); repo(r); kf = tmp_path / "agent.key"
    kf.write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    waits = []

    def sleep(s):
        waits.append(s)
        if len(waits) == 3:                              # the bundle arrives on the third poll
            (r / "var/ossec/etc/shared").mkdir(parents=True, exist_ok=True)
            (r / "var/ossec/etc/shared/merged.mg").write_text("x")
    done = sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=kf, run=Run(), root=r,
                      data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None, sleep=sleep)
    assert len(waits) == 3 and any("first sync" in d for d in done)


def test_firstboot_client_sync_wait_is_bounded(tmp_path):
    r = root(tmp_path, "client"); repo(r); kf = tmp_path / "agent.key"
    kf.write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    waits = []
    done = sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=kf, run=Run(), root=r,
                      data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None, sleep=waits.append)
    assert sum(waits) <= 130 and any("not synced yet" in d for d in done)


# ---- W2 final review I1: a failed client step must be retryable ----
def test_client_step_failing_after_key_install_can_be_retried(tmp_path):
    import subprocess
    r = root(tmp_path, "client"); repo(r); kf = tmp_path / "agent.key"
    kf.write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")

    class FailStart(Run):
        def __call__(self, argv, **kw):
            if argv[:3] == ["systemctl", "enable", "--now"] and kw.get("check"):
                raise subprocess.CalledProcessError(1, argv)
            return super().__call__(argv, **kw)
    with pytest.raises(SiteError):
        sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=kf, run=FailStart(), root=r,
                   data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None, sleep=lambda x: None)
    assert kf.exists()                                   # not shredded before the step succeeded
    sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=kf, run=Run(), root=r,
               data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None, sleep=lambda x: None)
    assert not kf.exists() and (r / "var/ossec/etc/client.keys").read_text().startswith("001 ws1 ")


def test_client_retry_uses_the_installed_key_when_the_staged_one_is_gone(tmp_path):
    r = root(tmp_path, "client"); repo(r)
    (r / "var/ossec/etc/client.keys").write_text("001 ws1 192.0.2.21 " + "cd" * 32 + "\n")
    done = sec.enable("client", "ws1", dict(SITE), hosts(), stick=None, key_file=tmp_path / "gone.key",
                      run=Run(), root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None,
                      sleep=lambda x: None)
    assert (r / "var/ossec/etc/client.keys").read_text() == "001 ws1 192.0.2.21 " + "cd" * 32 + "\n"
    assert any("started: wazuh-agent" in d for d in done)


def test_enable_installs_yara_and_starts_the_weekly_scan(tmp_path):
    r, s, run, done = enable(tmp_path, "server")
    assert ["dnf", "--enablerepo=chp", "install", "-y", "wazuh-manager", *INSTALL] in run.calls
    en = [c for c in run.calls if c[:3] == ["systemctl", "enable", "--now"]][0]
    assert "chp-yara-fullscan.timer" in en and "chp-yara-recent.timer" in en   # spec §10: every host
    rules = r / "var/ossec/etc/rules/chp_yara_rules.xml"
    assert rules.read_text() == w.YARA_RULES and oct(rules.stat().st_mode & 0o777) == "0o640"


def test_client_enable_starts_the_weekly_scan_but_writes_no_rules(tmp_path):
    s = tmp_path / "stick"; (s / "wazuh").mkdir(parents=True)
    (s / "wazuh/ws1.key").write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    r, _, run, _ = enable(tmp_path, "client", stick=s)
    en = [c for c in run.calls if c[:3] == ["systemctl", "enable", "--now"]][0]
    assert en[3:] == ["wazuh-agent", "chp-yara-fullscan.timer", "chp-yara-recent.timer", "suricata"]
    assert not (r / "var/ossec/etc/rules/chp_yara_rules.xml").exists()


def test_enable_rerun_on_an_enabled_server_keeps_keys_and_adds_yara(tmp_path):
    r, s, _, _ = enable(tmp_path, "server")
    (r / "var/ossec/etc/rules/chp_yara_rules.xml").unlink()                  # as on a host enabled before update1
    keys1 = (r / "var/ossec/etc/client.keys").read_text()
    r, s, run2, _ = enable(tmp_path, "server", run=Run(rules=w.rich_rules(hosts())[0] + "\n"), stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == keys1
    assert (r / "var/ossec/etc/rules/chp_yara_rules.xml").read_text() == w.YARA_RULES


def test_enable_creates_the_yara_log_before_wazuh_starts(tmp_path):
    # Y1 lab: Wazuh opens a log that appears later from its END, so the first YARA matches on a new host were lost
    r, s, run, _ = enable(tmp_path, "server")
    log = r / "var/log/chp-yara.json"
    assert log.exists() and log.read_text() == "" and oct(log.stat().st_mode & 0o777) == "0o640"
    first_start = next(i for i, c in enumerate(run.calls) if c[:3] == ["systemctl", "enable", "--now"])
    assert first_start > 0                                     # (the file is written before this call, by _enable)


# --- Suricata (S1, spec §3-§4) ---------------------------------------------------------------------------------------

def _units(run):
    return [c for c in run.calls if c[:3] == ["systemctl", "enable", "--now"]][0][3:]


def test_enable_writes_the_suricata_config_for_this_hosts_interface(tmp_path):
    r, _, _, _ = enable(tmp_path, "server")
    c = r / "etc/suricata/chp-suricata.yaml"
    assert c.read_text() == sc.config_text("enp1s0", "[192.0.2.0/24]") and oct(c.stat().st_mode & 0o777) == "0o640"
    assert (r / sc.DROPIN.lstrip("/")).read_text() == sc.dropin_text("enp1s0")
    assert (r / sc.SYSCONFIG.lstrip("/")).read_text() == sc.SYSCONFIG_TEXT


def test_client_uses_its_own_interface(tmp_path):
    s = tmp_path / "stick"; (s / "wazuh").mkdir(parents=True)
    (s / "wazuh/ws1.key").write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    r, _, run, _ = enable(tmp_path, "client", stick=s)
    assert "- interface: enp2s0" in (r / "etc/suricata/chp-suricata.yaml").read_text()
    assert not (r / "var/ossec/etc/rules/chp_suricata_rules.xml").exists()
    assert _units(run)[-1] == "suricata"


def test_server_writes_the_suricata_wazuh_rules_and_starts_suricata(tmp_path):
    r, _, run, _ = enable(tmp_path, "server")
    x = r / "var/ossec/etc/rules/chp_suricata_rules.xml"
    assert x.read_text() == w.SURICATA_RULES and oct(x.stat().st_mode & 0o777) == "0o640"
    assert _units(run)[-1] == "suricata"


def test_systemd_reloads_before_the_units_start_and_suricata_restarts(tmp_path):
    _, _, run, _ = enable(tmp_path, "server")
    i_reload = run.calls.index(["systemctl", "daemon-reload"])
    i_start = next(i for i, c in enumerate(run.calls) if c[:3] == ["systemctl", "enable", "--now"])
    assert i_reload < i_start and ["systemctl", "restart", "suricata"] in run.calls[i_start:]


def test_enable_creates_eve_before_the_units_start(tmp_path):
    r, _, _, _ = enable(tmp_path, "server")
    e = r / sc.EVE.lstrip("/")
    assert e.exists() and e.read_text() == "" and oct(e.stat().st_mode & 0o777) == "0o640"


def test_eve_content_is_kept_on_rerun(tmp_path):
    r, s, _, _ = enable(tmp_path, "server")
    (r / sc.EVE.lstrip("/")).write_text('{"event_type":"alert"}\n')
    enable(tmp_path, "server", run=Run(rules=w.rich_rules(hosts())[0] + "\n"), stick=s)
    assert (r / sc.EVE.lstrip("/")).read_text() == '{"event_type":"alert"}\n'


def test_rotation_replaces_epels_file_with_the_site_retention(tmp_path):        # one file: no duplicate-entry error
    r = root(tmp_path, "server"); (r / "etc/chp").mkdir(parents=True)
    (r / "etc/chp/security.conf").write_text("ROLE=server\nALERT_LEVEL=10\nRETENTION_DAYS=180\nDATA_DIR=/srv/wazuh\n")
    (r / "etc/logrotate.d").mkdir(parents=True); (r / "etc/logrotate.d/suricata").write_text("# EPEL sample\n")
    enable(tmp_path, "server")
    assert (r / "etc/logrotate.d/suricata").read_text() == sc.logrotate_text(180)
    assert sorted(p.name for p in (r / "etc/logrotate.d").iterdir()) == ["suricata"]


def test_rerun_keeps_client_keys_with_suricata(tmp_path):
    r, s, _, _ = enable(tmp_path, "server")
    keys1 = (r / "var/ossec/etc/client.keys").read_text()
    enable(tmp_path, "server", run=Run(rules=w.rich_rules(hosts())[0] + "\n"), stick=s)
    assert (r / "var/ossec/etc/client.keys").read_text() == keys1


def test_no_interface_for_this_host_refuses_before_any_change(tmp_path):     # Review Focus 1
    class NoIface(Run):
        def __call__(self, argv, **kw):
            res = super().__call__(argv, **kw)
            if argv[:2] == ["ip", "-o"]:
                res.stdout = IP_ADDR.splitlines()[0] + "\n"
            return res
    run = NoIface()
    with pytest.raises(SiteError, match="192.0.2.10"):
        enable(tmp_path, "server", run=run)
    assert not [c for c in run.calls if c[:1] in (["dnf"], ["systemctl"])]


def test_status_lists_suricata(tmp_path):
    r, _, _, _ = enable(tmp_path, "server")
    assert "suricata:" in sec.status(r, Run())


def test_epel_key_is_checked_and_imported_before_dnf(tmp_path):              # S1 lab: dnf refused suricata without it
    _, _, run, done = enable(tmp_path, "server")
    imp = run.calls.index(["rpm", "--import", str(tmp_path / "root/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9")])
    dnf = next(i for i, c in enumerate(run.calls) if c[:1] == ["dnf"])
    assert imp < dnf and any("EPEL 9" in d for d in done)


def test_wrong_epel_fingerprint_refuses_before_any_change(tmp_path):
    run = Run(epel=EPEL_COLONS.replace(sec.EPEL_FPR, "0" * 40))
    with pytest.raises(SiteError, match="EPEL 9 key fingerprint"):
        enable(tmp_path, "server", run=run)
    assert not [c for c in run.calls if c[:1] in (["dnf"], ["rpm"])]


def test_missing_epel_key_is_a_clear_error(tmp_path):
    r = root(tmp_path, "server"); (r / "etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9").unlink()
    with pytest.raises(SiteError, match="RPM-GPG-KEY-EPEL-9 is missing"):
        enable(tmp_path, "server")


def test_chp_site_ships_the_pinned_epel_key():
    top = Path(__file__).resolve().parents[1]
    spec = (top / "appliance/chp-site/chp-site.spec").read_text()
    assert "RPM-GPG-KEY-EPEL-9" in spec and "RPM-GPG-KEY-EPEL-9" in (top / "appliance/chp-site/build-rpm.sh").read_text()
    assert f"{sec.EPEL_FPR} epel9 RPM-GPG-KEY-EPEL-9" in (top / "appliance/release/trusted-keys.txt").read_text()
