from pathlib import Path

import pytest

from chp_site import security as sec
from chp_site import wazuh as w
from chp_site.hosts import Host
from chp_site.sitefile import SiteError

FX = Path(__file__).parent / "fixtures" / "wazuh"
FPR_COLONS = f"pub:-:4096:1:96B3EE5F29111145:1470009600:1810339200::-:\nfpr:::::::::{w.WAZUH_FPR}:\n"


class Run:
    def __init__(self, fpr=FPR_COLONS, rules=""):
        self.calls, self.fpr, self.rules = [], fpr, rules

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        out = self.fpr if argv[:1] == ["gpg"] and "--show-keys" in argv else (self.rules if "--list-rich-rules" in argv else "")
        return type("R", (), {"returncode": 0, "stdout": out, "stderr": ""})()


def hosts():
    return [Host("aa:aa:aa:aa:aa:01", "srv1", "192.0.2.10", "server", "vda"),
            Host("aa:aa:aa:aa:aa:02", "ws1", "192.0.2.21", "client", "vda")]


def root(tmp_path, role):
    r = tmp_path / "root"
    (r / "var/ossec/etc").mkdir(parents=True)
    (r / "var/ossec/api/configuration").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg").mkdir(parents=True)
    (r / "etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH").write_text("key")
    (r / "etc/fstab").write_text("UUID=x / xfs defaults 0 0\n")
    (r / "var/ossec/etc/ossec.conf").write_text((FX / f"{'manager' if role == 'server' else 'agent'}-ossec.conf").read_text())
    return r


def enable(tmp_path, role, run=None, stick=None):
    r = root(tmp_path, role) if not (tmp_path / "root").exists() else tmp_path / "root"
    s = stick or (tmp_path / "stick"); s.mkdir(exist_ok=True)
    run = run or Run()
    done = sec.enable(role, "srv1" if role == "server" else "ws1", {"ALERT_HOOK": ""}, hosts(), stick=s, run=run,
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
    assert ["dnf", "--enablerepo=chp", "install", "-y", "wazuh-manager", "chp-security"] in run.calls
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
    sec.enable("server", "srv1", {"ALERT_HOOK": ""}, hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
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
    done = sec.enable("server", "srv1", {"ALERT_HOOK": ""}, hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
                      chown=lambda *a: None, record=lambda *a, **k: None, api=api, sleep=lambda x: None)
    assert set(api.changed) == {"1", "2"} and len(set(api.changed.values())) == 2
    assert any("API logins locked" in d for d in done)
    assert not any(pw in repr(done) for pw in api.changed.values())


def test_api_lock_is_idempotent(tmp_path):
    api = Api(defaults_work=False)                    # already locked by an earlier run
    r = root(tmp_path, "server"); s = tmp_path / "stick"; s.mkdir()
    done = sec.enable("server", "srv1", {"ALERT_HOOK": ""}, hosts(), stick=s, run=Run(), root=r, data_is_mount=False,
                      chown=lambda *a: None, record=lambda *a, **k: None, api=api, sleep=lambda x: None)
    assert api.changed == {} and any("already locked" in d for d in done)


def test_key_check_uses_a_private_gnupg_home(tmp_path):
    # final review I6: gpg --show-keys without GNUPGHOME created /root/.gnupg (an AIDE change after enable)
    run = Run()
    enable(tmp_path, "server", run=run)
    gpg = [c for c in run.calls if c[:1] == ["gpg"]]
    assert gpg and all("--homedir" in c for c in gpg)
