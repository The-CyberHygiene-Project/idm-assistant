from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-security"
SPEC = (D / "chp-security.spec").read_text()


def test_spec_requires_and_files():
    assert "Requires:       chp-site >= 0.12.0, chp-base" in SPEC                      # 0.3.0: + suricata (S1)
    for f in ("70-wazuh-service.sh", "71-wazuh-agents.sh", "72-wazuh-disk.sh", "chp-wazuh-alerts.service",
              "chp-wazuh-retention.timer", "wazuh-retention"):
        assert f in SPEC, f


def test_wazuh_units_wait_for_the_bind_mount():
    for f in ("wazuh-manager.override.conf", "wazuh-agent.override.conf"):
        assert "RequiresMountsFor=/var/ossec" in (D / f).read_text()


def test_forwarder_unit():
    u = (D / "chp-wazuh-alerts.service").read_text()
    assert "ExecStart=/usr/bin/chp-site wazuh-forward" in u and "Restart=always" in u and "After=wazuh-manager.service" in u


def test_retention_uses_the_site_period():
    s = (D / "wazuh-retention.sh").read_text()
    assert "RETENTION_DAYS" in s and "-mtime" in s and "/var/ossec/logs/alerts" in s and "-delete" in s


def test_aide_watches_wazuh_config_but_never_hashes_its_secrets():
    top = Path(__file__).resolve().parents[1] / "appliance/rpm/chp-integrity"
    for f in ("chp-additions.conf", "aide.conf"):               # the source block and the shipped file agree
        a = (top / f).read_text()
        assert "/var/ossec/etc CHPCONTENT" in a, f
        # final review (re-graded): anchored, but also covering suffixed copies (client.keys.chp-tmp, .bak, …)
        assert r"!/var/ossec/etc/client\.keys(\.[A-Za-z0-9_-]+)?$" in a, f
        assert r"!/var/ossec/etc/sslmanager\.(key|cert)(\.[A-Za-z0-9_-]+)?$" in a, f


def test_aide_checks_wazuh_shared_files_by_content_not_timestamps():
    # W2 lab: the manager rewrites etc/shared/ar.conf (same content) at every start; clients receive the shared bundle
    # at first connection. Content and permissions stay checked; mtime/ctime/inode do not.
    top = Path(__file__).resolve().parents[1] / "appliance/rpm/chp-integrity"
    for f in ("chp-additions.conf", "aide.conf"):
        a = (top / f).read_text()
        assert "CHPSHARED = p+u+g+s+acl+selinux+xattrs+sha512" in a and "/var/ossec/etc/shared CHPSHARED" in a, f


def test_yara_pieces_are_packaged():
    assert "Requires:       chp-site >= 0.12.0, chp-base, yara, chp-yara-rules" in SPEC
    for f in ("chp-yara-fullscan.service", "chp-yara-fullscan.timer", "73-yara-scan.sh"):
        assert f in SPEC, f
    assert "active-response/bin" not in SPEC                                  # spec §10: no Wazuh trigger, no wrapper


def test_weekly_scan_runs_at_low_priority():
    s = (D / "chp-yara-fullscan.service").read_text(); t = (D / "chp-yara-fullscan.timer").read_text()
    assert "ExecStart=/usr/bin/chp-site yara-scan --full" in s
    assert "Nice=19" in s and "IOSchedulingClass=idle" in s
    assert "OnCalendar=Sun *-*-* 03:30:00" in t and "Persistent=true" in t


def test_clients_scan_recent_files_every_five_minutes():                     # spec §10
    s = (D / "chp-yara-recent.service").read_text(); t = (D / "chp-yara-recent.timer").read_text()
    assert "ExecStart=/usr/bin/chp-site yara-scan --recent" in s and "Nice=19" in s and "IOSchedulingClass=idle" in s
    assert "OnUnitActiveSec=5min" in t and "OnBootSec=2min" in t
    assert "chp-yara-recent.service" in SPEC and "chp-yara-recent.timer" in SPEC


def test_scan_services_have_time_limits():                                            # final review I4
    assert "TimeoutStartSec=30min" in (D / "chp-yara-recent.service").read_text()
    assert "TimeoutStartSec=7h" in (D / "chp-yara-fullscan.service").read_text()


def test_suricata_pieces_are_packaged():                                               # S1
    assert "Version:        0.4.0" in SPEC
    # S1 lab: NOT required here. suricata is EPEL-signed; `dnf upgrade` would pull it before chp-site's enable has
    # imported the EPEL key, and the whole upgrade fails its GPG check. security enable installs both instead.
    req = [ln for ln in SPEC.splitlines() if ln.startswith("Requires:")]
    assert req == ["Requires:       chp-site >= 0.12.0, chp-base, yara, chp-yara-rules"]
    assert "74-suricata.sh" in SPEC and (D / "monitor.d" / "74-suricata.sh").exists()
    assert "74-suricata.sh" in (D / "build-rpm.sh").read_text()
    assert "logrotate.d/suricata" not in SPEC         # Suricata rotation = EPEL's file, rewritten by enable (RETENTION_DAYS)



def test_review_pieces_are_packaged():                                                 # R1
    assert "Version:        0.4.0" in SPEC and "Release:        2.chp%{?dist}" in SPEC
    for f in ("chp-review-record.service", "chp-review-record.timer", "chp-review-build.service",
              "chp-review-build.timer", "75-review.sh"):
        assert f in SPEC, f
        assert f in (D / "build-rpm.sh").read_text(), f
    rec, rect = (D / "chp-review-record.service").read_text(), (D / "chp-review-record.timer").read_text()
    assert "ExecStart=/usr/bin/chp-site review host-record --append" in rec and "Nice=19" in rec
    assert "OnBootSec=2min" in rect and "OnUnitActiveSec=10min" in rect
    b, bt = (D / "chp-review-build.service").read_text(), (D / "chp-review-build.timer").read_text()
    assert "ExecStart=/usr/bin/chp-site review build" in b and "TimeoutStartSec=30min" in b
    assert "OnCalendar=*-*-* 00:20:00" in bt and "Persistent=true" in bt


def test_review_requires_its_chp_site_and_rotates_its_log():               # final review I12, I11
    assert "Requires:       chp-site >= 0.12.0," in SPEC
    lr = (D / "chp-review.logrotate").read_text()
    assert "/var/log/chp-review.json" in lr and "copytruncate" in lr and "missingok" in lr and "rotate 7" in lr
    assert "chp-review.logrotate" in SPEC and "%{_sysconfdir}/logrotate.d/chp-review" in SPEC
    assert "chp-review.logrotate" in (D / "build-rpm.sh").read_text()
