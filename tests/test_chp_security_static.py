from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-security"
SPEC = (D / "chp-security.spec").read_text()


def test_spec_requires_and_files():
    assert "Version:        0.1.0" in SPEC and "Requires:       chp-site >= 0.8.0, chp-base" in SPEC
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
