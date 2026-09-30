import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "appliance/rpm/chp-identity-client"


def text(n):
    return (C / n).read_text()


def test_enrol_is_bash_strict_and_branded():
    t = text("client-enrol.sh")
    assert t.startswith("#!/bin/bash\n# CyberHygiene Project Lab Installer") and "set -Eeuo pipefail" in t
    assert subprocess.run(["bash", "-n", str(C / "client-enrol.sh")]).returncode == 0


def test_trust_is_pinned_and_rechecked():
    t = text("client-enrol.sh")
    assert 'step-cli ca root "$T/root.pem" --ca-url "https://$CA:9000" --fingerprint "$PIN" --force' in t
    assert "openssl x509 -in \"$T/root.pem\" -outform DER | sha256sum" in t
    assert re.search(r'\[ "\$got" = "\$PIN" \] \|\| \{ log "CHP: refusing', t)


def test_unixd_token_is_never_copied_or_printed():
    t = text("client-enrol.sh")
    assert "LoadCredential=unixd_token:/etc/kanidm/token" in t
    assert "cat /etc/kanidm/token" not in t and "echo \"$token" not in t


def test_authselect_rebuilt_from_the_recorded_original():
    t = text("client-enrol.sh")
    assert "/var/lib/chp/authselect-original" in t
    assert "authselect select custom/kanidm" in t and "--force" in t
    assert "LOST authselect feature" in t


def test_sshd_validated_before_reload_and_removed_on_failure():
    t = text("client-enrol.sh")
    i, j = t.index("sshd -t"), t.index("systemctl reload sshd")
    assert i < j and "rm -f /etc/ssh/sshd_config.d/10-chp.conf /etc/ssh/sshd_config.d/99-chp-exceptions.conf" in t


def test_lab_and_appliance_patchers_do_not_drift():
    lab = (ROOT / "lab/client/authselect_patch.py").read_text()
    app = (ROOT / "appliance/chp-site/chp_site/authselect.py").read_text()
    assert app.endswith(lab) and app.startswith("# CyberHygiene Project Lab Installer")
    assert not (C / "authselect_patch.py").exists()          # no loose Python in the client RPM (fapolicyd)


def test_enrol_patches_through_chp_site():
    assert "chp-site authselect-patch /etc/authselect/custom/kanidm" in text("client-enrol.sh")
    assert "authselect_patch" not in text("chp-identity-client.spec") and "authselect_patch" not in text("build-rpm.sh")


def test_selinux_module_is_the_lab_policy_renamed():
    te = text("selinux/chp_kanidm.te")
    assert "module chp_kanidm 1.0;" in te and "type kanidm_unixd_var_run_t;" in te
    assert "allow nsswitch_domain kanidm_unixd_var_run_t:sock_file { getattr write };" in te
    assert "/var/run/kanidm-unixd(/.*)?" in text("selinux/chp_kanidm.fc")


def test_monitors_print_ok_or_alert():
    for n in ("50-authselect.sh", "51-sshd.sh", "52-kanidm-tls.sh"):
        t = text(f"monitor.d/{n}")
        assert t.startswith("#!/bin/bash\n# CyberHygiene") and "ALERT " in t and "OK " in t
        assert subprocess.run(["bash", "-n", str(C / "monitor.d" / n)]).returncode == 0
    assert "authselect check" in text("monitor.d/50-authselect.sh")
    assert "sshd -T -C user=chp-monitor-probe" in text("monitor.d/51-sshd.sh")
    assert "curl -fsS --max-time 10 --cacert /etc/pki/ca-trust/source/anchors/chp-root.crt" in text("monitor.d/52-kanidm-tls.sh")


def test_spec_installs_policy_and_requires_the_stack():
    s = text("chp-identity-client.spec")
    for r in ("kanidm-unixd", "kanidm-clients", "idm-collect", "step-cli", "policycoreutils-python-utils", "chp-site", "chp-base"):
        assert re.search(rf"^Requires:\s+.*\b{re.escape(r)}\b", s, re.M), r
    assert "semodule -i %{_datadir}/selinux/packages/chp_kanidm.pp" in s
    assert "semodule -r chp_kanidm" in s and "Vendor:         The CyberHygiene Project" in s


def test_firstboot_unit_runs_enrol_once():
    u = text("chp-client-firstboot.service")
    assert "ConditionPathExists=!/var/lib/chp/firstboot/client.done" in u and "Environment=HOME=/root" in u
    assert "After=chp-firstboot-common.service network-online.target" in u
    assert "exec /usr/libexec/chp/client-enrol --role client" in text("client-firstboot.sh")


def test_fc_uses_a_raw_context_not_a_refpolicy_macro():          # proof finding: "Bad filecon declaration" at install
    fc = text("selinux/chp_kanidm.fc")
    assert "gen_context" not in fc
    # Rocky's file_contexts.subs_dist maps /run -> /var/run: a rule for /run/... never matches (proof finding 2)
    assert re.search(r"^/var/run/kanidm-unixd\(/\.\*\)\?\s+system_u:object_r:kanidm_unixd_var_run_t:s0$", fc, re.M)
    assert "semanage fcontext" not in text("chp-identity-client.spec")     # the module carries the context itself


def test_build_checks_the_compiled_filecon():
    b = text("build-rpm.sh")
    assert "/usr/libexec/selinux/hll/pp" in b and "kanidm_unixd_var_run_t" in b.split("hll/pp", 1)[1]
    assert 'filecon \\"/var/run/kanidm-unixd' in b


def test_systemd_may_manage_the_runtime_dir():        # proof finding 3: init_t denied remove_name/rmdir on unixd stop
    te = text("selinux/chp_kanidm.te")
    assert "allow init_t kanidm_unixd_var_run_t:dir { create getattr setattr search open read write add_name remove_name rmdir };" in te
    assert "allow init_t kanidm_unixd_var_run_t:sock_file { getattr setattr unlink };" in te
    assert "allow nsswitch_domain kanidm_unixd_var_run_t:sock_file { getattr write };" in te   # clients' use unchanged
