"""Static checks on the shipped aide.conf and the tailoring (core 0.2.0 Plan A)."""
import re
from pathlib import Path

TOP = Path(__file__).resolve().parents[1]
CONF = (TOP / "appliance/rpm/chp-integrity/aide.conf").read_text()
TAIL = (TOP / "lab/kickstart/dc2-reference/dc2-cui-tailoring.xml").read_text()
CHP = ["/etc/chp", "/etc/kanidm", "/etc/step-ca", "/etc/ssh-ca", "/etc/ssh/sshd_config.d", "/etc/authselect",
       "/etc/fapolicyd", "/etc/selinux", "/etc/idm-collect", "/etc/systemd/system", "/var/lib/ssh-ca/keys"]


def lines():
    return [l.split() for l in CONF.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def test_chp_paths_get_content_checks_before_the_etc_catch_all():
    ls = lines()
    etc = next(i for i, l in enumerate(ls) if l == ["/etc", "PERMS"])
    for p in CHP:
        i = next(i for i, l in enumerate(ls) if l[0] == p)
        assert i < etc and ls[i][1] == "CHPCONTENT", p


def test_no_non_fips_hash_in_any_used_group():
    used = {l[1].split("+")[0].split("-")[0] for l in lines() if l[0].startswith("/") and len(l) > 1}
    defs = {l[0]: " ".join(l[2:]) for l in lines() if len(l) > 2 and l[1] == "="}
    for g in used & defs.keys():
        assert not re.search(r"\b(md5|sha1|rmd160|tiger|crc32|haval|gost|whirlpool|stribog\w*)\b", defs[g]), g


def test_audit_tools_are_listed():
    for t in ("auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules"):
        assert re.search(rf"^/usr/sbin/{t}\s", CONF, re.M), t


def test_tailoring_selects_all_eight_aide_rules():
    for r in ("package_aide_installed", "aide_build_database", "aide_periodic_cron_checking", "aide_scan_notification",
              "aide_use_fips_hashes", "aide_check_audit_tools", "aide_verify_acls", "aide_verify_ext_attributes"):
        assert f'content_rule_{r}" selected="true"' in TAIL, r


def test_no_exclusions_yet_or_each_one_justified():
    ex = [l[0] for l in lines() if l[0].startswith("!")]
    justified = re.findall(r"^# EXCLUDE (\S+): .{20,}$", CONF, re.M)
    stock = {"!/usr/src", "!/usr/tmp", "!/root/.xauth*", "!/etc/mtab", "!/etc/.*~",
             "!/etc/NetworkManager/system-connections", "!/var/log/sa", "!/var/log/aide.log", "!/var/log/httpd",
             "!/boot/grub2/grubenv"}
    for e in ex:
        assert e in stock or e in justified, f"{e}: exclusions need a '# EXCLUDE <path>: reason' line (spec §4.4)"


SPEC = (TOP / "appliance/rpm/chp-integrity/chp-integrity.spec").read_text()


def test_spec_ships_every_file_and_requires_new_chp_site():
    for f in ("aide-check", "aide-baseline", "chp-aide-check.service", "chp-aide-check.timer",
              "chp-aide-baseline.service", "60-aide-result.sh", "61-aide-stale.sh", "62-aide-pin.sh"):
        assert f in SPEC, f
    assert "chp-site >= 0.7.0" in SPEC and "%triggerin -- aide" in SPEC and "installed-on-existing-host" in SPEC


def test_baseline_unit_does_not_hold_the_boot_target():
    u = (TOP / "appliance/rpm/chp-integrity/chp-aide-baseline.service").read_text()
    assert "Type=simple" in u and "ConditionPathExists=!/var/lib/aide/aide.db.gz" in u and "Restart=on-failure" in u


def test_repo_lists_and_pins_rocky_aide():
    pk = (TOP / "appliance/release/PACKAGES.txt").read_text()
    assert "\naide rocky\n" in pk and "\nchp-integrity ours" in pk
    assert "rocky9 RPM-GPG-KEY-Rocky-9" in (TOP / "appliance/release/trusted-keys.txt").read_text()
