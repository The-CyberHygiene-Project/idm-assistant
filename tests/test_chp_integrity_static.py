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
        want = "CHPCONTENT-c" if p == "/etc/fapolicyd" else "CHPCONTENT"   # owner 2026-10-20: fapolicyd resets ownership (ctime) at start
        assert i < etc and ls[i][1] == want, p


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
        assert e in stock or e[1:] in justified, f"{e}: exclusions need a '# EXCLUDE <path>: reason' line (spec §4.4)"


SPEC = (TOP / "appliance/rpm/chp-integrity/chp-integrity.spec").read_text()


def test_spec_ships_every_file_and_requires_new_chp_site():
    for f in ("aide-check", "aide-baseline", "chp-aide-check.service", "chp-aide-check.timer",
              "chp-aide-baseline.service", "60-aide-result.sh", "61-aide-stale.sh", "62-aide-pin.sh"):
        assert f in SPEC, f
    assert "chp-site >= 0.7.1" in SPEC and "%triggerin -- aide" in SPEC and "installed-on-existing-host" in SPEC


def test_baseline_unit_does_not_hold_the_boot_target():
    u = (TOP / "appliance/rpm/chp-integrity/chp-aide-baseline.service").read_text()
    assert "Type=simple" in u and "ConditionPathExists=!/var/lib/aide/aide.db.gz" in u and "Restart=on-failure" in u


def test_repo_lists_and_pins_rocky_aide():
    pk = (TOP / "appliance/release/PACKAGES.txt").read_text()
    assert "\naide rocky\n" in pk and "\nchp-integrity ours" in pk
    assert "rocky9 RPM-GPG-KEY-Rocky-9" in (TOP / "appliance/release/trusted-keys.txt").read_text()


def test_growing_logs_have_no_content_hash():
    # measured 2026-10-14 (lab/aide/MEASUREMENT.md): sha512 from the FIPS-hash rule made every log line a change;
    # AIDE takes the FIRST rule for an identical path, so the stock lines themselves carry -sha512
    rules = {l[0]: l[1] for l in lines() if l[0].startswith("/var/log") and len(l) > 1}
    assert rules["/var/log"] == "LOG-sha512"
    assert rules["/var/log/journal"] == "LOG-xattrs-n-sha512"
    assert rules["/var/log/audit"] == "PERMS-sha512"


def test_measured_exclusions_are_present_and_justified():
    ex = [l[0] for l in lines() if l[0].startswith("!")]
    for p in ("/etc/pki/kanidm", "/etc/step-ca/db", "/var/log/aide"):
        assert "!" + p in ex, p
        assert re.search(rf"^# EXCLUDE {re.escape(p)}: .*covered by", CONF, re.M), p
    # the CA's configuration and keys stay fully content-checked
    assert ["/etc/step-ca", "CHPCONTENT"] in lines()


def test_rotated_audit_logs_are_excluded_but_the_live_log_stays_watched():
    # quiet check 2026-10-16: rotation added /var/log/audit/audit.log.2 on client2 -> an alert per rotation (owner: exclude)
    ex = [l[0] for l in lines() if l[0].startswith("!")]
    assert r"!/var/log/audit/audit\.log\.[0-9]+$" in ex
    assert {l[0]: l[1] for l in lines() if len(l) > 1}["/var/log/audit"] == "PERMS-sha512"
    add = (TOP / "appliance/rpm/chp-integrity/chp-additions.conf").read_text()
    assert r"!/var/log/audit/audit\.log\.[0-9]+$" in add          # the source block and the shipped file agree


def test_escrow_staging_is_excluded_from_aide():
    # Plan B (owner 2026-10-18): export-client empties this AFTER the first-boot baseline, and /root NORMAL would
    # also keep SHA-512 hashes of the recovery secrets in the AIDE database. Covered by 40-escrow-pending.
    ex = [l[0] for l in lines() if l[0].startswith("!")]
    assert "!/root/chp-escrow-pending" in ex
    assert "!/root/chp-escrow-pending" in (TOP / "appliance/rpm/chp-integrity/chp-additions.conf").read_text()
    assert {l[0]: l[1] for l in lines() if len(l) > 1}["/root"] == "NORMAL"      # the rest of /root stays watched


def test_reboot_and_login_churn_is_not_an_alert():
    # Plan B gate 1 on rc1 (2026-10-20, reboot test on iso5-cli1): owner decisions 2026-10-20
    rules = {l[0]: l[1] for l in lines() if len(l) > 1 and l[0].startswith("/")}
    assert rules["/boot/efi"] == "NORMAL-i"                          # vfat: inode numbers regenerated at every mount
    assert rules["/boot"] == "NORMAL"                                # the rest of /boot unchanged
    assert rules["/var/lib/systemd/random-seed$"] == "PERMS-sha512"  # rewritten at every boot (stock: permissions only)
    assert rules["/var/log/lastlog$"] == "PERMS-sha512"              # every login (stock: permissions only)
    assert rules[r"/root/\.bash_history$"] == "PERMS-sha512"         # every root shell; other root dotfiles stay hashed
    assert rules[r"/root/\..*"] == "PERMS"
    assert rules["/etc/fapolicyd"] == "CHPCONTENT-c"                 # fapolicyd resets ownership at every start
    add = (TOP / "appliance/rpm/chp-integrity/chp-additions.conf").read_text()
    assert "/etc/fapolicyd CHPCONTENT-c" in add


def test_specific_rules_come_before_their_parents():
    # AIDE takes the first matching rule for an identical path; keep the specific lines first so a later
    # reordering cannot silently undo them (confirmed with aide --path-check in Plan B Task 5)
    order = [l[0] for l in lines() if l[0].startswith("/")]
    assert order.index("/boot/efi") < order.index("/boot")
    assert order.index(r"/root/\.bash_history$") < order.index(r"/root/\..*")
