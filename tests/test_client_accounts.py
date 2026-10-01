import os
import re
import subprocess
from pathlib import Path

import pytest

C = Path(__file__).resolve().parents[1] / "appliance/rpm/chp-identity-client"


def diag(cmd, tmp_path):
    fake = tmp_path / "sudo"; fake.write_text('#!/bin/bash\necho "SUDO $*"\n'); fake.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin", "CHP_SUDO": str(fake)}
    if cmd is not None:
        env["SSH_ORIGINAL_COMMAND"] = cmd
    return subprocess.run(["bash", str(C / "diag-collect.sh")], env=env, capture_output=True, text=True)


@pytest.mark.parametrize("cmd,want", [
    (None, "SUDO -n /usr/sbin/idm-collect"),
    ("sudo -n /usr/sbin/idm-collect", "SUDO -n /usr/sbin/idm-collect"),
    ("sudo -n /usr/sbin/idm-collect --user lab09", "SUDO -n /usr/sbin/idm-collect --user lab09"),
    ("idm-collect --user ops_1", "SUDO -n /usr/sbin/idm-collect --user ops_1"),
])
def test_allowed_forms(tmp_path, cmd, want):
    r = diag(cmd, tmp_path)
    assert r.returncode == 0 and r.stdout.strip() == want


@pytest.mark.parametrize("cmd", [
    "bash", "sudo -n /usr/sbin/idm-collect --user 'x;id'", "idm-collect --user", "idm-collect --user a b",
    "sudo /usr/sbin/idm-collect", "/usr/bin/idm-collect", "idm-collect --json", "sudo -n /bin/sh",
    "idm-collect --user Root", "idm-collect --user $(id)", "idm-collect; id",
])
def test_everything_else_refused_and_sudo_never_runs(tmp_path, cmd):          # Review Focus 2
    r = diag(cmd, tmp_path)
    assert r.returncode == 1 and "SUDO" not in r.stdout and "refused" in r.stderr


def test_sshd_dropins():
    t10 = (C / "sshd-10-chp.conf").read_text()
    for line in ("PubkeyAuthentication yes", "KbdInteractiveAuthentication yes", "UsePAM yes",
                 "AuthenticationMethods publickey,keyboard-interactive:pam", "TrustedUserCAKeys /etc/ssh/chp_user_ca.pub"):
        assert line in t10.splitlines()
    t99 = (C / "sshd-99-chp-exceptions.conf").read_text()
    assert "Match User chpadmin,diag,chpcache" in t99 and "    AuthenticationMethods publickey" in t99
    assert "Match" not in t10


def test_accounts_script_pins_keys_and_exact_sudo():
    t = (C / "client-accounts.sh").read_text()
    assert 'from=\\"$CIP\\",command=\\"/usr/libexec/chp/diag-collect\\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding' in t
    assert 'from=\\"$SIP\\",command=\\"sudo -n /usr/sbin/kanidm-unix cache-invalidate\\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding' in t
    assert "diag ALL=(root) NOPASSWD: /usr/sbin/idm-collect, /usr/sbin/idm-collect --user *" in t
    assert "chpcache ALL=(root) NOPASSWD: /usr/sbin/kanidm-unix cache-invalidate" in t
    assert "%chp_admins ALL=(ALL) ALL" in t
    # every sudoers file goes through the ONE helper that runs visudo -cf before installing it
    assert "visudo -cf" in t.split("sudoers() {", 1)[1].split("\n}", 1)[0]
    assert len(re.findall(r"^\s*sudoers 6[0-2]-chp-", t, re.M)) == 3 and "> /etc/sudoers.d/" not in t
    assert subprocess.run(["bash", "-n", str(C / "client-accounts.sh")]).returncode == 0
