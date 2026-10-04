"""Tests for the gate (THROWAWAY spike, but it writes files as root on a lab VM, so its revert and logging are tested)."""
import base64
import hashlib
import re
import shlex

from gate import Gate, Log, verify


class FakeHost:
    """A tiny root shell: files in a dict; understands exactly the commands the gate sends."""

    BANNER = "\\S\nKernel \\r on \\m"            # client2's ssh stderr banner, mixed into every output

    def __init__(self, files, banner=False, dirs=()):
        self.files = dict(files)
        self.dirs = set(dirs)
        self.ran = []
        self.banner = banner

    def __call__(self, cmd):
        rc, out = self._run(cmd)
        return rc, (out + "\n" + self.BANNER).strip() if self.banner else out

    def _run(self, cmd):
        self.ran.append(cmd)
        if "\n" in cmd and "base64 -d >" in cmd:        # what bash did on client2: the line split, the redirect truncated
            self.files[cmd.rsplit("> ", 1)[1].strip("'")] = ""
            return 127, "command not found"
        w = shlex.split(cmd)
        if cmd.startswith(("if [ -e ", "if [ -f ")):
            p = w[3]
            if p in self.dirs:                           # real bash: [ -e dir ] is true, base64 of a dir prints nothing
                return 0, "__NOTFILE__" if cmd.startswith("if [ -f ") else "<<B64\n\nB64>>"
            body = base64.b64encode(self.files[p].encode()).decode() if p in self.files else "__ABSENT__"
            return 0, (f"<<B64\n{body}\nB64>>" if "<<B64" in cmd else body)
        if w[0] == "sha256sum":
            return (0, hashlib.sha256(self.files[w[1]].encode()).hexdigest() + "  " + w[1]) if w[1] in self.files else (1, "")
        if w[0] == "echo" and "base64" in w and "-d" in w:
            self.files[w[-1]] = base64.b64decode(w[1]).decode()
            return 0, ""
        if w[:2] == ["rm", "-f"]:
            self.files.pop(w[2], None)
            return 0, ""
        return 0, ""


def BRIEF(**kw):
    return {"problem": "lab01 cannot use sudo.", "implications": "Admins cannot do their work.",
            "cause": "initgroups lists only local files.", "cause_by": "the diagnostic tool",
            "action": "Adds Kanidm to the group lookup.", "downside": "Group lookups could slow down."}


def make(tmp_path, host, keys, words=()):
    keys, words, said = list(keys), list(words), []
    g = Gate("client2", host, BRIEF, Log(tmp_path / "log.jsonl"), "tester",
             lambda: keys.pop(0), lambda: words.pop(0), said.append)
    return g, said


def test_file_edit_yes_writes_and_revert_restores(tmp_path):
    host = FakeHost({"/etc/ssh/sshd_config.d/10-kanidm.conf": "old\n"})
    g, _ = make(tmp_path, host, ["y", "r"])
    assert g.ask_file("/etc/ssh/sshd_config.d/10-kanidm.conf", "new\n", "-old\n+new", []) is True
    assert host.files["/etc/ssh/sshd_config.d/10-kanidm.conf"] == "new\n"
    g.revert()
    assert host.files["/etc/ssh/sshd_config.d/10-kanidm.conf"] == "old\n"


def test_file_edit_no_leaves_file(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, _ = make(tmp_path, host, ["n"])
    assert g.ask_file("/etc/x", "new\n", "diff", []) is False
    assert host.files["/etc/x"] == "old\n"


def test_safety_findings_require_typed_yes(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["y"], words=["no"])
    assert g.ask_file("/etc/x", "new\n", "diff", ["sshd: second step removed"]) is False
    assert host.files["/etc/x"] == "old\n"
    assert any("second login step" in s for s in said)


def test_explain_then_yes(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["e", "y"])
    assert g.ask_file("/etc/x", "new\n", "diff", []) is True
    assert any("EXACT CHANGE" in s for s in said)


def test_irreversible_command_needs_typed_yes(tmp_path):
    host = FakeHost({})
    g, _ = make(tmp_path, host, ["y"], words=["nope"])
    assert g.ask("rm -rf /etc/ssh") is None
    assert not any("rm -rf" in c for c in host.ran)


def test_log_chain_detects_tampering(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, _ = make(tmp_path, host, ["n", "n"])
    g.ask_file("/etc/x", "new\n", "diff", [])
    g.ask("systemctl reload sshd")
    p = tmp_path / "log.jsonl"
    assert verify(p) is None
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")      # delete one event
    assert verify(p) == 1


def test_command_then_revert_restores_touched_file(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, _ = make(tmp_path, host, ["y"])
    g.ask("sed -i s/old/new/ /etc/x")
    host.files["/etc/x"] = "new\n"                               # what sed would have done
    g.revert()
    assert host.files["/etc/x"] == "old\n"


def test_findings_flag_a_kanidm_file_that_no_longer_parses():
    import live
    old = "version = '2'\n\n[kanidm]\npam_allowed_login_groups = [\"lab_users\"]\n"
    f = live.findings("/etc/kanidm/unixd", old, "sudo systemctl restart sshd\n")
    assert any("no longer valid" in x for x in f)


def test_findings_flag_dropped_login_group_restriction():
    import live
    old = "version = '2'\n\n[kanidm]\npam_allowed_login_groups = [\"lab_users\"]\n"
    f = live.findings("/etc/kanidm/unixd", old, "version = '2'\n")
    assert any("login group" in x for x in f)


def test_findings_quiet_for_a_valid_harmless_edit():
    import live
    old = "version = '2'\n\n[kanidm]\npam_allowed_login_groups = [\"lab_users\"]\n"
    assert live.findings("/etc/kanidm/unixd", old, old.replace('["lab_users"]', '["lab_users", "ops"]')) == []


def test_revert_survives_ssh_banner(tmp_path):
    """The lab failure of 2026-10-02: the banner got into the backup, revert emptied the file and logged success."""
    host = FakeHost({"/etc/kanidm/unixd": "version = '2'\n"}, banner=True)
    g, said = make(tmp_path, host, ["y", "r"], words=["yes"])
    assert g.ask_file("/etc/kanidm/unixd", "sudo\n", "diff", ["not valid TOML"]) is True
    assert g.revert() is True
    assert host.files["/etc/kanidm/unixd"] == "version = '2'\n"


def test_failed_restore_is_reported_not_logged_as_success(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["y"])
    g.ask_file("/etc/x", "new\n", "diff", [])
    host.files["/etc/x"] = "tampered\n"
    real = host._run
    host._run = lambda c: (1, "disk full") if "base64 -d >" in c else real(c)
    assert g.revert() is False
    assert any("REVERT FAILED" in s for s in said)
    events = [l for l in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert '"revert-failed"' in events[-1]


def test_no_backup_no_edit(tmp_path):
    """If the gate cannot read a clean backup of the file, it must not change the file."""
    host = FakeHost({"/etc/x": "old\n"})
    real = host._run
    host._run = lambda c: (0, "garbage only") if c.startswith("if [ -f ") else real(c)
    g, said = make(tmp_path, host, ["y"])
    assert g.ask_file("/etc/x", "new\n", "diff", []) is False
    assert host.files["/etc/x"] == "old\n"


def test_authselect_backs_up_the_files_it_rewrites():
    from gate import facts
    f = facts("sudo authselect apply-changes", "client2")
    assert "/etc/authselect/nsswitch.conf" in f["files"] and "/etc/authselect/system-auth" in f["files"]
    assert f["reversible"]


def test_unknown_command_that_names_no_file_is_not_called_reversible():
    from gate import facts
    f = facts("sudo update-ca-trust extract", "client2")
    assert not f["reversible"]


def test_read_only_and_service_commands_stay_reversible():
    from gate import facts
    for c in ["sshd -t", "systemctl restart sshd", "kanidm-unix status", "visudo -c", "authselect check"]:
        assert facts(c, "client2")["reversible"], c


def test_directory_target_is_not_a_clean_backup(tmp_path):
    """c2 live: a cp into a directory ran, because base64 of a directory came back empty and looked like an empty file."""
    host = FakeHost({}, dirs={"/etc/pki/ca-trust/source/anchors/"})
    g, said = make(tmp_path, host, ["y"])
    assert g.ask("cp /tmp/x.crt /etc/pki/ca-trust/source/anchors/") is None
    assert not any(c.startswith("cp ") for c in host.ran)


def test_empty_file_round_trips(tmp_path):
    host = FakeHost({"/etc/x": ""})
    g, _ = make(tmp_path, host, ["y"])
    g.ask_file("/etc/x", "new\n", "diff", [])
    assert g.revert() is True and host.files["/etc/x"] == ""


FORM_ORDER = ["PROBLEM DETECTED", "LIKELY CAUSE", "PROPOSED ACTION", "POTENTIAL DOWNSIDE", "CHOICE"]


def test_edit_is_shown_as_the_decision_form(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["n"])
    g.ask_file("/etc/x", "new\n", "-old\n+new", ["sudo: NEW privilege grant WITHOUT password: lab01 ALL=(ALL) NOPASSWD: ALL"])
    form = next(x for x in said if "PROBLEM DETECTED" in x)
    assert [form.index(h) for h in FORM_ORDER] == sorted(form.index(h) for h in FORM_ORDER)
    assert "found by the diagnostic tool" in form and "Adds Kanidm to the group lookup." in form
    assert "SAFETY CHECK: Gives" in form
    assert "If unsure, press N" in form
    assert "-old" not in form                                  # the raw diff waits for E


def test_e_shows_the_exact_change(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["e", "n"])
    g.ask_file("/etc/x", "new\n", "-old\n+new", [])
    assert any("-old\n+new" in s for s in said[1:])


def test_irreversible_command_form_says_it_cannot_be_undone(tmp_path):
    g, said = make(tmp_path, FakeHost({}), ["n"])
    g.ask("update-ca-trust extract")
    assert any("CANNOT be undone" in x for x in said)


def test_form_survives_a_failed_ai_summary(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["n"])
    def broken(**kw):
        raise RuntimeError("model down")
    g.brief = broken
    g.ask_file("/etc/x", "new\n", "diff", ["unixd: login group restriction removed"])
    form = next(x for x in said if "PROBLEM DETECTED" in x)
    assert "ANY directory account" in form and "AI summary unavailable" in form


def test_plain_words_for_findings():
    from gate import plain
    assert plain("sudo: NEW privilege grant WITHOUT password: lab01 ALL=(ALL) NOPASSWD: ALL") == \
        "Gives lab01 full administrator (root) power with NO password."
    assert plain("sshd: break-glass shut out (AllowUsers)").startswith("Locks out the emergency")
    assert plain("something new") == "something new"


def test_failed_command_result_is_plain_and_says_what_changed(tmp_path):
    host = FakeHost({"/etc/authselect/nsswitch.conf": "a\n"})
    real = host._run
    host._run = lambda c: (4, "[error] Refusing to activate profile") if c.strip().startswith("authselect apply") else real(c)
    g, said = make(tmp_path, host, ["y"])
    g.ask("authselect apply-changes")
    res = next(x for x in said if "RESULT" in x)
    assert "FAILED" in res and "nothing" in res.lower()
    assert "Refusing to activate profile" in res                    # the system's own words, labelled, short


def test_successful_edit_result_and_session_summary(tmp_path):
    host = FakeHost({"/etc/x": "old\n"})
    g, said = make(tmp_path, host, ["y", "n"])
    g.ask_file("/etc/x", "new\n", "diff", [])
    g.ask("authselect apply-changes")
    res = next(x for x in said if "RESULT" in x)
    assert "DONE" in res and "/etc/x" in res
    summary = g.summary()
    assert "1. Edit /etc/x" in summary and "DONE" in summary
    assert "2. Run: authselect apply-changes" in summary and "SKIPPED" in summary
    assert "R undoes: Edit /etc/x" in summary


def test_parse_choice_needs_a_whole_word():
    from gate import parse_choice
    assert parse_choice("y", "yner") == "y" and parse_choice(" Yes ", "yner") == "y"
    assert parse_choice("no", "yner") == "n" and parse_choice("undo", "yner") == "r"
    assert parse_choice("e", "yner") == "e" and parse_choice("q", "rq") == "q"
    for bad in ["", "es", "yesno", "ye s", "x", "q"]:
        assert parse_choice(bad, "yner") is None, bad
