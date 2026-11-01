import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from chp_site import yara_scan as y


def yara(stdout="", rc=0, stderr="", seen=None):
    def run(argv, **kw):
        if seen is not None:
            seen.append(argv)
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)
    return run


def setup(tmp_path):
    w = tmp_path / "home"; w.mkdir()
    log = tmp_path / "chp-yara.json"; st = tmp_path / "state"
    return w, log, st


def lines(log):
    return [json.loads(ln)["chp_yara"] for ln in log.read_text().splitlines()] if log.exists() else []


def scan(p, w, log, st, run, now=1000.0):
    return y.scan_file(str(p), run=run, log=log, state_dir=st, now=lambda: now, watched=(str(w),), never=())


def test_match_writes_one_line_with_rules_file_and_sha256(tmp_path):
    w, log, st = setup(tmp_path); f = w / "evil.bin"; f.write_bytes(b"x")
    ev = scan(f, w, log, st, yara(stdout=f"Rule_A {f}\nRule_B {f}\n"))
    assert ev["event"] == "match" and ev["rules"] == "Rule_A,Rule_B" and ev["file"] == str(f)
    assert ev["sha256"] == "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    assert lines(log) == [ev]


def test_clean_file_writes_nothing(tmp_path):
    w, log, st = setup(tmp_path); f = w / "ok.txt"; f.write_text("hi")
    assert scan(f, w, log, st, yara()) is None and lines(log) == []


def test_file_gone_before_the_scan_is_silent(tmp_path):                       # Review Focus 3
    w, log, st = setup(tmp_path)
    assert scan(w / "vanished", w, log, st, yara()) is None and lines(log) == []


def test_symlink_out_of_the_watched_folders_is_refused(tmp_path):              # Review Focus 2
    w, log, st = setup(tmp_path); out = tmp_path / "secret"; out.write_text("s")
    (w / "link").symlink_to(out)
    seen = []
    ev = scan(w / "link", w, log, st, yara(seen=seen))
    assert ev["event"] == "skipped" and ev["detail"] == "outside the watched folders" and seen == []


def test_fifo_is_refused_without_opening_it(tmp_path):                         # Review Focus 4
    w, log, st = setup(tmp_path); p = w / "pipe"; os.mkfifo(p)
    ev = scan(p, w, log, st, yara())                                          # would block if it opened the FIFO
    assert ev["event"] == "skipped" and ev["detail"] == "not a regular file"


def test_odd_file_names_are_passed_as_one_argument(tmp_path):                  # Review Focus 1
    w, log, st = setup(tmp_path); f = w / "a b'\"\n$(x)é.txt"; f.write_text("x")
    seen = []
    scan(f, w, log, st, yara(seen=seen))
    assert seen[0][-1] == str(f) and isinstance(seen[0], list)


def test_missing_rules_gives_one_error_line(tmp_path):                        # Review Focus 5
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    ev = scan(f, w, log, st, yara(rc=1, stderr="error: could not open file: /usr/share/chp-yara-rules/rules.yarc\n"))
    assert ev["event"] == "error" and "rules.yarc" in ev["detail"] and len(lines(log)) == 1


def test_yara_missing_gives_one_error_line(tmp_path):
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    def run(argv, **kw):
        raise FileNotFoundError("yara")
    ev = scan(f, w, log, st, run)
    assert ev["event"] == "error" and "yara is not installed" in ev["detail"]


def test_repeat_within_a_minute_is_scanned_once(tmp_path):
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    seen = []
    scan(f, w, log, st, yara(seen=seen), now=1000.0)
    scan(f, w, log, st, yara(seen=seen), now=1030.0)
    scan(f, w, log, st, yara(seen=seen), now=1061.0)
    assert len(seen) == 2


def test_wazuh_data_folder_is_never_scanned(tmp_path):
    w, log, st = setup(tmp_path); d = w / "wazuh"; d.mkdir(); f = d / "alerts.json"; f.write_text("{}")
    ev = y.scan_file(str(f), run=yara(), log=log, state_dir=st, now=lambda: 1.0, watched=(str(w),), never=(str(d),))
    assert ev["event"] == "skipped"


def test_scan_passes_per_file_externals(tmp_path):
    w, log, st = setup(tmp_path); f = w / "doc.pdf"; f.write_text("x")
    seen = []
    scan(f, w, log, st, yara(seen=seen))
    a = seen[0]
    assert "--define=filename=doc.pdf" in a and f"--define=filepath={w}" in a and "--define=extension=.pdf" in a
    assert "-C" in a and y.RULES in a and f"--timeout={y.TIMEOUT}" in a


def test_from_wazuh_reads_the_syscheck_path():
    msg = {"version": 1, "command": "add",
           "parameters": {"alert": {"syscheck": {"path": "/home/u/a b.exe", "event": "added"}}}}
    assert y.from_wazuh(json.dumps(msg)) == "/home/u/a b.exe"
    assert y.from_wazuh(json.dumps(dict(msg, command="delete"))) is None
    assert y.from_wazuh("not json") is None


def test_full_scan_skips_system_folders_and_writes_summary_and_last_full(tmp_path):
    root = tmp_path / "r"
    for d in ("home/u", "proc", "var/ossec/logs", "etc"):
        (root / d).mkdir(parents=True)
    (root / "home/u/bad").write_text("x"); (root / "etc/ok").write_text("y")
    (root / "proc/x").write_text("p"); (root / "var/ossec/logs/a").write_text("w")
    log = tmp_path / "log"; st = tmp_path / "st"
    listed = {}
    def run(argv, **kw):
        listed["files"] = Path(argv[argv.index("--scan-list") + 1]).read_text().splitlines()
        return SimpleNamespace(returncode=0, stdout=f"Rule_X {root}/home/u/bad\n", stderr="")
    s = y.full_scan(run=run, log=log, state_dir=st, now=lambda: 5000.0, walk_root=str(root),
                    skip=(str(root / "proc"), str(root / "var/ossec")), mounts_text="")
    assert sorted(listed["files"]) == [f"{root}/etc/ok", f"{root}/home/u/bad"]
    evs = lines(log)
    assert evs[0]["event"] == "match" and evs[0]["file"] == f"{root}/home/u/bad"
    assert evs[-1] == s and s["event"] == "summary" and s["files"] == 2 and s["matches"] == 1 and s["errors"] == 0
    assert (st / "last-full").read_text().strip() == "5000"


def test_full_scan_skips_network_mounts(tmp_path):
    root = tmp_path / "r"; (root / "mnt/nfs").mkdir(parents=True); (root / "mnt/nfs/f").write_text("x")
    log = tmp_path / "log"; st = tmp_path / "st"
    listed = {}
    def run(argv, **kw):
        listed["files"] = Path(argv[argv.index("--scan-list") + 1]).read_text().splitlines()
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    y.full_scan(run=run, log=log, state_dir=st, now=lambda: 1.0, walk_root=str(root), skip=(),
                mounts_text=f"srv:/x {root}/mnt/nfs nfs4 rw 0 0\n")
    assert listed["files"] == []


def test_log_lines_are_not_world_readable(tmp_path):
    w, log, st = setup(tmp_path); f = w / "x"; f.write_text("x")
    scan(f, w, log, st, yara(stdout=f"R {f}\n"))
    assert oct(log.stat().st_mode & 0o777) == "0o640"

def test_cli_wazuh_mode_reads_stdin(monkeypatch, tmp_path):
    from chp_site import cli
    got = {}
    monkeypatch.setattr(y, "scan_file", lambda p, run: got.setdefault("p", p))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(
        {"command": "add", "parameters": {"alert": {"syscheck": {"path": "/tmp/z"}}}})))
    assert cli.main(["yara-scan", "--wazuh"]) == 0 and got["p"] == "/tmp/z"


def test_full_scan_never_scans_the_rules_folder():                            # spike: the rules file matches itself
    assert y.RULES_DIR in y.FULL_SKIP and y.RULES.startswith(y.RULES_DIR + "/")


def test_full_scan_uses_the_long_limit_not_the_per_file_one(tmp_path):        # spike: --timeout limits the whole run
    root = tmp_path / "r"; (root / "a").mkdir(parents=True); (root / "a/f").write_text("x")
    seen = []
    def run(argv, **kw):
        seen.append(argv); return SimpleNamespace(returncode=0, stdout="", stderr="")
    y.full_scan(run=run, log=tmp_path / "log", state_dir=tmp_path / "st", now=lambda: 1.0, walk_root=str(root),
                skip=(), mounts_text="")
    assert f"--timeout={y.FULL_TIMEOUT}" in seen[0] and f"--timeout={y.TIMEOUT}" not in seen[0]


def test_full_scan_ignores_errors_for_files_that_vanished(tmp_path):          # spike: temp files go mid-scan
    root = tmp_path / "r"; (root / "a").mkdir(parents=True); keep = root / "a/keep"; keep.write_text("x")
    def run(argv, **kw):
        return SimpleNamespace(returncode=0, stdout="",
                               stderr=f"error scanning {root}/a/gone: could not open file\n"
                                      f"error scanning {keep}: could not open file\n")
    s = y.full_scan(run=run, log=tmp_path / "log", state_dir=tmp_path / "st", now=lambda: 1.0, walk_root=str(root),
                    skip=(), mounts_text="")
    errs = [e for e in lines(tmp_path / "log") if e["event"] == "error"]
    assert s["errors"] == 1 and len(errs) == 1 and str(keep) in errs[0]["detail"]
