from contextlib import contextmanager
from datetime import date

from chp_site import review_ledger as rl
from chp_site import review_store as st

SITE = {"ISSO_NAME": "Dana ISSO", "REVIEW_DELEGATES": []}


def setup(tmp_path, days=(date(2026, 11, 6), date(2026, 11, 7))):
    root = tmp_path / "root"
    for d in days:
        st.write_day(d, {"day": d.isoformat()}, f"# review {d}\n", "<html></html>", root=root)
        rl.sign(site=SITE, approver="Dana ISSO", notes="ok", days=[d], root=root, now=1.0, operator="dana",
                confirm=lambda t: True, say=lambda *a: None, rec=lambda *a, **k: None)
    stick = tmp_path / "stick"; stick.mkdir()
    return root, stick


def ledger(root):
    return root / "var/lib/chp/review/ledger.jsonl"


def test_export_appends_the_head_and_copies_sets(tmp_path):
    root, stick = setup(tmp_path)
    r = rl.export(stick, root=root, now=1_800_000_000.0)
    assert sorted(p.name for p in (stick / "review").iterdir()) == ["2026-11-06", "2026-11-07", "heads.txt", "ledger.jsonl",
                                                                     "verify.txt"]
    assert (stick / "review/2026-11-07/report.md").read_text() == "# review 2026-11-07\n"
    count, h = rl.head(ledger(root))
    assert (stick / "review/heads.txt").read_text().split()[:2] == [str(count), h] and r["head"] == (count, h)
    assert (stick / "review/verify.txt").read_text().startswith("OK")
    rl.export(stick, root=root, now=1_800_000_100.0)                         # a second export adds a second head
    assert len((stick / "review/heads.txt").read_text().splitlines()) == 2


def test_rewritten_ledger_fails_against_the_stick(tmp_path):
    root, stick = setup(tmp_path)
    rl.export(stick, root=root, now=1.0)
    p = ledger(root)                                                         # root rewrites the WHOLE chain consistently
    lines = p.read_text().splitlines()
    import json
    e1 = json.loads(lines[0]); e1["notes"] = "changed"; l1 = json.dumps(e1, sort_keys=True, separators=(",", ":"))
    e2 = json.loads(lines[1]); e2["prev"] = rl.entry_hash(l1); l2 = json.dumps(e2, sort_keys=True, separators=(",", ":"))
    p.write_text(l1 + "\n" + l2 + "\n")
    p.with_name("ledger.head").write_text(f"2 {rl.entry_hash(l2)}\n")      # root rewrites the witness too
    assert rl.verify(p, root=root) == []                                     # nothing on the server can see it
    assert any("head 1" in x for x in rl.verify_heads(p, (stick / "review/heads.txt").read_text()))


def test_dropped_newest_entries_fail_against_the_stick(tmp_path):
    root, stick = setup(tmp_path)
    rl.export(stick, root=root, now=1.0)
    p = ledger(root); p.write_text(p.read_text().splitlines()[0] + "\n")
    probs = rl.verify_heads(p, (stick / "review/heads.txt").read_text())
    assert probs and "entries removed" in probs[0]


def test_clean_heads_pass(tmp_path):
    root, stick = setup(tmp_path)
    rl.export(stick, root=root, now=1.0)
    assert rl.verify_heads(ledger(root), (stick / "review/heads.txt").read_text()) == []


def test_bad_heads_file_is_reported_not_trusted(tmp_path):
    root, stick = setup(tmp_path)
    assert rl.verify_heads(ledger(root), "garbage\n") == ["stick heads.txt line 1 is not '<count> <hash> <time>'"]


def test_verify_without_stick_says_anchor_not_checked(tmp_path, monkeypatch, capsys):   # Review Focus 5
    from chp_site import cli
    root, stick = setup(tmp_path)
    monkeypatch.setattr(rl, "_path", lambda r: ledger(root))
    monkeypatch.setattr(st, "_dir", lambda r: root / "var/lib/chp/review")
    assert cli.main(["review", "verify"]) == 0
    out = capsys.readouterr().out
    assert "chain OK" in out and "stick anchor NOT checked" in out


def test_verify_quiet_prints_only_problems(tmp_path, monkeypatch, capsys):
    from chp_site import cli
    root, stick = setup(tmp_path)
    monkeypatch.setattr(rl, "_path", lambda r: ledger(root))
    monkeypatch.setattr(st, "_dir", lambda r: root / "var/lib/chp/review")
    assert cli.main(["review", "verify", "--quiet"]) == 0 and capsys.readouterr().out == ""
    p = ledger(root); p.write_text(p.read_text().replace('"ok"', '"OK"', 1))
    assert cli.main(["review", "verify", "--quiet"]) == 1 and "entry 2" in capsys.readouterr().out


def test_cli_export_and_verify_use_the_pinned_stick(tmp_path, monkeypatch, capsys):
    from chp_site import cli, usbstick
    root, stick = setup(tmp_path)
    monkeypatch.setattr(rl, "_path", lambda r: ledger(root))
    monkeypatch.setattr(st, "_dir", lambda r: root / "var/lib/chp/review")

    @contextmanager
    def fake_stick(s=None):
        yield stick
    monkeypatch.setattr(usbstick, "site_stick", fake_stick)
    assert cli.main(["review", "export"]) == 0 and "exported 2 review(s)" in capsys.readouterr().out
    assert cli.main(["review", "verify", "--stick"]) == 0
    assert "stick anchor OK (1 head)" in capsys.readouterr().out
