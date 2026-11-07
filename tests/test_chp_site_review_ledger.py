import json
from datetime import date

import pytest

from chp_site import review_ledger as rl
from chp_site import review_store as st
from chp_site.sitefile import SiteError

SITE = {"ISSO_NAME": "Dana ISSO", "REVIEW_DELEGATES": ["Deputy One"]}


def built(tmp_path, *days):
    for d in days:
        st.write_day(d, {"day": d.isoformat()}, f"# review {d}\n", "<html></html>", root=tmp_path)


def ledger(tmp_path):
    return tmp_path / "var/lib/chp/review/ledger.jsonl"


def sign(tmp_path, approver="Dana ISSO", days=None, notes="looked fine", confirm=lambda text: True, rec=None):
    return rl.sign(site=SITE, approver=approver, notes=notes, days=days, root=tmp_path, now=1_800_000_000.0,
                   operator="dana", confirm=confirm, say=lambda *a: None, rec=rec or (lambda *a, **k: None))


def test_entries_chain_and_verify_clean(tmp_path):
    built(tmp_path, date(2026, 11, 6), date(2026, 11, 7))
    sign(tmp_path, days=[date(2026, 11, 6)]); sign(tmp_path, days=[date(2026, 11, 7)])
    es = rl.read(ledger(tmp_path))
    assert [e["date"] for e in es] == ["2026-11-06", "2026-11-07"]
    assert es[0]["prev"] == "0" * 64 and es[1]["prev"] == rl.entry_hash(ledger(tmp_path).read_text().splitlines()[0])
    assert set(es[0]) == {"date", "report_sha256", "approver", "operator", "time", "notes", "prev"}
    assert es[0]["report_sha256"] == st.report_sha256(tmp_path / "var/lib/chp/review/2026-11-06")
    assert rl.verify(ledger(tmp_path), root=tmp_path) == []
    assert rl.head(ledger(tmp_path)) == (2, rl.entry_hash(ledger(tmp_path).read_text().splitlines()[1]))


def test_editing_an_earlier_entry_fails_verify(tmp_path):
    built(tmp_path, date(2026, 11, 6), date(2026, 11, 7))
    sign(tmp_path, days=[date(2026, 11, 6)]); sign(tmp_path, days=[date(2026, 11, 7)])
    p = ledger(tmp_path)
    p.write_text(p.read_text().replace("looked fine", "looked fine!", 1))
    problems = rl.verify(p, root=tmp_path)
    assert problems and "entry 2" in problems[0]


def test_editing_a_kept_report_fails_verify(tmp_path):
    built(tmp_path, date(2026, 11, 6))
    sign(tmp_path, days=[date(2026, 11, 6)])
    (tmp_path / "var/lib/chp/review/2026-11-06/report.md").write_text("# edited\n")
    assert any("2026-11-06" in x and "report" in x for x in rl.verify(ledger(tmp_path), root=tmp_path))


def test_sign_refuses_a_broken_chain(tmp_path):                  # Review Focus 4
    built(tmp_path, date(2026, 11, 6), date(2026, 11, 7))
    sign(tmp_path, days=[date(2026, 11, 6)])
    p = ledger(tmp_path); p.write_text(p.read_text() + '{"date": "2026-11-0')            # power loss mid-append
    with pytest.raises(SiteError, match="ledger.*line 2"):
        sign(tmp_path, days=[date(2026, 11, 7)])
    assert p.read_text().count("\n") == 1                                                # nothing appended


def test_verify_reports_a_truncated_last_line(tmp_path):         # Review Focus 4
    built(tmp_path, date(2026, 11, 6))
    sign(tmp_path, days=[date(2026, 11, 6)])
    p = ledger(tmp_path); p.write_text(p.read_text() + "{")
    assert any("line 2" in x for x in rl.verify(p, root=tmp_path))


def test_missing_ledger_is_empty_not_an_error(tmp_path):
    assert rl.read(ledger(tmp_path)) == [] and rl.head(ledger(tmp_path)) == (0, "0" * 64)
    assert rl.verify(ledger(tmp_path), root=tmp_path) == []


def test_unlisted_name_cannot_sign(tmp_path):
    built(tmp_path, date(2026, 11, 6))
    with pytest.raises(SiteError, match="refusing"):
        sign(tmp_path, approver="Mallory", days=[date(2026, 11, 6)])
    assert not ledger(tmp_path).exists()


def test_isso_and_review_delegate_can_sign(tmp_path):
    built(tmp_path, date(2026, 11, 6), date(2026, 11, 7))
    sign(tmp_path, approver="dana isso", days=[date(2026, 11, 6)])            # case-insensitive, as approved_by
    sign(tmp_path, approver="Deputy One", days=[date(2026, 11, 7)])
    assert [e["approver"] for e in rl.read(ledger(tmp_path))] == ["dana isso", "Deputy One"]


def test_several_days_signed_as_separate_entries(tmp_path):
    built(tmp_path, date(2026, 11, 6), date(2026, 11, 7), date(2026, 11, 8))
    sign(tmp_path, days=None)                                                 # default: every built, unsigned day
    assert [e["date"] for e in rl.read(ledger(tmp_path))] == ["2026-11-06", "2026-11-07", "2026-11-08"]
    with pytest.raises(SiteError, match="nothing to sign"):
        sign(tmp_path, days=None)


def test_unbuilt_or_already_signed_day_is_refused(tmp_path):
    built(tmp_path, date(2026, 11, 6))
    with pytest.raises(SiteError, match="no review for 2026-11-05"):
        sign(tmp_path, days=[date(2026, 11, 5)])
    sign(tmp_path, days=[date(2026, 11, 6)])
    with pytest.raises(SiteError, match="already signed"):
        sign(tmp_path, days=[date(2026, 11, 6)])


def test_declined_confirmation_records_nothing(tmp_path):
    built(tmp_path, date(2026, 11, 6))
    with pytest.raises(SiteError, match="not signed"):
        sign(tmp_path, days=[date(2026, 11, 6)], confirm=lambda text: False)
    assert not ledger(tmp_path).exists()


def test_sign_writes_the_audit_record(tmp_path):
    built(tmp_path, date(2026, 11, 6))
    got = []
    sign(tmp_path, days=[date(2026, 11, 6)], rec=lambda action, fields, **k: got.append((action, fields)))
    assert got[0][0] == "review-sign" and got[0][1]["date"] == "2026-11-06" and got[0][1]["approver"] == "Dana ISSO"
    assert got[0][1]["entry"] == rl.head(ledger(tmp_path))[1]


def test_ledger_file_is_0600(tmp_path):
    built(tmp_path, date(2026, 11, 6))
    sign(tmp_path, days=[date(2026, 11, 6)])
    assert oct(ledger(tmp_path).stat().st_mode & 0o777) == "0o600"


def test_cli_sign_passes_the_approver_dates_and_a_yes_prompt(monkeypatch):
    from chp_site import cli
    got = {}
    monkeypatch.setattr(cli, "_load", lambda site: (SITE, []))
    monkeypatch.setattr(rl, "sign", lambda **kw: got.update(kw) or [{}])
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    assert cli.main(["review", "sign", "--approver", "Dana ISSO", "--notes", "ok", "--date", "2026-11-06",
                     "--date", "2026-11-07"]) == 0
    assert got["approver"] == "Dana ISSO" and got["days"] == [date(2026, 11, 6), date(2026, 11, 7)]
    assert got["confirm"]("sign?") is True
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    assert got["confirm"]("sign?") is False


def test_cli_sign_requires_approver_and_notes(capsys):
    from chp_site import cli
    assert cli.main(["review", "sign", "--notes", "ok"]) == 2
    assert "--approver" in capsys.readouterr().err
    assert cli.main(["review", "sign", "--approver", "Dana ISSO"]) == 2
