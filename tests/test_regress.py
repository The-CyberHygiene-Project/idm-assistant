from engine.regress import summarize

ROWS = [
    {"id": "l2", "run": 1, "status": "GREEN", "timings": {"reset": 33.0, "inject": 2.0, "nsswitch-restore:apply": 1.5},
     "interp": {"valid": True, "agrees": True}},
    {"id": "l2", "run": 2, "status": "GREEN", "timings": {"reset": 35.0, "inject": 2.2, "nsswitch-restore:apply": 1.1},
     "interp": {"valid": False, "agrees": False, "errors": ["repair_id 'x' is not on the allow-list"]}},
    {"id": "c2", "run": 1, "status": "NOT-CLEARED", "timings": {"reset": 30.0}, "interp": {"skipped": "IDM_NO_MODEL=1"}},
]


def test_summary_has_one_row_per_scenario_with_counts_and_medians():
    md = summarize(ROWS)
    assert "| l2 | 2 | 2/2 | GREEN, GREEN | 34.0 |" in md
    assert "| c2 | 1 | 0/1 | NOT-CLEARED |" in md


def test_summary_reports_model_validity_and_agreement():
    md = summarize(ROWS)
    assert "1/2 valid, 1/2 agree" in md and "skipped" in md


def test_summary_ends_with_an_overall_verdict():
    assert summarize(ROWS).rstrip().endswith("**Overall: 1 of 2 scenarios green in every run.**")


def test_regress_accepts_a_relative_output_path(tmp_path, monkeypatch):
    from engine import cli, regress
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(regress, "run", lambda ids, runs: [dict(ROWS[0], case="c")])
    assert cli.regress_cmd(["l2"], 1, "out/report.md") == 0
    assert "Overall: 1 of 1" in (tmp_path / "out" / "report.md").read_text()


def test_failed_reset_is_reported_with_its_reason_and_nothing_runs(tmp_path, monkeypatch):    # final review I-1
    import subprocess
    import types
    from engine import cli
    monkeypatch.setattr(cli, "ROOT", tmp_path)

    def boom(*a, **kw):
        raise subprocess.CalledProcessError(1, a[0], output="", stderr="reset: client2 not reachable after the revert\n")
    monkeypatch.setattr(cli.subprocess, "run", boom)
    injected = []
    sc = types.SimpleNamespace(ID="zz", SYMPTOM="s", EXPECT={"client2": set()}, USER=None,
                               inject=lambda log: injected.append(1))
    case, st = cli.run_scenario(sc, 1)
    assert st == "RESET-FAILED" and not injected                     # never runs on a host that is not at golden
    assert "client2 not reachable after the revert" in (case.dir / "repair.log").read_text()
    assert (case.dir / "status.txt").read_text().strip() == "RESET-FAILED"
