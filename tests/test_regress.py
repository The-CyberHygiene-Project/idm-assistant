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
