from probe.report import to_markdown


def test_markdown_table_has_valid_rate_and_abort_marker():
    pts = [
        {"model": "gemma", "pad_tokens": 1000, "n": 20, "counts": {"valid": 18, "prose": 2},
         "prompt_tokens_mean": 1300, "seconds_mean": 2.1, "aborted": False, "reason": ""},
        {"model": "gemma", "pad_tokens": 15000, "n": 20, "counts": {"valid": 5},
         "prompt_tokens_mean": 15400, "seconds_mean": 9.8, "aborted": True, "reason": "changed"},
    ]
    md = to_markdown(pts, {"date": "2026-09-27", "temperature": 0.5})
    assert "| gemma | 1000 | 20 | 90% |" in md
    assert "ABORTED" in md and "temperature: 0.5" in md
