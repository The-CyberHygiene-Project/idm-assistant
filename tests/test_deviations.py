import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "lab" / "iso5" / "deviations.py"
NS = "http://checklists.nist.gov/xccdf/1.2"


def results(tmp_path, host, rows):
    rr = "".join(f'<rule-result idref="{r}" severity="{s}"><result>{res}</result></rule-result>' for r, s, res in rows)
    rules = "".join(f'<Rule id="{r}"><title>Title of {r}</title></Rule>' for r, _, _ in rows)
    p = tmp_path / f"{host}.xml"
    p.write_text(f'<Benchmark xmlns="{NS}">{rules}<TestResult><target>{host}</target>{rr}</TestResult></Benchmark>')
    return p


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)


def test_every_failure_decided_accept_passes(tmp_path):
    a = results(tmp_path, "srv", [("r1", "high", "fail"), ("r2", "low", "pass")])
    b = results(tmp_path, "cli", [("r1", "high", "fail")])
    d = tmp_path / "d.tsv"; d.write_text("# c\nr1\taccept\tD. Shannon (ISSO)\tGUI is required on both roles\n")
    r = run(a, b, "--decisions", d)
    assert r.returncode == 0, r.stderr
    assert "| r1 | high | cli, srv | accept | D. Shannon (ISSO) | GUI is required on both roles |" in r.stdout
    assert "Title of r1" in r.stdout and "r2" not in r.stdout.split("## Failures")[1]


def test_undecided_or_fix_fails_the_gate(tmp_path):
    a = results(tmp_path, "srv", [("r1", "medium", "fail"), ("r3", "low", "fail")])
    d = tmp_path / "d.tsv"; d.write_text("r1\tfix\tD. Shannon (ISSO)\tchange the RPM\n")
    r = run(a, "--decisions", d)
    assert r.returncode == 1
    assert "UNDECIDED: r3" in r.stdout and "NOT YET FIXED: r1" in r.stdout


def test_error_and_notchecked_are_listed_separately(tmp_path):
    a = results(tmp_path, "srv", [("r4", "low", "error"), ("r5", "low", "notchecked")])
    d = tmp_path / "d.tsv"; d.write_text("")
    r = run(a, "--decisions", d)
    assert "## Not evaluated" in r.stdout and "r4 (error)" in r.stdout and "r5 (notchecked)" in r.stdout


def test_bad_decision_word_is_refused(tmp_path):
    a = results(tmp_path, "srv", [("r1", "low", "fail")])
    d = tmp_path / "d.tsv"; d.write_text("r1\tmaybe\tx\ty\n")
    r = run(a, "--decisions", d)
    assert r.returncode == 2 and "decisions line 1" in r.stderr
