"""The runbook shape (approved 2026-10-03): every field fills one line of the operator's decision form, by code."""
from engine import runbooks
from engine.case import Case
from engine.findings import Finding
from engine.form import render

CONVERTED = set(runbooks.ids())                                  # all of them


def test_converted_runbooks_have_every_field():
    for fid in CONVERTED:
        rb = runbooks.load(fid)
        missing = [f for f in runbooks.FIELDS if not getattr(rb, f).strip()]
        assert not missing, f"{fid} lacks {missing}"
        assert rb.complete


def test_all_twenty_four_are_in_the_shape():
    assert len(CONVERTED) == 24


def test_every_repair_has_a_complete_runbook_that_fills_its_form():
    from engine.repairs import REGISTRY
    for rid, r in REGISTRY.items():
        rb = runbooks.for_repair(rid, r.verify_absent)
        assert rb is not None and rb.complete, f"{rid} has no complete runbook"


def test_old_two_line_header_still_loads(tmp_path, monkeypatch):
    (tmp_path / "OLD.md").write_text("default_repair: none\n---\nShort text.\n")
    monkeypatch.setattr(runbooks, "DIR", tmp_path)
    rb = runbooks.load("OLD")
    assert rb.default_repair is None and rb.excerpt == "Short text." and not rb.complete


def test_form_is_built_from_the_runbook_and_the_hosts_evidence():
    rb = runbooks.load("NSS_ORDER_WRONG")
    f = Finding("NSS_ORDER_WRONG", "nss", ["initgroups: 'files'"], "error")
    form = render("client2", rb, [f], "nsswitch-restore")
    order = ["PROBLEM DETECTED", "LIKELY CAUSE", "PROPOSED ACTION", "POTENTIAL DOWNSIDE", "SAY NO IF", "CHOICE"]
    assert [form.index(h) for h in order] == sorted(form.index(h) for h in order)
    for field in (rb.user_sees, rb.means, rb.repair, rb.if_wrong, rb.rollback, rb.say_no_if):
        assert " ".join(field.split()[:4]) in " ".join(form.split())
    assert "initgroups: 'files'" in form                       # what the collector actually found on THIS host
    assert "If unsure, type no" in form and "Type yes" in form


def test_repair_prompt_is_the_form_for_a_converted_runbook(tmp_path):
    from engine.repairs import Ctx, REGISTRY, run_repair
    seen = []
    def approve(prompt):
        seen.append(prompt); return False
    r = REGISTRY["nsswitch-restore"]
    r_pre = r.precheck
    r.precheck = lambda ctx: None
    try:
        rep = {"host": "client2", "role": "client", "nss": {"initgroups": ["files"]}}
        ctx = Ctx(host="client2", role="client", case=Case(tmp_path, "c", "s"), collect=lambda: rep, remote=None)
        run_repair("nsswitch-restore", ctx, approve, REGISTRY)
    finally:
        r.precheck = r_pre
    assert "PROBLEM DETECTED" in seen[0] and "SAY NO IF" in seen[0]


def test_the_format_readme_is_not_a_runbook():
    assert (runbooks.DIR / "README.md").is_file() and "README" not in runbooks.ids()
