"""The runbook shape (approved 2026-10-03): every field fills one line of the operator's decision form, by code."""
from engine import runbooks
from engine.case import Case
from engine.findings import Finding
from engine.form import render

CONVERTED = {"NSS_ORDER_WRONG"}          # grows until it is all 18; then the completeness test covers every runbook


def test_converted_runbooks_have_every_field():
    for fid in CONVERTED:
        rb = runbooks.load(fid)
        missing = [f for f in runbooks.FIELDS if not getattr(rb, f).strip()]
        assert not missing, f"{fid} lacks {missing}"
        assert rb.complete


def test_unconverted_runbooks_still_load():
    rb = runbooks.load("SERVICE_DOWN")
    assert rb.default_repair is None and rb.excerpt and not rb.complete


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
