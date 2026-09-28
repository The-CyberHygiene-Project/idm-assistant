"""Explainable-response schema for the Plan 6 interpreter (fields from sysadmin-agent's ExplainableResponse, plus
repair_id). The model only ever picks a repair id from the allow-list, or null (= unsure: show the runbook default)."""
LEVELS = {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
REVIEW = {"REQUIRED", "RECOMMENDED", "ROUTINE"}
LISTS = ("evidence", "alternative_hypotheses", "validation_steps")


def validate(resp, allowed_repairs):
    errs = []
    if not isinstance(resp, dict):
        return ["response is not an object"]
    if not isinstance(resp.get("analysis"), str) or not resp["analysis"].strip():
        errs.append("analysis missing")
    if resp.get("confidence_level") not in LEVELS:
        errs.append("confidence_level missing/invalid")
    s = resp.get("confidence_score")
    if not isinstance(s, int) or not 0 <= s <= 100:
        errs.append("confidence_score must be an int 0-100")
    if not isinstance(resp.get("confidence_justification"), str):
        errs.append("confidence_justification missing")
    for k in LISTS:
        if not isinstance(resp.get(k), list) or not all(isinstance(x, str) for x in resp[k]):
            errs.append(f"{k} must be a list of strings")
    if resp.get("human_review") not in REVIEW:
        errs.append("human_review missing/invalid")
    rid = resp.get("repair_id")
    if rid is not None and rid not in allowed_repairs:
        errs.append(f"repair_id {rid!r} is not on the allow-list")
    return errs
