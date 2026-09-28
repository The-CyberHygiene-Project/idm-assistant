from engine.explain import validate

OK = {"analysis": "The Kanidm certificate expired and the renewal timer is stopped.", "confidence_level": "HIGH",
      "confidence_score": 90, "confidence_justification": "Both findings present on srv1.",
      "evidence": ["TLS_CERT_EXPIRED(kanidm)", "ACME_RENEWAL_STOPPED"], "alternative_hypotheses": ["client clock skew"],
      "validation_steps": ["fresh collect shows no finding"], "human_review": "REQUIRED", "repair_id": "kanidm-cert-renew"}


def test_valid_response_passes():
    assert validate(OK, {"kanidm-cert-renew", "acme-timer-restore"}) == []


def test_unknown_repair_id_is_rejected_but_null_means_unsure():
    assert validate(dict(OK, repair_id="rm-rf"), {"kanidm-cert-renew"})
    assert validate(dict(OK, repair_id=None), {"kanidm-cert-renew"}) == []


def test_missing_confidence_and_bad_score_are_rejected():
    bad = {k: v for k, v in OK.items() if k != "confidence_level"}
    assert validate(bad, {"kanidm-cert-renew"})
    assert validate(dict(OK, confidence_score=140), {"kanidm-cert-renew"})
