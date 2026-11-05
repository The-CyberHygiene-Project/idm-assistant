import importlib.util
from pathlib import Path

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-suricata-rules"
spec = importlib.util.spec_from_file_location("build_rules_s", D / "build-rules.py")
br = importlib.util.module_from_spec(spec); spec.loader.exec_module(br)

R1 = 'alert http any any -> any any (msg:"one"; content:"x"; sid:1001; rev:1;)\n'
R2 = 'alert tcp any any -> any any (msg:"two"; sid:1002; rev:3;)\n'
R3 = '# alert tcp any any -> any any (msg:"commented upstream"; sid:1003; rev:1;)\n'


def tree(tmp_path):
    src = tmp_path / "rules"; src.mkdir()
    (src / "a.rules").write_text(R1 + R3); (src / "b.rules").write_text(R2)
    (src / "classification.config").write_text("config classification: x,X,1\n")
    out = tmp_path / "out"; out.mkdir()
    return src, out


def test_merges_rules_and_disables_listed_sids_with_reasons(tmp_path):
    src, out = tree(tmp_path)
    n_on, n_off, unknown = br.build(src, {"1002": "fires on the appliance's own Wazuh traffic"}, out)
    text = (out / "chp-suricata.rules").read_text()
    assert "sid:1001;" in text and text.count("\n# chp-disabled: ") == 1 and "#alert tcp any any" not in text
    assert "# chp-disabled: fires on the appliance's own Wazuh traffic\n# alert tcp any any -> any any (msg:\"two\"" in text
    assert (n_on, n_off, unknown) == (1, 1, [])
    assert (out / "DISABLED.txt").read_text() == "1002\tfires on the appliance's own Wazuh traffic\n"


def test_unknown_disabled_sid_is_reported_not_fatal(tmp_path):              # Review Focus 5
    src, out = tree(tmp_path)
    assert br.build(src, {"9999": "gone upstream"}, out)[2] == ["9999"]


def test_classification_and_reference_files_are_copied(tmp_path):
    src, out = tree(tmp_path); (src / "reference.config").write_text("config reference: url http://\n")
    br.build(src, {}, out)
    assert (out / "classification.config").exists() and (out / "reference.config").exists()


def test_disable_file_format():
    assert br.load_disable("# c\n2100498 fires on the lab's test page  # note\n\n2000001\n") == \
        {"2100498": "fires on the lab's test page", "2000001": "disabled"}


def test_spec_and_notice():
    s = (D / "chp-suricata-rules.spec").read_text()
    assert "Vendor:         The CyberHygiene Project" in s and "Requires:       suricata >= 7.0, suricata < 8" in s
    for f in ("chp-suricata.rules", "DISABLED.txt", "ET_DATE", "LICENSE", "NOTICE", "classification.config"):
        assert f in s, f
    n = (D / "NOTICE").read_text()
    assert "Emerging Threats" in n and "ET Open" in n


def test_packages_list():
    p = (Path(__file__).resolve().parents[1] / "appliance/release/PACKAGES.txt").read_text().splitlines()
    assert "suricata epel" in p and "chp-suricata-rules ours" in p
