"""chp-site docs (Plan C3 Task 2): render the site's SSP and POA&M from the stick's profile.ini via the installed
chp-templates renderer (a subprocess)."""
import json
import stat
from pathlib import Path

import pytest
from chp_site import cli

STUB = r'''
import json, os, sys
from pathlib import Path
a = sys.argv[1:]
Path(os.environ["STUB_ARGS"]).write_text(json.dumps(a))
if os.environ.get("STUB_FAIL"):
    sys.stderr.write("profile.ini: organization.admin_password: a key named like a secret\n"); sys.exit(2)
out = Path(a[a.index("--out") + 1]); out.mkdir()
for n in ("ssp.md", "poam.md", "fill-report.md"): (out / n).write_text(n)
print(f"wrote {out}: 2 documents, 7 unfilled placeholders (see fill-report.md)")
'''


@pytest.fixture
def env(tmp_path, monkeypatch):
    t = tmp_path / "chp-templates"
    (t / "rev2").mkdir(parents=True)
    (t / "rev2" / "MANIFEST.json").write_text(json.dumps({"content_version": "1.2.0"}))
    (t / "chpfill.pyz").write_text(STUB)
    stick = tmp_path / "stick"
    (stick / "escrow").mkdir(parents=True)
    (stick / "profile.ini").write_text("[organization]\nlegal_name = Example Manufacturing LLC\n")
    site = tmp_path / "site.conf"
    site.write_text("DOMAIN=example.test\n")
    monkeypatch.setenv("STUB_ARGS", str(tmp_path / "args.json"))
    return {"t": t, "stick": stick, "site": site, "out": tmp_path / "docs", "args": tmp_path / "args.json", "tmp": tmp_path}


def run(e, *extra, stick=True):
    argv = ["docs", "--site", str(e["site"]), "--templates", str(e["t"]), "--out-root", str(e["out"]), *extra]
    if stick:
        argv += ["--stick", str(e["stick"])]
    return cli.main(argv)


def test_renders_with_the_stick_profile_and_root_only_output(env, capsys):
    assert run(env) == 0
    a = json.loads(env["args"].read_text())
    assert a[0] == "fill" and a[a.index("--lib") + 1] == str(env["t"] / "rev2")
    assert a[a.index("--profile") + 1] == str(env["stick"] / "profile.ini")
    assert a[a.index("--site-conf") + 1] == str(env["site"]) and a[a.index("--templates-version") + 1] == "1.2.0"
    outs = list(env["out"].iterdir())
    assert len(outs) == 1 and len(outs[0].name) == 16 and outs[0].name.endswith("Z")
    assert stat.S_IMODE(outs[0].stat().st_mode) == 0o700
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in outs[0].iterdir())
    assert "7 unfilled" in capsys.readouterr().out


def test_second_run_in_the_same_second_never_overwrites(env, monkeypatch):
    from chp_site import docs
    monkeypatch.setattr(docs, "_stamp", lambda: "20261025T120000Z")
    assert run(env) == 0 and run(env) == 0
    assert sorted(p.name for p in env["out"].iterdir()) == ["20261025T120000Z", "20261025T120000Z-2"]


def test_docs_without_a_stick_refuses(env, capsys):
    assert run(env, stick=False) != 0
    assert "stick" in capsys.readouterr().err.lower() and not env["out"].exists()


def test_docs_without_a_profile_renders_with_placeholders(env, capsys):
    (env["stick"] / "profile.ini").unlink()
    assert run(env) == 0
    a = json.loads(env["args"].read_text())
    assert "--profile" not in a and "no profile.ini on the site stick" in capsys.readouterr().out


def test_renderer_error_is_passed_through_and_nothing_is_left(env, monkeypatch, capsys):
    monkeypatch.setenv("STUB_FAIL", "1")
    assert run(env) != 0
    assert "admin_password" in capsys.readouterr().err
    assert not env["out"].exists() or not list(env["out"].iterdir())


def test_docs_without_chp_templates_installed(env, capsys):
    (env["t"] / "chpfill.pyz").unlink()
    assert run(env) != 0 and "install chp-templates" in capsys.readouterr().err


def test_unknown_revision_is_refused(env, capsys):
    assert run(env, "--rev", "rev3") != 0 and "rev3 is not in this chp-templates release" in capsys.readouterr().err


def test_escrow_is_never_read(env):
    (env["stick"] / "escrow" / "secret.txt").write_text("x")
    (env["stick"] / "escrow").chmod(0o000)
    try:
        assert run(env) == 0
    finally:
        (env["stick"] / "escrow").chmod(0o700)
