import importlib.util
from pathlib import Path
from types import SimpleNamespace

D = Path(__file__).resolve().parents[1] / "appliance" / "rpm" / "chp-yara-rules"
spec = importlib.util.spec_from_file_location("build_rules", D / "build-rules.py")
br = importlib.util.module_from_spec(spec); spec.loader.exec_module(br)


def fake_yarac(bad=(), dup=None):
    """A stand-in for yarac: files named in bad fail alone; dup = a file whose rules clash in the combined compile."""
    def run(argv, **kw):
        srcs = [a for a in argv[1:-1] if a.endswith(".yar")]
        out = Path(argv[-1])
        for s in srcs:
            if Path(s).name in bad:
                return SimpleNamespace(returncode=1, stdout="", stderr=f'{s}(3): error: undefined identifier "x"\n')
        if dup and len(srcs) > 1 and any(Path(s).name == dup for s in srcs):
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr=f'{Path(srcs[0]).parent}/{dup}(9): error: duplicated identifier "r"\n')
        out.write_bytes(b"compiled")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def tree(tmp_path, names):
    src = tmp_path / "src"; src.mkdir()
    for n in names:
        (src / n).write_text("rule r_%s { condition: true }\n" % n.replace(".", "_"))
    out = tmp_path / "out"; out.mkdir()
    return src, out


def test_excluded_and_uncompilable_files_are_skipped_with_reasons(tmp_path):
    src, out = tree(tmp_path, ["a.yar", "b.yar", "c.yar"])
    kept, skipped = br.build(src, {"b.yar": "matched /usr/lib64/libfoo.so on a clean server"}, out,
                             run=fake_yarac(bad={"c.yar"}))
    assert (kept, skipped) == (1, 2)
    s = (out / "SKIPPED.txt").read_text()
    assert "b.yar\tfalse alarm on the appliance: matched /usr/lib64/libfoo.so on a clean server" in s
    assert "c.yar\tdoes not compile with plain YARA: " in s
    assert (out / "rules.yarc").read_bytes() == b"compiled"


def test_a_clash_in_the_combined_compile_drops_that_file_and_retries(tmp_path):
    src, out = tree(tmp_path, ["a.yar", "b.yar", "c.yar"])
    kept, skipped = br.build(src, {}, out, run=fake_yarac(dup="b.yar"))
    assert (kept, skipped) == (2, 1)
    assert "b.yar\tclashes with another rule file: " in (out / "SKIPPED.txt").read_text()


def test_externals_are_defined_empty_at_compile_time(tmp_path):
    src, out = tree(tmp_path, ["a.yar"])
    seen = []
    def run(argv, **kw):
        seen.append(argv); Path(argv[-1]).write_bytes(b"c")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    br.build(src, {}, out, run=run)
    for name in ("filename", "filepath", "extension", "filetype", "owner"):
        assert f"--define={name}=" in seen[-1]


def test_exclude_file_format():
    ex = br.load_excludes("# comment\nfoo.yar matched a clean file  # note\n\nbar.yar\n")
    assert ex == {"foo.yar": "matched a clean file", "bar.yar": "excluded"}


def test_spec_pins_yara_and_ships_licence_and_notice():
    s = (D / "chp-yara-rules.spec").read_text()
    assert "Requires:       yara = %{yara_evr}" in s
    for f in ("rules.yarc", "SKIPPED.txt", "COMMIT", "LICENSE", "NOTICE"):
        assert f in s, f
    n = (D / "NOTICE").read_text()
    assert "Neo23x0/signature-base" in n and "Detection Rule License" in n


def test_packages_list_has_the_new_packages():
    p = (Path(__file__).resolve().parents[1] / "appliance" / "release" / "PACKAGES.txt").read_text().splitlines()
    assert "chp-yara-rules ours" in p and "yara rocky" in p


def test_spec_names_our_vendor_so_sign_repo_signs_it():
    # sign-repo signs only Vendor=The CyberHygiene Project + .chp releases (it refused 2026.10.29-1 without it)
    assert "Vendor:         The CyberHygiene Project" in (D / "chp-yara-rules.spec").read_text()
