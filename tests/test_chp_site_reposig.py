import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from chp_site import reposig
from chp_site.cli import main
from chp_site.sitefile import SiteError

TOP = Path(__file__).resolve().parents[1]
GPG = shutil.which("gpg")
needs_gpg = pytest.mark.skipif(GPG is None or shutil.which("gpgv") is None, reason="needs gpg + gpgv")


def test_bundled_key_is_the_release_key():
    assert reposig.bundled_key() == (TOP / "appliance/release/RPM-GPG-KEY-cyberhygiene").read_text()


def test_trusted_primary_matches_the_release_pin():
    pins = [ln.split()[0] for ln in (TOP / "appliance/release/trusted-keys.txt").read_text().splitlines()
            if ln.strip() and not ln.startswith("#") and ln.split()[1] == "cyberhygiene"]
    assert reposig.TRUSTED_PRIMARY == tuple(pins)


def test_primary_from_status_uses_the_last_validsig_field():      # Review Focus 3: subkey signature
    st = ("[GNUPG:] GOODSIG 1111222233334444 t\n"
          "[GNUPG:] VALIDSIG AAAA000000000000000000000000000000000000 2026-10-10 1 0 4 0 1 8 00 "
          "BBBB000000000000000000000000000000000000\n")
    assert reposig.primary_from_status(st) == "BBBB000000000000000000000000000000000000"


def test_primary_from_status_refuses_two_signatures_or_none():
    v = "[GNUPG:] VALIDSIG " + "A" * 40 + " d 1 0 4 0 1 8 00 " + "B" * 40 + "\n"
    with pytest.raises(SiteError):
        reposig.primary_from_status(v + v)
    with pytest.raises(SiteError):
        reposig.primary_from_status("[GNUPG:] NEWSIG\n")


@pytest.fixture(scope="module")
def signer(request):
    if GPG is None:
        pytest.skip("needs gpg")
    # A SHORT home: gpg-agent's socket path must fit in sun_path (104 bytes on macOS); pytest's tmp paths do not.
    home = tempfile.mkdtemp(prefix="gpgt", dir="/tmp")
    request.addfinalizer(lambda: shutil.rmtree(home, ignore_errors=True))
    env = dict(os.environ, GNUPGHOME=home)
    def g(*a, **kw):
        return subprocess.run([GPG, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", *a],
                              env=env, check=True, capture_output=True, **kw)
    g("--quick-gen-key", "repo test <t@example.invalid>", "rsa3072", "sign", "never")
    fpr = next(ln.split(":")[9] for ln in g("--with-colons", "--list-keys").stdout.decode().splitlines()
               if ln.startswith("fpr:"))
    armored = g("--armor", "--export", fpr).stdout.decode()
    binary = g("--export", fpr).stdout
    def make_repo(root, body=b"<repomd/>\n", sign=True):
        rd = root / "repodata"; rd.mkdir(parents=True)
        (rd / "repomd.xml").write_bytes(body)
        if sign:
            g("--armor", "--local-user", fpr, "--detach-sign", "-o", str(rd / "repomd.xml.asc"), str(rd / "repomd.xml"))
        return root
    return {"fpr": fpr, "armored": armored, "binary": binary, "make_repo": make_repo}


@needs_gpg
def test_dearmor_matches_gpg_binary_export(signer):
    assert reposig.dearmor(signer["armored"]) == signer["binary"]


@needs_gpg
@pytest.mark.parametrize("slash", ["", "/"])                        # Review Focus 1
def test_good_signature_by_a_pinned_key(signer, tmp_path, slash):
    r = signer["make_repo"](tmp_path / "repo")
    assert reposig.verify(r.as_uri() + slash, signer["armored"], (signer["fpr"],)) == signer["fpr"]


@needs_gpg
def test_tampered_metadata_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo")
    with open(r / "repodata/repomd.xml", "ab") as f:
        f.write(b"<!-- changed -->\n")
    with pytest.raises(SiteError, match="NOT valid"):
        reposig.verify(r.as_uri(), signer["armored"], (signer["fpr"],))


@needs_gpg
def test_valid_signature_by_an_unpinned_key_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo")
    with pytest.raises(SiteError, match="not a pinned"):
        reposig.verify(r.as_uri(), signer["armored"], ("0" * 40,))


@needs_gpg
def test_missing_signature_file_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo", sign=False)
    with pytest.raises(SiteError, match="cannot read"):
        reposig.verify(r.as_uri(), signer["armored"], (signer["fpr"],))


@needs_gpg
def test_signature_by_a_key_not_in_the_keyring_is_refused(signer, tmp_path):
    r = signer["make_repo"](tmp_path / "repo")
    other = reposig.bundled_key()                      # the real project key: did not make this signature
    with pytest.raises(SiteError, match="NOT valid"):
        reposig.verify(r.as_uri(), other, (signer["fpr"],))


def test_missing_gpgv_stops_with_a_readable_message(tmp_path):      # Review Focus 2
    rd = tmp_path / "repodata"; rd.mkdir()
    (rd / "repomd.xml").write_text("x"); (rd / "repomd.xml.asc").write_text("y")
    with pytest.raises(SiteError, match="gpgv"):
        reposig.verify(tmp_path.as_uri(), reposig.bundled_key(), gpgv="/nonexistent/gpgv")


@needs_gpg
def test_cli_ok_and_refusal(signer, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reposig, "bundled_key", lambda: signer["armored"])
    monkeypatch.setattr(reposig, "TRUSTED_PRIMARY", (signer["fpr"],))
    r = signer["make_repo"](tmp_path / "repo")
    assert main(["verify-repo", "--url", r.as_uri()]) == 0
    assert f"REPO SIGNATURE OK: {r.as_uri()} (signed by {signer['fpr']})" in capsys.readouterr().out
    (r / "repodata/repomd.xml").write_text("tampered")
    assert main(["verify-repo", "--url", r.as_uri()]) == 2
    assert "NOT valid" in capsys.readouterr().err
