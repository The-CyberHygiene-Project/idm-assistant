import base64

import pytest

from chp_site.escrow import move_pending
from chp_site.sitefile import SiteError


def pending(tmp_path):
    p = tmp_path / "pending"; p.mkdir()
    (p / "kanidm-admins.json").write_text('{"admin":"a","idm_admin":"b"}')
    (p / "step-ca-password").write_text("pw\n")
    (p / "root_ca_key").write_text("-----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY-----\n")
    return p


def test_moves_everything_and_shreds_after_read_back(tmp_path):
    p = pending(tmp_path); s = tmp_path / "stick"; s.mkdir()
    moved = move_pending(p, s, "iso3-srv", "20260930T120000Z")
    assert sorted(moved) == ["kanidm-admins.json", "root_ca_key", "step-ca-password"]
    t = (s / "escrow" / "iso3-srv-server.txt").read_text()
    assert base64.b64decode(t.split("ROOT_CA_KEY_PEM=")[1].split()[0]).startswith(b"-----BEGIN EC PRIVATE KEY-----")
    assert list(p.iterdir()) == []


def test_read_only_stick_keeps_the_pending_secrets(tmp_path):          # Review Focus 3
    import os
    p = pending(tmp_path); s = tmp_path / "stick"; s.mkdir(); os.chmod(s, 0o555)
    try:
        with pytest.raises(SiteError, match="kept on the server"):
            move_pending(p, s, "iso3-srv", "20260930T120000Z")
        assert len(list(p.iterdir())) == 3
    finally:
        os.chmod(s, 0o755)


def test_second_export_keeps_the_first_as_old(tmp_path):
    s = tmp_path / "stick"; s.mkdir()
    move_pending(pending(tmp_path), s, "iso3-srv", "A")
    p2 = tmp_path / "p2"; p2.mkdir(); (p2 / "step-ca-password").write_text("pw2\n")
    move_pending(p2, s, "iso3-srv", "B")
    assert (s / "escrow" / "iso3-srv-server.txt.B.old").exists()


def test_nothing_pending(tmp_path):
    p = tmp_path / "empty"; p.mkdir(); s = tmp_path / "stick"; s.mkdir()
    assert move_pending(p, s, "iso3-srv", "A") == [] and not (s / "escrow").exists()


def test_shreds_only_after_a_device_read_back_compares_equal(tmp_path, monkeypatch):   # final review C1
    import chp_site.escrow as esc
    p = pending(tmp_path); s = tmp_path / "stick"; s.mkdir()
    monkeypatch.setattr(esc, "_read_back", lambda path: path.read_text().replace("ROOT_CA_KEY_PEM=", "ROOT_CA_KEY_PEM=X"))
    with pytest.raises(SiteError, match="kept on the server"):
        move_pending(p, s, "iso3-srv", "A")
    assert len(list(p.iterdir())) == 3                      # nothing shredded after a bad read-back


def test_write_is_fsynced_file_and_directory(tmp_path, monkeypatch):
    import chp_site.escrow as esc
    calls = []
    real = esc.os.fsync
    monkeypatch.setattr(esc.os, "fsync", lambda fd: (calls.append(fd), real(fd)))
    monkeypatch.setattr(esc, "_shred", lambda path: None)   # count only the fsyncs of the WRITE, not of the shred
    p = pending(tmp_path); s = tmp_path / "stick"; s.mkdir()
    move_pending(p, s, "iso3-srv", "A")
    assert len(calls) >= 2                                  # the escrow file AND its directory


def test_move_tokens_writes_reads_back_then_shreds(tmp_path):
    from chp_site.escrow import move_tokens
    p = tmp_path / "pending" / "tokens"; p.mkdir(parents=True); stick = tmp_path / "stick"; stick.mkdir()
    (p / "cli1.token").write_text("A" * 30 + "." + "B" * 30 + "." + "C" * 30 + "\n")
    assert move_tokens(p, stick, "20260930T000000Z") == ["cli1"]
    assert (stick / "tokens" / "cli1.token").read_text().startswith("AAAA") and not (p / "cli1.token").exists()
    assert oct((stick / "tokens" / "cli1.token").stat().st_mode & 0o777) == "0o600"


def test_move_tokens_keeps_source_when_readback_differs(tmp_path, monkeypatch):
    from chp_site import escrow
    from chp_site.sitefile import SiteError
    p = tmp_path / "t"; p.mkdir(); stick = tmp_path / "s"; stick.mkdir()
    (p / "cli1.token").write_text("x" * 20 + ".y" + "y" * 20 + ".z" + "z" * 20)
    monkeypatch.setattr(escrow, "_read_back", lambda path: "corrupted")
    with pytest.raises(SiteError, match="kept on the server"):
        escrow.move_tokens(p, stick, "N")
    assert (p / "cli1.token").exists()


def test_move_tokens_replaces_old_as_dot_old(tmp_path):
    from chp_site.escrow import move_tokens
    p = tmp_path / "t"; p.mkdir(); stick = tmp_path / "s"; (stick / "tokens").mkdir(parents=True)
    (stick / "tokens" / "cli1.token").write_text("old")
    (p / "cli1.token").write_text("n" * 20 + ".n" + "n" * 20 + ".n" + "n" * 20)
    move_tokens(p, stick, "NOW")
    assert (stick / "tokens" / "cli1.token.NOW.old").read_text() == "old"
