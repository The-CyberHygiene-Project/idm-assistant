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
