from pathlib import Path

ISO = Path(__file__).resolve().parents[1] / "appliance" / "iso"
HEADER = (Path(__file__).resolve().parents[1] / "appliance/branding/file-header.txt").read_text()


def test_scripts_carry_the_header_and_strict_mode():
    for s in ("build-iso.sh", "check-iso.sh", "push.sh", "render-boot.sh"):
        t = (ISO / s).read_text()
        assert t.startswith("#!/usr/bin/env bash\n" + HEADER), s
        assert "set -Eeuo pipefail" in t, s


def test_build_keeps_the_boot_chain_and_pins_inputs():
    t = (ISO / "build-iso.sh").read_text()
    assert "-boot_image any replay" in t and "discard" not in t
    assert "d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f" in t
    assert "verify-repo.sh" in t and "refusing:" in t
    assert "VOLID=CHP-LAB-EL9" in t and '-volid "$VOLID"' in t
    for p in ("/EFI/BOOT/grub.cfg", "/isolinux/isolinux.cfg", "/images/efiboot.img", "/chp", "/NOTICE.txt"):
        assert p in t


def test_check_compares_the_secure_boot_chain_with_the_dvd():
    t = (ISO / "check-iso.sh").read_text()
    for f in ("BOOTX64.EFI", "grubx64.efi", "mmx64.efi", "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img"):
        assert f in t
    assert "efiboot" in t and "isohybrid-gpt-basdat" in t                # Review Focus 5: USB boot path
