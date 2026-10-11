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
    # NOT xorriso's "-boot_image any replay": with /images/efiboot.img replaced, replay re-used the DVD's ORIGINAL EFI
    # image as an appended partition (Rocky menu, wrong label; found by check-iso.sh on ISO 0.1.0-rc1). Build from the
    # DVD's tree with the DVD's own mkisofs boot options, so El Torito EFI and the GPT entry point at OUR efiboot.img.
    code = "\n".join(ln for ln in t.splitlines() if not ln.lstrip().startswith("#"))
    assert "replay" not in code and "-as mkisofs" in code
    for opt in ("-R -J -joliet-long", "-b isolinux/isolinux.bin", "-e images/efiboot.img", "-isohybrid-gpt-basdat",
                "-isohybrid-mbr --interval:local_fs:0s-15s:zero_mbrpt,zero_gpt:"):
        assert opt in code, opt
    assert "d2bcbb64c2d67511adf80d40cd9543391a33aea5860a355b1d26d7f55236d01f" in t
    assert "verify-repo.sh" in t and "refusing:" in t
    assert "VOLID=CHP-LAB-EL9" in t and '-V "$VOLID"' in t
    for p in ("/EFI/BOOT/grub.cfg", "/isolinux/isolinux.cfg", "/images/efiboot.img", "/chp", "/NOTICE.txt"):
        assert p in t


def test_check_compares_the_secure_boot_chain_with_the_dvd():
    t = (ISO / "check-iso.sh").read_text()
    for f in ("BOOTX64.EFI", "grubx64.efi", "mmx64.efi", "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img"):
        assert f in t
    assert "efiboot" in t and "isohybrid-gpt-basdat" in t                # Review Focus 5: USB boot path


def test_check_compares_the_usb_boot_partition_bytes_with_efiboot():   # final review I-1 (the rc1 regression)
    t = (ISO / "check-iso.sh").read_text()
    assert "-report_system_area plain" in t and "GPT start and size" in t
    assert "append_partition" in t                                        # an appended EFI partition = BAD
    assert "dd if=" in t and "cmp" in t
