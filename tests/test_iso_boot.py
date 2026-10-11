import re
import subprocess
from pathlib import Path

import pytest

ISO = Path(__file__).resolve().parents[1] / "appliance" / "iso"
BANNER = (Path(__file__).resolve().parents[1] / "appliance/branding/boot-banner.txt").read_text()


@pytest.fixture(scope="module")
def out(tmp_path_factory):
    d = tmp_path_factory.mktemp("boot")
    subprocess.run(["bash", str(ISO / "render-boot.sh"), str(d)], check=True, capture_output=True)
    return d


def entries(cfg):
    return re.findall(r"menuentry '([^']+)'[^{]*\{(.*?)\n\}", cfg, re.S)


def test_menu_order_and_kernel_arguments(out):
    e = entries((out / "grub.cfg").read_text())
    titles = [t for t, _ in e]
    assert titles[0].startswith("Install identity server") and titles[1].startswith("Install client workstation")
    assert "serial console" in titles[2] and titles[2].startswith("Install identity server")
    assert "serial console" in titles[3] and titles[3].startswith("Install client workstation")
    assert titles[4] == "Boot from the local disk"
    for i, role in ((0, "server"), (1, "client"), (2, "server"), (3, "client")):
        body = e[i][1]
        assert "inst.stage2=hd:LABEL=CHP-LAB-EL9 " in body
        assert f"inst.ks=hd:LABEL=CHP-LAB-EL9:/chp/ks/{role}.ks" in body
        assert "fips=1" in body and "quiet" not in body and "rd.live.check" not in body
        assert ("console=ttyS0,115200" in body) == (i >= 2)       # serial only on the serial entries
    assert "exit" in e[4][1]


def test_never_installs_on_a_timeout(out):                           # Review Focus 4
    cfg = (out / "grub.cfg").read_text()
    assert re.search(r"^set timeout=-1$", cfg, re.M) and "set default=\"0\"" in cfg


def test_label_and_branding(out):
    cfg = (out / "grub.cfg").read_text()
    assert "search --no-floppy --set=root -l 'CHP-LAB-EL9'" in cfg
    assert not any("Rocky" in t for t, _ in entries(cfg))           # never presented as Rocky Linux
    for line in (ln for ln in BANNER.splitlines() if ln.strip()):
        assert f"echo '{line}'" in cfg


def test_bios_boot_only_says_uefi_is_required(out):
    t = (out / "isolinux.cfg").read_text()
    assert "UEFI" in t and not re.search(r"^\s*(kernel|append|label)\b", t, re.M | re.I)


def test_volid_override(tmp_path):
    subprocess.run(["bash", str(ISO / "render-boot.sh"), str(tmp_path), "TEST-VOL"], check=True, capture_output=True)
    assert "hd:LABEL=TEST-VOL:/chp/ks/server.ks" in (tmp_path / "grub.cfg").read_text()
