"""Which hosts the engine drives. "lab" (default): the aero lab srv1 + client2. "appliance": hosts installed from the CHP
ISO (iso5-srv + iso5-cli2). Scenarios and repairs keep the LOGICAL names srv1/client2; this maps them to real hosts,
names, paths and pins. Read from IDM_PROFILE at every call."""
import json
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Profile:
    name: str
    hostnames: dict
    vms: dict
    ips: dict
    domain: str
    short_names: bool
    login_group: str
    anchor: str
    sshd_dropin: str
    trusted_ca_keys: str
    ca_root_path: str
    ssh_config: Optional[str]
    secrets_prefix: str
    reset: str

    def fqdn(self):
        return f"idm.{self.domain}"

    def group(self, name):
        return name if self.short_names else f"{name}@{self.fqdn()}"

    def ip(self, alias):
        return self.ips[alias]

    def _pins(self):
        from engine import labsecrets
        p = labsecrets.path("pins.json")
        if not p.exists():
            raise FileNotFoundError(f"appliance pins missing: {p} (run lab/iso5/prove.sh adapter after each install)")
        return json.loads(p.read_text())

    def pinned_root(self):
        if self.name == "lab":
            return (ROOT / "lab/trust/kanidm-lab-root.sha256").read_text().strip()
        h = self._pins()["CA_ROOT_SHA256"].upper()
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))

    def pinned_ssh_ca(self):
        if self.name == "lab":
            return (ROOT / "lab/trust/ssh-user-ca.sha256").read_text().strip()
        return self._pins()["SSH_CA_FPR"]


PROFILES = {
    "lab": Profile("lab", {"srv1": "srv1", "client2": "client2"}, {"srv1": "srv1", "client2": "client2"},
                   {"srv1": "192.168.100.10", "client2": "192.168.100.13"}, "kanidm.lab.test", False, "lab_users",
                   "/etc/pki/ca-trust/source/anchors/kanidm-lab-root.crt", "/etc/ssh/sshd_config.d/10-kanidm.conf",
                   "/etc/ssh/trusted_user_ca_keys", "/root/.step/certs/root_ca.crt", None, "", "lab/reset.sh"),
    "appliance": Profile("appliance", {"srv1": "iso5-srv", "client2": "iso5-cli2"},
                         {"srv1": "iso5-srv", "client2": "iso5-cli2"},
                         {"srv1": "192.168.100.50", "client2": "192.168.100.52"}, "iso5.lab.test", True, "chp_users",
                         "/etc/pki/ca-trust/source/anchors/chp-root.crt", "/etc/ssh/sshd_config.d/10-chp.conf",
                         "/etc/ssh/chp_user_ca.pub", "/etc/step-ca/certs/root_ca.crt", "lab/iso5/ssh_config", "iso5-",
                         "lab/iso5/reset.sh"),
}


def current():
    n = os.environ.get("IDM_PROFILE") or "lab"
    if n not in PROFILES:
        raise ValueError(f"IDM_PROFILE={n!r} is not a profile ({', '.join(PROFILES)})")
    return PROFILES[n]
