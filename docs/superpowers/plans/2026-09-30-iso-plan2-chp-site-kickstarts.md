# ISO Plan 2: `chp-site` and the Kickstarts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The site-file tool `chp-site` and the two kickstarts (`server.ks`, `client.ks`). Together they install a
host from the Rocky DVD plus an OEMDRV site stick with **no console typing**. The install stops **before any disk is
touched** when anything about the site, the host or the disk is wrong. It is proven by real installs on aero.

**Architecture:** `chp-site` is a Python 3.9, standard-library-only package (`appliance/chp-site/chp_site/`), shipped
as one zipapp (`chp-site.pyz`) that runs in three places: the Anaconda `%pre`, the installed host (RPM
`/usr/bin/chp-site`), and an admin's Mac or Linux box. The kickstarts are thin. `%pre` mounts the stick and runs
`chp-site pre`, which does these things, in this order:
1. validates everything
2. only then writes the escrow file (LUKS + root console password) to the stick
3. emits `/tmp/chp/*.ks` snippets that the kickstart `%include`s (network, disk, users, time, repo)

`%post --nochroot` copies the non-secret site files to `/etc/chp/`. `chp-site export-client` writes `client.conf` (the
pinned trust values) for the client installs.

**Tech Stack:** Python 3.9 stdlib (the installer and hosts run 3.9.25; the Mac runs 3.14, so there are no 3.10+ features
and no `crypt` import at module level), pytest, `pykickstart` `ksvalidator` (via `uvx`), Anaconda kickstart RHEL9,
virt-install on aero (UEFI + Secure Boot + vTPM, as client1).

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md` (§4 site file, §5.1 kickstart, §10 error handling,
§12 plan 2). Requirements log: `lab/iso-requirements.md` (rows 1, 5, 15, 16, 17).

## Decisions made after the spec (user, 2026-09-29): binding for this plan

1. **Break-glass:** a local `chpadmin` account (in `wheel`) with an **SSH public key from the site stick and no password**.
   `root` is locked for SSH (CUI profile) and gets a **random console password**, which is written to the stick's escrow
   file next to the LUKS passphrase. chpadmin becomes root with `su -` and that password.
2. **Disk:** install only when there is **exactly one** non-USB, non-removable disk. With 2+ candidates the hosts table
   must name the disk (optional 5th column: `sda`, `vda`, `nvme0n1` or `/dev/disk/by-id/…`). Otherwise `%pre` stops
   before touching anything.
3. **`chp-site onboard / revoke / unexpire` move to Plan 3** (server role). This plan covers the site files, the
   validator, host lookup, `export-client`, the `%pre` gate, the kickstarts and the install proof.

## Global Constraints

- `chp-site` is **Python 3.9 syntax and the standard library only**. It is checked by a test that parses every module with
  `ast.parse(…, feature_version=(3, 9))`. `crypt` is imported only inside the hashing function (it is absent from the Mac's Python 3.14).
- **`site.conf`, `hosts` and `client.conf` hold no secrets.** Secrets (LUKS passphrase, root console password) exist only
  in the installer's RAM (`/tmp/chp`, mode 0600) and in the stick's `escrow/<hostname>.txt`. They are **never** printed, logged,
  copied to `/etc/chp`, or put in a kickstart file on disk.
- **Validate everything before writing anything.** The escrow is written only after every check passes. If the escrow cannot
  be written, the install stops. An install never proceeds without its recovery secrets on the stick.
- The site stick is a **secret** after an install (it carries the escrow). Every message that mentions it says so.
- **FIPS:** the admin SSH key must be ECDSA (nistp256/384/521) or RSA ≥ 3072 bits. **`ssh-ed25519` is rejected** (RHEL 9 FIPS
  mode refuses it for SSH). Kickstart: `fips=1`, OpenSCAP **CUI** profile, SELinux enforcing, LUKS2.
- Every shipped script and kickstart starts with the three lines of `appliance/branding/file-header.txt` (for `.py` modules:
  as comments right after any shebang).
- Our RPMs: `Vendor: The CyberHygiene Project`, Release `.chp`, `License: Apache-2.0`, signed through `sign-session.sh`
  (**the user touches the YubiKey**; the PIN dialog may open behind other windows).
- The lab never reaches the internet. Every lab host is disposable, and only the new VMs named `iso2-*` are created or destroyed.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The user has limited vision and typing: nothing in this plan asks the user to type anything except PINs in dialogs.

## Review Focus

1. **Site files edited on Windows or macOS.** CRLF line ends, a UTF-8 BOM, trailing spaces or "smart quotes" in a
   value. Expected: CRLF, BOM and spaces are tolerated; a quote character in a value gives a clear error naming the
   line. Tests: Task 1.
2. **A MAC written in another notation** (upper case, dashes: `52-54-00-C4-02-30`). Expected: it matches the live NIC.
   Test: Task 2.
3. **The stick is read-only or full when the escrow is written.** Expected: `chp-site pre` fails with a clear message,
   writes no snippets, and the install stops before the disks. Test: Task 4.
4. **Re-installing the same host.** Expected: an existing `escrow/<hostname>.txt` is kept, renamed with a timestamp, and
   never silently overwritten. Test: Task 4.
5. **An `ssh-ed25519` admin key** (the OpenSSH default). Expected: rejected by `chp-site validate` on the admin's Mac,
   long before install, with the reason (FIPS). Test: Task 1.

---

## File Structure

```
appliance/chp-site/
  chp_site/
    __init__.py        VERSION
    sitefile.py        strict KEY=value reader, per-key validators, parse_site()
    hosts.py           hosts table parser, MAC normalisation, lookup()
    disks.py           lsblk facts → Disk list, choose_disk()
    clientconf.py      ssh_fpr(), cert_sha256(), make_client_conf(), parse_client_conf()
    render.py          kickstart snippets: misc/net/users/disk/repo
    pre.py             run_pre(): the %pre gate (validate → escrow → snippets)
    facts.py           live facts: MACs from /sys/class/net, disks from lsblk (the only I/O on the host's hardware)
    cli.py             argparse: validate | pre | export-client | --version
  build.sh             zipapp → appliance/chp-site/dist/chp-site.pyz (dist/ is git-ignored)
  chp-site.spec        noarch RPM: /usr/bin/chp-site, pinned key, chp.repo
  chp.repo             /etc/yum.repos.d/chp.repo (disabled until a local repo is unpacked)
  build-rpm.sh         Mac: build the RPM on aero (as idm-collect)
appliance/kickstart/
  chp.ks.in            ONE template; @ROLE@ = server|client
  render-ks.sh         → server.ks, client.ks (committed, and checked to equal the template's rendering)
  server.ks, client.ks
tests/
  test_chp_site_sitefile.py, test_chp_site_hosts.py, test_chp_site_disks.py, test_chp_site_clientconf.py,
  test_chp_site_render.py, test_chp_site_pre.py, test_chp_site_cli.py, test_kickstarts.py
  fixtures/chp-site/   test-only public CA cert + SSH CA public key (generated for the tests; no private halves kept)
lab/iso2/
  site.conf.in, hosts        the lab test site (domain iso2.lab.test; admin key rendered in, never committed)
  make-stick.sh              aero: FAT image labelled OEMDRV from a directory (loop mount, sudo)
  install.sh                 aero: virt-install an iso2-* VM with the stick on USB and chp-site.pyz injected
  prove.sh                   Mac: the whole proof (negatives, server, export-client, client) with PASS/FAIL lines
  PROOF-RECORD.md            results
```
`tests/` (not `appliance/chp-site/tests/`) because pytest's `testpaths` is `tests`. The tests import `chp_site` through a
`conftest.py` path entry.

---

### Task 1: `sitefile.py`: the strict reader and `site.conf` validation

**Files:**
- Create: `appliance/chp-site/chp_site/__init__.py`, `appliance/chp-site/chp_site/sitefile.py`, `tests/conftest.py` (or modify, if it exists),
  `tests/test_chp_site_sitefile.py`

**Interfaces:**
- Produces: `class SiteError(ValueError)`; `read_kv(text: str, name: str) -> dict[str,str]`;
  `parse_site(text: str) -> dict[str, object]`. Its keys:
  - `DOMAIN` str; `SUBNET` `ipaddress.IPv4Network`; `GATEWAY` `IPv4Address`
  - `DNS_FORWARDERS` list[str]; `NTP_UPSTREAM` list[str]; `TIMEZONE` str
  - `ISSO_NAME` str; `UNEXPIRE_DELEGATES` list[str]; `COLLECTOR_IP` str (may be "")
  - `ACCESSIBILITY` "on"|"off"; `ALERT_HOOK` str (may be ""); `ADMIN_SSH_PUBKEY` str (normalised "type base64")
- Also `ssh_pubkey(v: str) -> str` (validator, reused by Task 3). `LABEL_RE` (reused by Task 2).

- [ ] **Step 1: Path entry for the tests.** If `tests/conftest.py` exists, append; otherwise create:
  ```python
  import sys
  from pathlib import Path

  sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "appliance" / "chp-site"))
  ```

- [ ] **Step 2: Write the failing tests** `tests/test_chp_site_sitefile.py`:
  ```python
  import ast
  import base64
  import ipaddress
  import struct
  from pathlib import Path

  import pytest

  from chp_site.sitefile import SiteError, parse_site, read_kv, ssh_pubkey

  PKG = Path(__file__).resolve().parents[1] / "appliance" / "chp-site" / "chp_site"


  def _blob(*parts):
      return base64.b64encode(b"".join(struct.pack(">I", len(p)) + p for p in parts)).decode()


  ECDSA = "ecdsa-sha2-nistp384 " + _blob(b"ecdsa-sha2-nistp384", b"nistp384", b"\x04" + b"\x01" * 96)
  RSA3072 = "ssh-rsa " + _blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + b"\xff" * 384)
  RSA2048 = "ssh-rsa " + _blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + b"\xff" * 256)
  ED25519 = "ssh-ed25519 " + _blob(b"ssh-ed25519", b"\x02" * 32)

  GOOD = f"""# lab site
  DOMAIN=iso2.lab.test
  SUBNET=192.168.100.0/24
  GATEWAY=192.168.100.1
  DNS_FORWARDERS=
  NTP_UPSTREAM=192.168.100.1
  TIMEZONE=America/Denver
  ISSO_NAME=D. Shannon
  UNEXPIRE_DELEGATES=J. Shannon, Deputy ISSO
  COLLECTOR_IP=192.168.100.1
  ACCESSIBILITY=off
  ALERT_HOOK=
  ADMIN_SSH_PUBKEY={ECDSA} chpadmin@mac
  """


  def test_every_module_is_python_39_syntax():
      for f in PKG.glob("*.py"):
          ast.parse(f.read_text(), filename=str(f), feature_version=(3, 9))


  def test_good_site_parses_and_normalises():
      s = parse_site(GOOD)
      assert s["DOMAIN"] == "iso2.lab.test"
      assert s["SUBNET"] == ipaddress.IPv4Network("192.168.100.0/24")
      assert s["GATEWAY"] == ipaddress.IPv4Address("192.168.100.1")
      assert s["DNS_FORWARDERS"] == [] and s["NTP_UPSTREAM"] == ["192.168.100.1"]
      assert s["UNEXPIRE_DELEGATES"] == ["J. Shannon", "Deputy ISSO"]
      assert s["ADMIN_SSH_PUBKEY"] == ECDSA          # comment dropped
      assert s["ACCESSIBILITY"] == "off" and s["ALERT_HOOK"] == ""


  def test_optional_keys_default():
      text = "\n".join(l for l in GOOD.splitlines() if not l.startswith(("DNS_", "UNEXPIRE", "COLLECTOR", "ACCESS", "ALERT")))
      s = parse_site(text)
      assert s["DNS_FORWARDERS"] == [] and s["ACCESSIBILITY"] == "off" and s["COLLECTOR_IP"] == ""


  def test_crlf_bom_and_trailing_spaces_are_tolerated():          # Review Focus 1
      s = parse_site("﻿" + GOOD.replace("\n", "  \r\n"))
      assert s["DOMAIN"] == "iso2.lab.test"


  @pytest.mark.parametrize("line,why", [
      ("DOMAIN=“iso2.lab.test”", "DOMAIN"),                      # smart quotes (Review Focus 1)
      ('DOMAIN="iso2.lab.test"', "DOMAIN"),
      ("DOMAIN=ISO2.lab.test", "DOMAIN"),                        # upper case
      ("DOMAIN=localhost", "DOMAIN"),                            # one label
      ("SUBNET=192.168.100.5/24", "SUBNET"),                     # host bits set
      ("GATEWAY=10.0.0.1", "GATEWAY"),                           # outside SUBNET
      ("TIMEZONE=Mountain", "TIMEZONE"),
      ("ACCESSIBILITY=yes", "ACCESSIBILITY"),
      ("ALERT_HOOK=relative/path", "ALERT_HOOK"),
      ("COLLECTOR_IP=10.0.0.9", "COLLECTOR_IP"),
      ("ISSO_NAME=", "ISSO_NAME"),
  ])
  def test_bad_values_name_the_key(line, why):
      key = line.split("=", 1)[0]
      text = "\n".join(line if l.startswith(key + "=") else l for l in GOOD.splitlines())
      with pytest.raises(SiteError, match=why):
          parse_site(text)


  def test_unknown_key_missing_key_duplicate_key_and_no_equals():
      with pytest.raises(SiteError, match="unknown key NTP_SERVER"):
          parse_site(GOOD + "NTP_SERVER=1.2.3.4\n")
      with pytest.raises(SiteError, match="DOMAIN is required"):
          parse_site("\n".join(l for l in GOOD.splitlines() if not l.startswith("DOMAIN=")))
      with pytest.raises(SiteError, match="line 14: DOMAIN is set twice"):
          parse_site(GOOD + "DOMAIN=other.lab.test\n")
      with pytest.raises(SiteError, match="line 2: expected KEY=value"):
          read_kv("A=1\njust words\n", "site.conf")


  def test_admin_key_types():                                      # Review Focus 5
      assert ssh_pubkey(ECDSA + " c") == ECDSA
      assert ssh_pubkey(RSA3072) == RSA3072
      with pytest.raises(SiteError, match="ed25519.*FIPS"):
          ssh_pubkey(ED25519)
      with pytest.raises(SiteError, match="3072"):
          ssh_pubkey(RSA2048)
      with pytest.raises(SiteError, match="does not match"):     # declared type vs the type inside the blob
          ssh_pubkey("ecdsa-sha2-nistp256 " + ECDSA.split()[1])
      with pytest.raises(SiteError):
          ssh_pubkey('from="10.0.0.1" ' + ECDSA)                # options are not a key
  ```
  Run: `uv run pytest tests/test_chp_site_sitefile.py -q`. Expected: FAIL (`ModuleNotFoundError: chp_site`).

- [ ] **Step 3: Write `appliance/chp-site/chp_site/__init__.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """chp-site: the CyberHygiene site files (site.conf, hosts, client.conf) and the installer's %pre gate."""
  VERSION = "0.1.0"
  ```

- [ ] **Step 4: Write `appliance/chp-site/chp_site/sitefile.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """Strict KEY=value reader and site.conf validation. Nothing here is ever evaluated by a shell."""
  import base64
  import ipaddress
  import re
  import struct

  LABEL_RE = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


  class SiteError(ValueError):
      """A problem in the site files; str() is the message shown at the install console."""


  def read_kv(text, name):
      """KEY=value lines; blank lines and '#' comments ignored. A UTF-8 BOM, CRLF and surrounding spaces are tolerated
      (files edited on Windows/macOS). A line without '=', a key that is not UPPER_CASE, or a repeated key is an error."""
      if text.startswith("﻿"):
          text = text[1:]
      out = {}
      for n, raw in enumerate(text.splitlines(), 1):
          line = raw.strip()
          if not line or line.startswith("#"):
              continue
          if "=" not in line:
              raise SiteError(f"{name} line {n}: expected KEY=value, got {raw.strip()!r}")
          k, v = (p.strip() for p in line.split("=", 1))
          if not re.fullmatch(r"[A-Z][A-Z0-9_]*", k):
              raise SiteError(f"{name} line {n}: bad key {k!r} (keys are UPPER_CASE)")
          if k in out:
              raise SiteError(f"{name} line {n}: {k} is set twice")
          out[k] = v
      return out


  def _plain(k, v):
      if re.search(r"[\"'“”‘’`$\\;|&<>]", v):
          raise SiteError(f"{k}: quotes and shell characters are not allowed in values ({v!r})")
      return v


  def domain(v):
      if len(v) > 253 or not re.fullmatch(rf"{LABEL_RE}(?:\.{LABEL_RE})+", v):
          raise SiteError(f"DOMAIN: {v!r} is not a lower-case DNS domain with at least two labels")
      return v


  def _ip(k, v):
      try:
          return ipaddress.IPv4Address(v)
      except ValueError:
          raise SiteError(f"{k}: {v!r} is not an IPv4 address") from None


  def _list(v):
      return [x for x in re.split(r"[,\s]+", v) if x]


  def _host_or_ip(k, v):
      try:
          ipaddress.IPv4Address(v)
          return v
      except ValueError:
          if re.fullmatch(rf"{LABEL_RE}(?:\.{LABEL_RE})*", v):
              return v
          raise SiteError(f"{k}: {v!r} is neither an IPv4 address nor a host name") from None


  def ssh_pubkey(v):
      """An OpenSSH public key usable on a FIPS host: ECDSA nistp256/384/521 or RSA >= 3072 bits. Returns 'type base64'."""
      f = v.split()
      if len(f) < 2:
          raise SiteError("ADMIN_SSH_PUBKEY: expected '<type> <base64> [comment]'")
      typ, b64 = f[0], f[1]
      if typ == "ssh-ed25519":
          raise SiteError("ADMIN_SSH_PUBKEY: ssh-ed25519 keys cannot be used on a FIPS host; "
                          "make an ECDSA key: ssh-keygen -t ecdsa -b 384")
      if typ not in ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"):
          raise SiteError(f"ADMIN_SSH_PUBKEY: key type {typ!r} is not usable (want ECDSA or RSA >= 3072)")
      try:
          blob = base64.b64decode(b64, validate=True)
          parts, i = [], 0
          while i < len(blob):
              (n,) = struct.unpack(">I", blob[i:i + 4])
              parts.append(blob[i + 4:i + 4 + n])
              i += 4 + n
      except Exception:
          raise SiteError("ADMIN_SSH_PUBKEY: the key data is not valid base64/OpenSSH") from None
      if not parts or parts[0].decode(errors="replace") != typ:
          raise SiteError(f"ADMIN_SSH_PUBKEY: declared type {typ} does not match the key data")
      if typ == "ssh-rsa":
          bits = (len(parts[2].lstrip(b"\x00")) * 8) if len(parts) >= 3 else 0
          if bits < 3072:
              raise SiteError(f"ADMIN_SSH_PUBKEY: RSA key is {bits} bits; at least 3072 are required")
      return f"{typ} {b64}"


  _TZ = r"UTC|[A-Z][A-Za-z_]+(?:/[A-Za-z0-9_+-]+){1,2}"
  _PATH = r"(?:/[A-Za-z0-9._-]+)+"
  _NAME = r"[^\x00-\x1f=,]{1,64}"


  def parse_site(text):
      raw = read_kv(text, "site.conf")
      for k, v in raw.items():
          _plain(k, v)
      known = {"DOMAIN", "SUBNET", "GATEWAY", "DNS_FORWARDERS", "NTP_UPSTREAM", "TIMEZONE", "ISSO_NAME",
               "UNEXPIRE_DELEGATES", "COLLECTOR_IP", "ACCESSIBILITY", "ALERT_HOOK", "ADMIN_SSH_PUBKEY"}
      for k in raw:
          if k not in known:
              raise SiteError(f"site.conf: unknown key {k}")
      for k in ("DOMAIN", "SUBNET", "GATEWAY", "NTP_UPSTREAM", "TIMEZONE", "ISSO_NAME", "ADMIN_SSH_PUBKEY"):
          if not raw.get(k):
              raise SiteError(f"site.conf: {k} is required")
      s = {"DOMAIN": domain(raw["DOMAIN"])}
      try:
          s["SUBNET"] = ipaddress.IPv4Network(raw["SUBNET"], strict=True)
      except ValueError:
          raise SiteError(f"SUBNET: {raw['SUBNET']!r} is not a network in CIDR form (host bits must be zero)") from None
      if not 8 <= s["SUBNET"].prefixlen <= 30:
          raise SiteError("SUBNET: prefix must be /8 to /30")
      s["GATEWAY"] = _ip("GATEWAY", raw["GATEWAY"])
      if s["GATEWAY"] not in s["SUBNET"]:
          raise SiteError(f"GATEWAY: {s['GATEWAY']} is outside SUBNET {s['SUBNET']}")
      s["DNS_FORWARDERS"] = [str(_ip("DNS_FORWARDERS", x)) for x in _list(raw.get("DNS_FORWARDERS", ""))]
      s["NTP_UPSTREAM"] = [_host_or_ip("NTP_UPSTREAM", x) for x in _list(raw["NTP_UPSTREAM"])]
      if not re.fullmatch(_TZ, raw["TIMEZONE"]):
          raise SiteError(f"TIMEZONE: {raw['TIMEZONE']!r} is not a zone name like America/Denver or UTC")
      s["TIMEZONE"] = raw["TIMEZONE"]
      if not re.fullmatch(_NAME, raw["ISSO_NAME"]):
          raise SiteError("ISSO_NAME: 1-64 printable characters, no '=' or ','")
      s["ISSO_NAME"] = raw["ISSO_NAME"]
      dels = [x.strip() for x in raw.get("UNEXPIRE_DELEGATES", "").split(",") if x.strip()]
      for d in dels:
          if not re.fullmatch(_NAME, d):
              raise SiteError(f"UNEXPIRE_DELEGATES: bad name {d!r}")
      s["UNEXPIRE_DELEGATES"] = dels
      c = raw.get("COLLECTOR_IP", "")
      if c and _ip("COLLECTOR_IP", c) not in s["SUBNET"]:
          raise SiteError(f"COLLECTOR_IP: {c} is outside SUBNET {s['SUBNET']}")
      s["COLLECTOR_IP"] = c
      a = raw.get("ACCESSIBILITY", "off") or "off"
      if a not in ("on", "off"):
          raise SiteError("ACCESSIBILITY: on or off")
      s["ACCESSIBILITY"] = a
      h = raw.get("ALERT_HOOK", "")
      if h and not re.fullmatch(_PATH, h):
          raise SiteError(f"ALERT_HOOK: {h!r} is not an absolute path")
      s["ALERT_HOOK"] = h
      s["ADMIN_SSH_PUBKEY"] = ssh_pubkey(raw["ADMIN_SSH_PUBKEY"])
      return s
  ```
  (The smart-quote test fails in `_plain` before `domain`: its message names the key, so `match="DOMAIN"` holds.)

- [ ] **Step 5: Run the tests.** `uv run pytest tests/test_chp_site_sitefile.py -q`. Expected: all pass. Then `uv run pytest -q`
  to confirm the whole suite is green.

- [ ] **Step 6: Commit** `appliance/chp-site/chp_site/{__init__,sitefile}.py tests/conftest.py tests/test_chp_site_sitefile.py` with the message
  `ISO Plan 2 Task 1: chp-site strict site.conf reader + validators (FIPS-usable admin key, CRLF/BOM tolerant)`.

---

### Task 2: `hosts.py`: the hosts table and MAC lookup

**Files:**
- Create: `appliance/chp-site/chp_site/hosts.py`, `tests/test_chp_site_hosts.py`

**Interfaces:**
- Consumes: `SiteError`, `LABEL_RE`, `parse_site` (Task 1).
- Produces: `Host = namedtuple("Host", "mac hostname ip role disk")`, where `mac` is lower-case colon form, `ip` a str, and
  `disk` is "" or a name/by-id path; `norm_mac(s) -> str | None`; `parse_hosts(text, site) -> list[Host]`;
  `lookup(hosts, macs) -> Host`; `server_of(hosts) -> Host`.

- [ ] **Step 1: Write the failing tests** `tests/test_chp_site_hosts.py`:
  ```python
  import pytest

  from chp_site.hosts import lookup, norm_mac, parse_hosts, server_of
  from chp_site.sitefile import SiteError, parse_site
  from tests.test_chp_site_sitefile import GOOD

  SITE = parse_site(GOOD)
  HOSTS = """# MAC               hostname  IP              role    [disk]
  52:54:00:c4:02:30  iso2-srv  192.168.100.30  server
  52:54:00:c4:02:31  iso2-cli  192.168.100.31  client  vda
  """


  def test_parse_and_lookup():
      hs = parse_hosts(HOSTS, SITE)
      assert [h.hostname for h in hs] == ["iso2-srv", "iso2-cli"]
      assert lookup(hs, ["aa:bb:cc:dd:ee:ff", "52:54:00:c4:02:31"]).hostname == "iso2-cli"
      assert server_of(hs).ip == "192.168.100.30"
      assert hs[1].disk == "vda" and hs[0].disk == ""


  @pytest.mark.parametrize("raw", ["52-54-00-C4-02-30", "52:54:00:C4:02:30", " 52:54:00:c4:02:30 "])
  def test_mac_notations_match(raw):                                 # Review Focus 2
      assert norm_mac(raw) == "52:54:00:c4:02:30"


  def test_unknown_machine_stops_with_its_macs():
      with pytest.raises(SiteError, match=r"not in the hosts table.*aa:bb:cc:dd:ee:ff"):
          lookup(parse_hosts(HOSTS, SITE), ["aa:bb:cc:dd:ee:ff"])


  def test_crlf_hosts_file_is_fine():
      assert len(parse_hosts(HOSTS.replace("\n", "\r\n"), SITE)) == 2


  @pytest.mark.parametrize("bad,why", [
      ("52:54:00:c4:02:30 iso2-srv 192.168.100.30 server\n52:54:00:c4:02:30 b 192.168.100.32 client", "MAC .* twice"),
      ("52:54:00:c4:02:30 iso2-srv 192.168.100.30 server\n52:54:00:c4:02:31 iso2-srv 192.168.100.32 client", "hostname .* twice"),
      ("52:54:00:c4:02:30 a 192.168.100.30 server\n52:54:00:c4:02:31 b 192.168.100.30 client", "IP .* twice"),
      ("52:54:00:c4:02:31 b 192.168.100.31 client", "exactly one server"),
      ("52:54:00:c4:02:30 a 192.168.100.30 server\n52:54:00:c4:02:31 b 192.168.100.31 server", "exactly one server"),
      ("52:54:00:c4:02:30 a 10.0.0.5 server", "outside SUBNET"),
      ("52:54:00:c4:02:30 a 192.168.100.1 server", "is the GATEWAY"),
      ("52:54:00:c4:02:30 a 192.168.100.255 server", "broadcast"),
      ("52:54:00:c4:02:30 Srv_1 192.168.100.30 server", "hostname"),
      ("zz:54:00:c4:02:30 a 192.168.100.30 server", "MAC"),
      ("52:54:00:c4:02:30 a 192.168.100.30 router", "role"),
      ("52:54:00:c4:02:30 a 192.168.100.30 server ../../etc/passwd", "disk"),
      ("52:54:00:c4:02:30 a 192.168.100.30", "4 or 5 fields"),
  ])
  def test_bad_tables_say_why(bad, why):
      with pytest.raises(SiteError, match=why):
          parse_hosts(bad, SITE)


  def test_by_id_disk_is_allowed():
      hs = parse_hosts("52:54:00:c4:02:30 a 192.168.100.30 server /dev/disk/by-id/nvme-Samsung_SSD_980_S64DNX0R\n", SITE)
      assert hs[0].disk.startswith("/dev/disk/by-id/")
  ```
  Run: `uv run pytest tests/test_chp_site_hosts.py -q`. Expected: FAIL (no `chp_site.hosts`).

- [ ] **Step 2: Write `appliance/chp-site/chp_site/hosts.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """The hosts table: '<MAC> <hostname> <IP> <server|client> [disk]' per line; lookup by the machine's own MACs."""
  import ipaddress
  import re
  from collections import namedtuple

  from .sitefile import LABEL_RE, SiteError

  Host = namedtuple("Host", "mac hostname ip role disk")
  _DISK = r"(?:sd[a-z]{1,2}|vd[a-z]{1,2}|nvme\d+n\d+|/dev/disk/by-id/[A-Za-z0-9._:+-]+)"


  def norm_mac(s):
      h = re.sub(r"[:-]", "", s.strip().lower())
      if not re.fullmatch(r"[0-9a-f]{12}", h) or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", s.strip()):
          return None
      return ":".join(h[i:i + 2] for i in range(0, 12, 2))


  def parse_hosts(text, site):
      if text.startswith("﻿"):
          text = text[1:]
      net, gw = site["SUBNET"], site["GATEWAY"]
      hosts, seen = [], {"MAC": set(), "hostname": set(), "IP": set()}
      for n, raw in enumerate(text.splitlines(), 1):
          line = raw.split("#", 1)[0].strip()
          if not line:
              continue
          f = line.split()
          if len(f) not in (4, 5):
              raise SiteError(f"hosts line {n}: expected 4 or 5 fields (MAC hostname IP role [disk]), got {len(f)}")
          mac = norm_mac(f[0])
          if not mac:
              raise SiteError(f"hosts line {n}: {f[0]!r} is not a MAC address")
          if not re.fullmatch(LABEL_RE, f[1]):
              raise SiteError(f"hosts line {n}: hostname {f[1]!r} must be one lower-case DNS label")
          try:
              ip = ipaddress.IPv4Address(f[2])
          except ValueError:
              raise SiteError(f"hosts line {n}: {f[2]!r} is not an IPv4 address") from None
          if ip not in net:
              raise SiteError(f"hosts line {n}: {ip} is outside SUBNET {net}")
          if ip == gw:
              raise SiteError(f"hosts line {n}: {ip} is the GATEWAY")
          if ip in (net.network_address, net.broadcast_address):
              raise SiteError(f"hosts line {n}: {ip} is the network or broadcast address")
          if f[3] not in ("server", "client"):
              raise SiteError(f"hosts line {n}: role must be server or client, got {f[3]!r}")
          disk = f[4] if len(f) == 5 else ""
          if disk and not re.fullmatch(_DISK, disk):
              raise SiteError(f"hosts line {n}: disk {disk!r} must be sdX, vdX, nvmeNnM or /dev/disk/by-id/...")
          for what, val in (("MAC", mac), ("hostname", f[1]), ("IP", str(ip))):
              if val in seen[what]:
                  raise SiteError(f"hosts line {n}: {what} {val} appears twice")
              seen[what].add(val)
          hosts.append(Host(mac, f[1], str(ip), f[3], disk))
      if sum(h.role == "server" for h in hosts) != 1:
          raise SiteError("hosts: there must be exactly one server")
      return hosts


  def server_of(hosts):
      return next(h for h in hosts if h.role == "server")


  def lookup(hosts, macs):
      mine = {norm_mac(m) for m in macs} - {None}
      hit = [h for h in hosts if h.mac in mine]
      if not hit:
          raise SiteError("this machine is not in the hosts table (its MACs: " + ", ".join(sorted(mine)) + ")")
      if len(hit) > 1:
          raise SiteError("this machine matches more than one hosts line: " + ", ".join(h.hostname for h in hit))
      return hit[0]
  ```

- [ ] **Step 3: Run the tests.** `uv run pytest tests/test_chp_site_hosts.py -q`, then `uv run pytest -q`. Expected: all pass.

- [ ] **Step 4: Commit** with the message `ISO Plan 2 Task 2: hosts table + MAC lookup (any MAC notation; one server; no gateway/broadcast IPs)`.

---

### Task 3: `disks.py` and `clientconf.py`: disk choice and the pinned client values

**Files:**
- Create: `appliance/chp-site/chp_site/disks.py`, `appliance/chp-site/chp_site/clientconf.py`,
  `tests/test_chp_site_disks.py`, `tests/test_chp_site_clientconf.py`,
  `tests/fixtures/chp-site/root_ca.crt`, `tests/fixtures/chp-site/user_ca.pub`

**Interfaces:**
- Produces:
  - `Disk = namedtuple("Disk", "name size tran rm by_id")`, where `size` is bytes, `rm` is bool and `by_id` a list of `/dev/disk/by-id/...` paths
  - `disks_from_lsblk(json_text, by_id: dict[name, list[path]]) -> list[Disk]`
  - `choose_disk(disks, wanted: str, min_bytes=100_000_000_000) -> str` (a kernel name)
  - `ssh_fpr(pub) -> "SHA256:…"`; `cert_sha256(pem) -> hex`
  - `make_client_conf(domain, root_pem, ssh_ca_pub) -> str`; `parse_client_conf(text, site) -> dict`
- `client.conf` keys: `CA_ROOT_SHA256`, `SSH_CA_PUBKEY`, `SSH_CA_FPR`, `KANIDM_URL`.

- [ ] **Step 1: Make the test fixtures** (public halves only; the private keys are deleted at once).
  ```bash
  D=tests/fixtures/chp-site; mkdir -p $D; T=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $T/k -subj "/CN=chp-site test root" -days 3650 -out $D/root_ca.crt
  ssh-keygen -q -t ecdsa -b 384 -N '' -C 'chp-site test ssh ca' -f $T/ca && cp $T/ca.pub $D/user_ca.pub
  rm -rf $T; openssl x509 -in $D/root_ca.crt -noout -fingerprint -sha256; ssh-keygen -lf $D/user_ca.pub
  ```
  (The tests compute the expected fingerprints with the same two tools at run time.)

- [ ] **Step 2: Write the failing tests.** `tests/test_chp_site_disks.py`:
  ```python
  import json

  import pytest

  from chp_site.disks import choose_disk, disks_from_lsblk
  from chp_site.sitefile import SiteError

  G = 1_000_000_000


  def _ls(*devs):
      return json.dumps({"blockdevices": [dict(zip(("name", "size", "tran", "rm", "type"), d)) for d in devs]})


  def test_one_candidate_is_chosen_usb_and_cdrom_ignored():
      ds = disks_from_lsblk(_ls(("vda", 120 * G, "virtio", False, "disk"), ("sda", 8 * G, "usb", True, "disk"),
                                ("sr0", 11 * G, "sata", True, "rom")), {})
      assert choose_disk(ds, "") == "vda"


  def test_two_candidates_need_a_name():
      ds = disks_from_lsblk(_ls(("vda", 120 * G, "virtio", False, "disk"), ("vdb", 120 * G, "virtio", False, "disk")), {})
      with pytest.raises(SiteError, match="2 disks could be the install disk.*vda.*vdb.*5th column"):
          choose_disk(ds, "")
      assert choose_disk(ds, "vdb") == "vdb"


  def test_named_by_id_and_bad_names():
      ds = disks_from_lsblk(_ls(("nvme0n1", 512 * G, "nvme", False, "disk")),
                            {"nvme0n1": ["/dev/disk/by-id/nvme-Samsung_X"]})
      assert choose_disk(ds, "/dev/disk/by-id/nvme-Samsung_X") == "nvme0n1"
      with pytest.raises(SiteError, match="not found"):
          choose_disk(ds, "sdz")
      usb = disks_from_lsblk(_ls(("sda", 500 * G, "usb", False, "disk")), {})
      with pytest.raises(SiteError, match="USB"):
          choose_disk(usb, "sda")


  def test_no_disk_and_too_small():
      with pytest.raises(SiteError, match="no install disk"):
          choose_disk(disks_from_lsblk(_ls(("sda", 8 * G, "usb", True, "disk")), {}), "")
      with pytest.raises(SiteError, match="at least 100 GB"):
          choose_disk(disks_from_lsblk(_ls(("vda", 40 * G, "virtio", False, "disk")), {}), "")
  ```
  `tests/test_chp_site_clientconf.py` (put the two printed fingerprints into `ROOT_SHA` and `SSH_FPR`, lower-case hex without colons):
  ```python
  import subprocess
  from pathlib import Path

  import pytest

  from chp_site.clientconf import cert_sha256, make_client_conf, parse_client_conf, ssh_fpr
  from chp_site.sitefile import SiteError, parse_site
  from tests.test_chp_site_sitefile import GOOD

  FX = Path(__file__).parent / "fixtures" / "chp-site"
  PEM = (FX / "root_ca.crt").read_text()
  PUB = (FX / "user_ca.pub").read_text()
  SITE = parse_site(GOOD)
  # Expected values come from the reference tools, not from our own code:
  ROOT_SHA = subprocess.run(["openssl", "x509", "-in", str(FX / "root_ca.crt"), "-noout", "-fingerprint", "-sha256"],
                            capture_output=True, text=True, check=True).stdout.split("=", 1)[1].strip().replace(":", "").lower()
  SSH_FPR = subprocess.run(["ssh-keygen", "-lf", str(FX / "user_ca.pub")], capture_output=True, text=True,
                           check=True).stdout.split()[1]


  def test_fingerprints_match_openssl_and_ssh_keygen():
      assert cert_sha256(PEM) == ROOT_SHA
      assert ssh_fpr(PUB) == SSH_FPR


  def test_round_trip():
      c = parse_client_conf(make_client_conf("iso2.lab.test", PEM, PUB), SITE)
      assert c["KANIDM_URL"] == "https://idm.iso2.lab.test" and c["SSH_CA_FPR"] == SSH_FPR


  @pytest.mark.parametrize("edit,why", [
      (lambda t: t.replace(SSH_FPR, "SHA256:" + "A" * 43), "SSH_CA_FPR does not match"),
      (lambda t: t.replace("idm.iso2.lab.test", "idm.other.test"), "KANIDM_URL"),
      (lambda t: t.replace(ROOT_SHA, "zz"), "CA_ROOT_SHA256"),
      (lambda t: "\n".join(l for l in t.splitlines() if not l.startswith("SSH_CA_PUBKEY")), "SSH_CA_PUBKEY is required"),
  ])
  def test_tampered_client_conf_is_refused(edit, why):
      with pytest.raises(SiteError, match=why):
          parse_client_conf(edit(make_client_conf("iso2.lab.test", PEM, PUB)), SITE)


  def test_no_certificate_in_pem():
      with pytest.raises(SiteError, match="no CERTIFICATE"):
          cert_sha256("hello")
  ```
  Run both files. Expected: FAIL (modules missing).

- [ ] **Step 3: Write `appliance/chp-site/chp_site/disks.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """Pick the install disk. A wrong answer destroys data, so: exactly one candidate, or the hosts table names it."""
  import json
  from collections import namedtuple

  from .sitefile import SiteError

  Disk = namedtuple("Disk", "name size tran rm by_id")


  def disks_from_lsblk(json_text, by_id):
      """`lsblk -J -b -d -o NAME,SIZE,TRAN,RM,TYPE` output; by_id maps kernel name -> [/dev/disk/by-id/... paths]."""
      out = []
      for d in json.loads(json_text).get("blockdevices", []):
          if d.get("type") != "disk" or str(d.get("name", "")).startswith(("loop", "zram", "sr")):
              continue
          rm = d.get("rm") in (True, 1, "1", "true")
          out.append(Disk(d["name"], int(d.get("size") or 0), d.get("tran") or "", rm, by_id.get(d["name"], [])))
      return out


  def choose_disk(disks, wanted, min_bytes=100_000_000_000):
      cands = [d for d in disks if d.tran != "usb" and not d.rm]
      if wanted:
          hit = [d for d in disks if wanted in (d.name, f"/dev/{d.name}") or wanted in d.by_id]
          if not hit:
              raise SiteError(f"install disk {wanted!r} (hosts table) not found on this machine; disks: "
                              + ", ".join(d.name for d in disks))
          d = hit[0]
          if d not in cands:
              raise SiteError(f"install disk {wanted!r} is a USB or removable device; refusing to install on it")
      else:
          if not cands:
              raise SiteError("no install disk: only USB/removable devices found")
          if len(cands) > 1:
              raise SiteError(f"{len(cands)} disks could be the install disk (" + ", ".join(d.name for d in cands)
                              + "): name one in the hosts table (5th column) so the right one is wiped")
          d = cands[0]
      if d.size < min_bytes:
          raise SiteError(f"install disk {d.name} is {d.size // 10**9} GB; at least 100 GB are required")
      return d.name
  ```

- [ ] **Step 4: Write `appliance/chp-site/chp_site/clientconf.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """client.conf: the server's trust values pinned for client installs (written by export-client, never by hand)."""
  import base64
  import hashlib
  import re

  from .sitefile import SiteError, read_kv, ssh_pubkey


  def cert_sha256(pem):
      m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", pem, re.S)
      if not m:
          raise SiteError("no CERTIFICATE block in the CA root file")
      return hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest()


  def ssh_fpr(pub):
      blob = base64.b64decode(pub.split()[1])
      return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


  def make_client_conf(domain, root_pem, ssh_ca_pub):
      key = ssh_pubkey(ssh_ca_pub)
      return ("# client.conf: written by `chp-site export-client` on the server. Do not edit.\n"
              f"CA_ROOT_SHA256={cert_sha256(root_pem)}\n"
              f"SSH_CA_PUBKEY={key}\n"
              f"SSH_CA_FPR={ssh_fpr(key)}\n"
              f"KANIDM_URL=https://idm.{domain}\n")


  def parse_client_conf(text, site):
      raw = read_kv(text, "client.conf")
      for k in ("CA_ROOT_SHA256", "SSH_CA_PUBKEY", "SSH_CA_FPR", "KANIDM_URL"):
          if not raw.get(k):
              raise SiteError(f"client.conf: {k} is required (run `chp-site export-client` on the server)")
      if not re.fullmatch(r"[0-9a-f]{64}", raw["CA_ROOT_SHA256"]):
          raise SiteError("client.conf: CA_ROOT_SHA256 must be 64 lower-case hex digits")
      try:
          key = ssh_pubkey(raw["SSH_CA_PUBKEY"])
      except SiteError as e:
          raise SiteError(str(e).replace("ADMIN_SSH_PUBKEY", "client.conf SSH_CA_PUBKEY")) from None
      if ssh_fpr(key) != raw["SSH_CA_FPR"]:
          raise SiteError("client.conf: SSH_CA_FPR does not match SSH_CA_PUBKEY (tampered or corrupted)")
      if raw["KANIDM_URL"] != f"https://idm.{site['DOMAIN']}":
          raise SiteError(f"client.conf: KANIDM_URL must be https://idm.{site['DOMAIN']} (site DOMAIN)")
      return {"CA_ROOT_SHA256": raw["CA_ROOT_SHA256"], "SSH_CA_PUBKEY": key, "SSH_CA_FPR": raw["SSH_CA_FPR"],
              "KANIDM_URL": raw["KANIDM_URL"]}
  ```

- [ ] **Step 5: Run the tests.** `uv run pytest tests/test_chp_site_disks.py tests/test_chp_site_clientconf.py -q`, then `uv run pytest -q`.
  Expected: all pass.

- [ ] **Step 6: Commit** the modules, tests and fixtures with the message
  `ISO Plan 2 Task 3: install-disk choice (one candidate or named) + client.conf pinning (export/verify round trip)`.

---

### Task 4: `render.py`, `pre.py`, `facts.py`: the `%pre` gate

**Files:**
- Create: `appliance/chp-site/chp_site/render.py`, `appliance/chp-site/chp_site/pre.py`, `appliance/chp-site/chp_site/facts.py`,
  `tests/test_chp_site_render.py`, `tests/test_chp_site_pre.py`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `Facts = namedtuple("Facts", "macs disks now")`
  - `run_pre(role, stick: Path, out: Path, repo_url: str, facts: Facts, hasher=sha512_crypt, secret=secrets.token_urlsafe) -> Host`
  - It writes `out/{misc,net,users,disk,repo}.ks` (mode 0600) and `stick/escrow/<hostname>.txt`.
  - `facts.live() -> Facts` (reads `/sys/class/net/*/address` and `lsblk`).

- [ ] **Step 1: Write the failing tests** `tests/test_chp_site_render.py`:
  ```python
  from chp_site.hosts import parse_hosts
  from chp_site.render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
  from chp_site.sitefile import parse_site
  from tests.test_chp_site_hosts import HOSTS
  from tests.test_chp_site_sitefile import ECDSA, GOOD

  SITE = parse_site(GOOD)
  HS = parse_hosts(HOSTS, SITE)


  def test_net_binds_the_matched_nic_and_resolves_via_the_server():
      srv, cli = HS
      s = net_ks(SITE, srv, HS)
      assert "--device=52:54:00:c4:02:30" in s and "--ip=192.168.100.30" in s and "--netmask=255.255.255.0" in s
      assert "--gateway=192.168.100.1" in s and "--hostname=iso2-srv.iso2.lab.test" in s
      assert "--nameserver=192.168.100.30" in s                  # the server resolves via itself (dc1 lesson)
      assert "--nameserver=192.168.100.30" in net_ks(SITE, cli, HS)


  def test_users_root_hash_and_keyonly_admin():
      s = users_ks(SITE, "$6$salt$hash")
      assert "rootpw --iscrypted $6$salt$hash" in s
      assert "user --name=chpadmin --groups=wheel" in s and "--password" not in s
      assert f'sshkey --username=chpadmin "{ECDSA}"' in s


  def test_disk_is_luks2_on_the_chosen_disk_only():
      s = disk_ks("vda", "PASSPHRASE")
      assert "ignoredisk --only-use=vda" in s and "clearpart --all --initlabel --drives=vda" in s
      assert "--encrypted --luks-version=luks2 --passphrase=PASSPHRASE" in s
      for mnt in ("/boot/efi", "/boot", "/home", "/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "swap"):
          assert f" {mnt} " in s or f" {mnt}\n" in s or f"logvol {mnt}" in s or f"part {mnt}" in s


  def test_misc_time_and_repo():
      assert "timezone America/Denver --utc" in misc_ks(SITE)
      assert "timesource --ntp-server=192.168.100.1" in misc_ks(SITE)
      assert repo_ks("file:///run/install/repo/chp") == "repo --name=chp --baseurl=file:///run/install/repo/chp\n"
  ```
  `tests/test_chp_site_pre.py`:
  ```python
  import json
  import os
  import stat
  from pathlib import Path

  import pytest

  from chp_site.pre import Facts, run_pre
  from chp_site.sitefile import SiteError
  from tests.test_chp_site_clientconf import PEM, PUB
  from chp_site.clientconf import make_client_conf
  from tests.test_chp_site_hosts import HOSTS
  from tests.test_chp_site_sitefile import GOOD

  G = 1_000_000_000
  ONE_DISK = [("vda", 120 * G, "virtio", False, "disk")]


  def facts(macs, disks=ONE_DISK):
      from chp_site.disks import disks_from_lsblk
      lsblk = json.dumps({"blockdevices": [dict(zip(("name", "size", "tran", "rm", "type"), d)) for d in disks]})
      return Facts(macs, disks_from_lsblk(lsblk, {}), "20260930T120000Z")


  def stick(tmp_path, client_conf=True):
      s = tmp_path / "stick"; s.mkdir()
      (s / "site.conf").write_text(GOOD); (s / "hosts").write_text(HOSTS)
      if client_conf:
          (s / "client.conf").write_text(make_client_conf("iso2.lab.test", PEM, PUB))
      return s


  def run(tmp_path, role, macs, **kw):
      s = kw.pop("stick_dir", None) or stick(tmp_path)
      out = tmp_path / "out"
      h = run_pre(role, s, out, "file:///run/install/repo/chp", kw.pop("facts", facts(macs)),
                  hasher=lambda pw: "$6$fake$" + str(len(pw)), secret=lambda n: "S" * n)
      return h, s, out


  def test_server_install_writes_snippets_and_escrow(tmp_path):
      h, s, out = run(tmp_path, "server", ["52:54:00:c4:02:30"])
      assert h.hostname == "iso2-srv"
      for f in ("misc", "net", "users", "disk", "repo"):
          p = out / f"{f}.ks"
          assert p.exists() and stat.S_IMODE(p.stat().st_mode) == 0o600
      esc = (s / "escrow" / "iso2-srv.txt").read_text()
      assert "LUKS_PASSPHRASE=" + "S" * 32 in esc and "ROOT_CONSOLE_PASSWORD=" in esc
      assert "--passphrase=" + "S" * 32 in (out / "disk.ks").read_text()
      assert "S" * 32 not in (out / "users.ks").read_text()     # only the hash goes to users.ks


  def test_role_must_match_the_boot_entry(tmp_path):
      with pytest.raises(SiteError, match="booted the client installer.*server"):
          run(tmp_path, "client", ["52:54:00:c4:02:30"])


  def test_client_needs_a_valid_client_conf(tmp_path):
      s = stick(tmp_path, client_conf=False)
      with pytest.raises(SiteError, match="client.conf"):
          run(tmp_path, "client", ["52:54:00:c4:02:31"], stick_dir=s)


  def test_nothing_is_written_when_validation_fails(tmp_path):
      s = stick(tmp_path)
      with pytest.raises(SiteError, match="not in the hosts table"):
          run(tmp_path, "server", ["aa:bb:cc:dd:ee:ff"], stick_dir=s)
      assert not (s / "escrow").exists() and not (tmp_path / "out").exists()


  def test_read_only_stick_stops_the_install(tmp_path):                # Review Focus 3
      s = stick(tmp_path)
      os.chmod(s, 0o555)
      try:
          with pytest.raises(SiteError, match="cannot write the escrow.*stick"):
              run(tmp_path, "server", ["52:54:00:c4:02:30"], stick_dir=s)
          assert not (tmp_path / "out").exists()
      finally:
          os.chmod(s, 0o755)


  def test_reinstall_keeps_the_previous_escrow(tmp_path):              # Review Focus 4
      s = stick(tmp_path)
      (s / "escrow").mkdir(); (s / "escrow" / "iso2-srv.txt").write_text("OLD\n")
      run(tmp_path, "server", ["52:54:00:c4:02:30"], stick_dir=s)
      olds = list((s / "escrow").glob("iso2-srv.txt.*.old"))
      assert len(olds) == 1 and olds[0].read_text() == "OLD\n"
      assert "LUKS_PASSPHRASE=" in (s / "escrow" / "iso2-srv.txt").read_text()


  def test_disk_rules_apply(tmp_path):
      two = [("vda", 120 * G, "virtio", False, "disk"), ("vdb", 120 * G, "virtio", False, "disk")]
      with pytest.raises(SiteError, match="name one in the hosts table"):
          run(tmp_path, "server", ["52:54:00:c4:02:30"], facts=facts(["52:54:00:c4:02:30"], two))
  ```
  Run both files. Expected: FAIL (modules missing).

- [ ] **Step 2: Write `appliance/chp-site/chp_site/render.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """Kickstart snippets written by %pre and %include'd by server.ks/client.ks."""
  from .hosts import server_of


  def misc_ks(site):
      lines = [f"timezone {site['TIMEZONE']} --utc"] + [f"timesource --ntp-server={n}" for n in site["NTP_UPSTREAM"]]
      return "\n".join(lines) + "\n"


  def net_ks(site, host, hosts):
      ns = server_of(hosts).ip                                  # the server resolves via itself; clients via the server
      return (f"network --bootproto=static --device={host.mac} --ip={host.ip} --netmask={site['SUBNET'].netmask} "
              f"--gateway={site['GATEWAY']} --nameserver={ns} --noipv6 --activate "
              f"--hostname={host.hostname}.{site['DOMAIN']}\n")


  def users_ks(site, root_hash):
      return (f"rootpw --iscrypted {root_hash}\n"
              "user --name=chpadmin --groups=wheel --gecos=\"CHP break-glass admin (SSH key only)\"\n"
              f"sshkey --username=chpadmin \"{site['ADMIN_SSH_PUBKEY']}\"\n")


  def disk_ks(disk, passphrase):
      vg = "chp"
      return (f"ignoredisk --only-use={disk}\n"
              f"clearpart --all --initlabel --drives={disk}\n"
              "part /boot/efi --fstype=efi --size=1024\n"
              "part /boot --fstype=xfs --size=2048\n"
              f"part pv.01 --size=1 --grow --encrypted --luks-version=luks2 --passphrase={passphrase}\n"
              f"volgroup {vg} pv.01\n"
              f"logvol swap           --vgname={vg} --name=swap          --size=8192\n"
              f"logvol /home          --vgname={vg} --name=home          --fstype=xfs --size=10240\n"
              f"logvol /tmp           --vgname={vg} --name=tmp           --fstype=xfs --size=4096\n"
              f"logvol /var           --vgname={vg} --name=var           --fstype=xfs --size=20480\n"
              f"logvol /var/tmp       --vgname={vg} --name=var_tmp       --fstype=xfs --size=4096\n"
              f"logvol /var/log       --vgname={vg} --name=var_log       --fstype=xfs --size=8192\n"
              f"logvol /var/log/audit --vgname={vg} --name=var_log_audit --fstype=xfs --size=8192\n"
              f"logvol /              --vgname={vg} --name=root          --fstype=xfs --size=20480 --grow\n")


  def repo_ks(url):
      return f"repo --name=chp --baseurl={url}\n"
  ```
  (Fixed LV sizes total about 83 GB of the 100 GB minimum, and `/` grows into the rest. This matches the CUI separate-partition rules the lab kickstarts use.)

- [ ] **Step 3: Write `appliance/chp-site/chp_site/facts.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """The only code that reads this machine's hardware: NIC MACs and block devices."""
  import os
  import subprocess
  import time
  from collections import namedtuple
  from pathlib import Path

  from .disks import disks_from_lsblk

  Facts = namedtuple("Facts", "macs disks now")


  def live():
      macs = []
      for nic in sorted(Path("/sys/class/net").iterdir()):
          if nic.name == "lo":
              continue
          m = (nic / "address").read_text().strip()
          if m and m != "00:00:00:00:00:00":
              macs.append(m)
      js = subprocess.run(["lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,TRAN,RM,TYPE"], check=True,
                          capture_output=True, text=True).stdout
      by_id = {}
      bid = Path("/dev/disk/by-id")
      if bid.is_dir():
          for p in bid.iterdir():
              by_id.setdefault(os.path.basename(os.path.realpath(p)), []).append(str(p))
      return Facts(macs, disks_from_lsblk(js, by_id), time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
  ```

- [ ] **Step 4: Write `appliance/chp-site/chp_site/pre.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """The %pre gate: validate EVERYTHING, then write the escrow to the stick, then write the kickstart snippets.
  Any failure raises SiteError before a disk is touched; the install never proceeds without its recovery secrets."""
  import os
  import secrets
  import subprocess
  from pathlib import Path

  from .clientconf import parse_client_conf
  from .disks import choose_disk
  from .facts import Facts  # noqa: F401  (re-exported for callers and tests)
  from .hosts import lookup, parse_hosts
  from .render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
  from .sitefile import SiteError, parse_site


  def sha512_crypt(pw):
      """SHA-512 crypt for rootpw --iscrypted. `crypt` exists on EL9's Python 3.9 (it was removed in 3.13); fall back to
      openssl, which is on every EL9 host and in the installer."""
      try:
          import crypt  # noqa: PLC0415
          return crypt.crypt(pw, crypt.mksalt(crypt.METHOD_SHA512))
      except ImportError:
          return subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=pw, capture_output=True, text=True,
                                check=True).stdout.strip()


  def _read(p, what):
      try:
          return p.read_text(encoding="utf-8")
      except FileNotFoundError:
          raise SiteError(f"the site stick has no {what} ({p.name})") from None


  def run_pre(role, stick, out, repo_url, facts, hasher=sha512_crypt, secret=secrets.token_urlsafe):
      stick, out = Path(stick), Path(out)
      site = parse_site(_read(stick / "site.conf", "site.conf"))
      hosts = parse_hosts(_read(stick / "hosts", "hosts table"), site)
      host = lookup(hosts, facts.macs)
      if host.role != role:
          raise SiteError(f"you booted the {role} installer, but the hosts table says {host.hostname} is a {host.role}")
      if role == "client":
          parse_client_conf(_read(stick / "client.conf", "client.conf (run `chp-site export-client` on the server)"), site)
      disk = choose_disk(facts.disks, host.disk)
      # --- everything is valid: now the secrets, escrow first ---
      luks, rootpw = secret(32), secret(18)
      esc_dir, esc = stick / "escrow", stick / "escrow" / f"{host.hostname}.txt"
      try:
          esc_dir.mkdir(exist_ok=True)
          if esc.exists():
              esc.rename(esc_dir / f"{host.hostname}.txt.{facts.now}.old")
          esc.write_text(f"# {host.hostname}.{site['DOMAIN']}  installed {facts.now}\n"
                         "# KEEP THIS STICK OFFLINE: it now holds this host's recovery secrets.\n"
                         f"LUKS_PASSPHRASE={luks}\nROOT_CONSOLE_PASSWORD={rootpw}\n")
          os.sync()
      except OSError as e:
          raise SiteError(f"cannot write the escrow file to the site stick ({e.strerror}); is the stick read-only "
                          "or full? The install stops: it never proceeds without its recovery secrets") from None
      out.mkdir(mode=0o700, parents=True, exist_ok=True)
      for name, text in (("misc", misc_ks(site)), ("net", net_ks(site, host, hosts)), ("users", users_ks(site, hasher(rootpw))),
                         ("disk", disk_ks(disk, luks)), ("repo", repo_ks(repo_url))):
          p = out / f"{name}.ks"
          fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
          with os.fdopen(fd, "w") as f:
              f.write(text)
      return host
  ```

- [ ] **Step 5: Run the tests.** `uv run pytest tests/test_chp_site_render.py tests/test_chp_site_pre.py -q`, then `uv run pytest -q`. Expected: all pass.
  (The read-only-stick test uses directory permissions. If the tests run as root, where 0555 is not enforced, skip that test with
  `pytest.mark.skipif(os.geteuid() == 0, …)`.)

- [ ] **Step 6: Commit** with the message `ISO Plan 2 Task 4: %pre gate — validate all, escrow first (kept on reinstall), 0600 snippets`.

---

### Task 5: `cli.py`, the zipapp, and `export-client`

**Files:**
- Create: `appliance/chp-site/chp_site/cli.py`, `appliance/chp-site/build.sh`, `tests/test_chp_site_cli.py`; append
  `appliance/chp-site/dist/` to `.gitignore`

**Interfaces:**
- Produces:
  - `chp-site validate --site DIR [--role server|client] [--mac MAC …]`: exit 0 and a one-line summary; exit 2 and
    `chp-site: <message>` on a SiteError
  - `chp-site pre --role R --stick DIR --out DIR [--repo-url URL]`, using live facts
  - `chp-site export-client --stick DIR [--site FILE=/etc/chp/site.conf] [--root FILE=/etc/step-ca/certs/root_ca.crt] [--ssh-ca FILE=/etc/ssh-ca/user_ca.pub]`:
    writes `DIR/client.conf` and prints both fingerprints for a human to compare
  - `chp-site --version`
  - `appliance/chp-site/build.sh` → `appliance/chp-site/dist/chp-site.pyz` (shebang `/usr/bin/python3`)

- [ ] **Step 1: Write the failing tests** `tests/test_chp_site_cli.py`:
  ```python
  import subprocess
  import sys
  from pathlib import Path

  from tests.test_chp_site_clientconf import FX
  from tests.test_chp_site_hosts import HOSTS
  from tests.test_chp_site_sitefile import GOOD

  ROOT = Path(__file__).resolve().parents[1]
  PKG = ROOT / "appliance" / "chp-site"


  def cli(*args):
      return subprocess.run([sys.executable, "-m", "chp_site.cli", *args], cwd=PKG, capture_output=True, text=True)


  def site(tmp_path, extra=""):
      d = tmp_path / "s"; d.mkdir()
      (d / "site.conf").write_text(GOOD + extra); (d / "hosts").write_text(HOSTS)
      return d


  def test_validate_ok_and_host_found(tmp_path):
      r = cli("validate", "--site", str(site(tmp_path)), "--mac", "52-54-00-C4-02-31")
      assert r.returncode == 0 and "iso2-cli" in r.stdout and "client" in r.stdout


  def test_validate_error_is_one_readable_line(tmp_path):
      r = cli("validate", "--site", str(site(tmp_path, "BOGUS=1\n")))
      assert r.returncode == 2 and r.stderr.strip() == "chp-site: site.conf: unknown key BOGUS"


  def test_export_client_writes_and_prints_fingerprints(tmp_path):
      d = site(tmp_path); stick = tmp_path / "stick"; stick.mkdir()
      r = cli("export-client", "--stick", str(stick), "--site", str(d / "site.conf"),
              "--root", str(FX / "root_ca.crt"), "--ssh-ca", str(FX / "user_ca.pub"))
      assert r.returncode == 0, r.stderr
      assert "CA root SHA-256:" in r.stdout and "SSH CA fingerprint: SHA256:" in r.stdout
      c = cli("validate", "--site", str(d), "--role", "client")      # site dir without client.conf: role check only
      assert c.returncode == 0
      (d / "client.conf").write_text((stick / "client.conf").read_text())
      assert cli("validate", "--site", str(d), "--role", "client").returncode == 0


  def test_zipapp_builds_and_runs(tmp_path):
      subprocess.run(["bash", str(PKG / "build.sh")], check=True, capture_output=True)
      pyz = PKG / "dist" / "chp-site.pyz"
      assert pyz.read_bytes().startswith(b"#!/usr/bin/python3\n")
      r = subprocess.run([sys.executable, str(pyz), "--version"], capture_output=True, text=True)
      assert r.returncode == 0 and r.stdout.strip() == "chp-site 0.1.0"
  ```
  Run it. Expected: FAIL.

- [ ] **Step 2: Write `appliance/chp-site/chp_site/cli.py`.**
  ```python
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  """chp-site command line: validate | pre | export-client."""
  import argparse
  import sys
  from pathlib import Path

  from . import VERSION
  from .clientconf import cert_sha256, make_client_conf, parse_client_conf, ssh_fpr
  from .hosts import lookup, parse_hosts
  from .sitefile import SiteError, parse_site


  def _validate(a):
      d = Path(a.site)
      site = parse_site((d / "site.conf").read_text(encoding="utf-8"))
      hosts = parse_hosts((d / "hosts").read_text(encoding="utf-8"), site)
      if (d / "client.conf").exists():
          parse_client_conf((d / "client.conf").read_text(encoding="utf-8"), site)
      msg = f"OK: {site['DOMAIN']}, {len(hosts)} hosts, server {next(h.hostname for h in hosts if h.role == 'server')}"
      if a.mac:
          h = lookup(hosts, a.mac)
          if a.role and h.role != a.role:
              raise SiteError(f"{h.hostname} is a {h.role}, not a {a.role}")
          msg += f"; this machine is {h.hostname} ({h.role}, {h.ip})"
      print(msg)


  def _pre(a):
      from .facts import live
      from .pre import run_pre
      h = run_pre(a.role, Path(a.stick), Path(a.out), a.repo_url, live())
      print(f"CHP: installing {h.hostname} ({h.role}, {h.ip}). Recovery secrets were written to the site stick: "
            "keep it offline from now on.")


  def _export(a):
      site = parse_site(Path(a.site).read_text(encoding="utf-8"))
      pem, pub = Path(a.root).read_text(), Path(a.ssh_ca).read_text()
      text = make_client_conf(site["DOMAIN"], pem, pub)
      (Path(a.stick) / "client.conf").write_text(text)
      print(f"wrote {Path(a.stick) / 'client.conf'}\nCA root SHA-256: {cert_sha256(pem)}\nSSH CA fingerprint: {ssh_fpr(pub)}\n"
            "Compare both with the server console before installing clients.")


  def main(argv=None):
      ap = argparse.ArgumentParser(prog="chp-site")
      ap.add_argument("--version", action="version", version=f"chp-site {VERSION}")
      sub = ap.add_subparsers(dest="cmd", required=True)
      v = sub.add_parser("validate"); v.add_argument("--site", required=True)
      v.add_argument("--role", choices=("server", "client")); v.add_argument("--mac", nargs="*")
      p = sub.add_parser("pre"); p.add_argument("--role", required=True, choices=("server", "client"))
      p.add_argument("--stick", required=True); p.add_argument("--out", required=True)
      p.add_argument("--repo-url", default="file:///run/install/repo/chp")
      e = sub.add_parser("export-client"); e.add_argument("--stick", required=True)
      e.add_argument("--site", default="/etc/chp/site.conf"); e.add_argument("--root", default="/etc/step-ca/certs/root_ca.crt")
      e.add_argument("--ssh-ca", default="/etc/ssh-ca/user_ca.pub")
      a = ap.parse_args(argv)
      try:
          {"validate": _validate, "pre": _pre, "export-client": _export}[a.cmd](a)
      except SiteError as err:
          print(f"chp-site: {err}", file=sys.stderr)
          return 2
      except FileNotFoundError as err:
          print(f"chp-site: missing file: {err.filename}", file=sys.stderr)
          return 2
      return 0


  def run():
      """zipapp entry point: zipapp's generated __main__ ignores main()'s return value, so exit here."""
      sys.exit(main())


  if __name__ == "__main__":
      run()
  ```

- [ ] **Step 3: Write `appliance/chp-site/build.sh`.**
  ```bash
  #!/usr/bin/env bash
  # CyberHygiene Project Lab Installer — based on Rocky Linux 9.
  # Not an official Rocky Linux product.
  # Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
  # build.sh: pack chp_site into one zipapp, dist/chp-site.pyz, run by the system python3 (installer, hosts, Mac).
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
  mkdir -p "$here/dist"; cp -R "$here/chp_site" "$T/"; find "$T" -name __pycache__ -prune -exec rm -rf {} +
  python3 -m zipapp "$T" -m "chp_site.cli:run" -p "/usr/bin/python3" -o "$here/dist/chp-site.pyz"
  echo "$here/dist/chp-site.pyz"
  ```
  Add `appliance/chp-site/dist/` to `.gitignore`.

- [ ] **Step 4: Run the tests.** `uv run pytest tests/test_chp_site_cli.py -q`, then `uv run pytest -q`. Expected: all pass.

- [ ] **Step 5: Commit** with the message `ISO Plan 2 Task 5: chp-site CLI (validate / pre / export-client) + zipapp`.

---

### Task 6: The kickstarts

**Files:**
- Create: `appliance/kickstart/chp.ks.in`, `appliance/kickstart/render-ks.sh`, `appliance/kickstart/server.ks`,
  `appliance/kickstart/client.ks`, `tests/test_kickstarts.py`

**Interfaces:**
- Consumes: the snippet names `/tmp/chp/{misc,net,users,disk,repo}.ks` (Task 4); `chp-site pre` (Task 5). The zipapp is looked for at
  `/chp-site.pyz` (lab: initrd-inject) and then `/run/install/repo/chp/chp-site.pyz` (ISO, Plan 5). The repo URL comes from
  the kernel argument `chp.repo=` (lab), defaulting to the ISO path.
- Produces: `server.ks`, `client.ks`, identical except for `@ROLE@`.

- [ ] **Step 1: Write the failing test** `tests/test_kickstarts.py`:
  ```python
  import re
  import shutil
  import subprocess
  from pathlib import Path

  import pytest

  from chp_site.hosts import parse_hosts
  from chp_site.render import disk_ks, misc_ks, net_ks, repo_ks, users_ks
  from chp_site.sitefile import parse_site
  from tests.test_chp_site_hosts import HOSTS
  from tests.test_chp_site_sitefile import GOOD

  KS = Path(__file__).resolve().parents[1] / "appliance" / "kickstart"
  HEADER = (Path(__file__).resolve().parents[1] / "appliance" / "branding" / "file-header.txt").read_text()


  @pytest.mark.parametrize("role", ["server", "client"])
  def test_committed_kickstart_equals_the_template(role):
      assert (KS / f"{role}.ks").read_text() == (KS / "chp.ks.in").read_text().replace("@ROLE@", role)


  @pytest.mark.parametrize("role", ["server", "client"])
  def test_kickstart_rules(role):
      t = (KS / f"{role}.ks").read_text()
      assert t.startswith(HEADER)
      assert "--erroronfail" in t and "%pre" in t and f"pre --role {role}" in t
      for inc in ("misc", "net", "users", "disk", "repo"):
          assert f"%include /tmp/chp/{inc}.ks" in t
      assert "fips=1" in t and "selinux --enforcing" in t and "content_profile_cui" in t
      assert "--passphrase" not in t and "rootpw --plaintext" not in t     # secrets only ever come from /tmp/chp
      assert not re.search(r"cp .*escrow|escrow.*/mnt/sysimage", t)      # the escrow never reaches the host


  @pytest.mark.skipif(shutil.which("uvx") is None, reason="needs uvx (pykickstart)")
  @pytest.mark.parametrize("role,host", [("server", 0), ("client", 1)])
  def test_kickstart_with_snippets_validates(tmp_path, role, host):
      site = parse_site(GOOD); hs = parse_hosts(HOSTS, site)
      snip = {"misc": misc_ks(site), "net": net_ks(site, hs[host], hs), "users": users_ks(site, "$6$x$y"),
              "disk": disk_ks("vda", "test-only"), "repo": repo_ks("file:///run/install/repo/chp")}
      t = (KS / f"{role}.ks").read_text()
      for k, v in snip.items():
          t = t.replace(f"%include /tmp/chp/{k}.ks", v.rstrip("\n"))
      f = tmp_path / "ks.cfg"; f.write_text(t)
      r = subprocess.run(["uvx", "--from", "pykickstart", "ksvalidator", "-v", "RHEL9", str(f)], capture_output=True, text=True)
      assert r.returncode == 0, r.stdout + r.stderr
  ```
  Run it. Expected: FAIL (no kickstarts).

- [ ] **Step 2: Write `appliance/kickstart/chp.ks.in`.** Put the three header lines from `appliance/branding/file-header.txt` first,
  then:
  ```
  # CHP Lab Installer, @ROLE@ kickstart. Site values come from the OEMDRV stick through `chp-site pre` (%pre below);
  # the secrets (LUKS passphrase, root console password) exist only in /tmp/chp (installer RAM) and on the stick.
  text
  cdrom
  poweroff
  lang en_US.UTF-8
  keyboard --vckeymap=us --xlayouts='us'
  %include /tmp/chp/misc.ks
  %include /tmp/chp/net.ks
  firewall --enabled --service=ssh
  selinux --enforcing
  %include /tmp/chp/users.ks
  bootloader --append="fips=1"
  zerombr
  %include /tmp/chp/disk.ks
  %include /tmp/chp/repo.ks

  %addon com_redhat_kdump --disable
  %end

  %addon com_redhat_oscap
      content-type = scap-security-guide
      profile = xccdf_org.ssgproject.content_profile_cui
  %end

  %packages
  @^graphical-server-environment
  audit
  chrony
  crypto-policies
  firewalld
  fapolicyd
  openscap-scanner
  scap-security-guide
  openssh-server
  sudo
  tar
  rsync
  clevis
  clevis-luks
  clevis-dracut
  clevis-systemd
  tpm2-tools
  mokutil
  chp-site
  %end

  %pre --interpreter=/usr/bin/bash --erroronfail --log=/tmp/chp-pre.log
  # Validate the site stick BEFORE any disk is touched. Messages go to the console so the person installing sees them.
  set -uo pipefail
  mkdir -p /mnt/oemdrv /tmp/chp
  if ! mount -o rw LABEL=OEMDRV /mnt/oemdrv; then
    echo "CHP: no site stick found (a USB volume labelled OEMDRV). Nothing was changed." | tee /dev/console
    exit 1
  fi
  repo=file:///run/install/repo/chp
  for a in $(cat /proc/cmdline); do case $a in chp.repo=*) repo=${a#chp.repo=} ;; esac; done
  pyz=/run/install/repo/chp/chp-site.pyz
  if [ -f /chp-site.pyz ]; then pyz=/chp-site.pyz; fi
  python3 "$pyz" pre --role @ROLE@ --stick /mnt/oemdrv --out /tmp/chp --repo-url "$repo" 2>&1 | tee /dev/console
  rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ]; then echo "CHP: install stopped before any disk was touched." | tee /dev/console; fi
  exit "$rc"
  %end

  %post --nochroot --log=/mnt/sysimage/root/chp-post-nochroot.log
  # Non-secret site files to /etc/chp (0644). The escrow directory is NEVER copied to the host.
  install -d -m 0755 /mnt/sysimage/etc/chp
  for f in site.conf hosts client.conf; do
    if [ -f "/mnt/oemdrv/$f" ]; then install -m 0644 "/mnt/oemdrv/$f" "/mnt/sysimage/etc/chp/$f"; fi
  done
  sync; umount /mnt/oemdrv || true
  echo "CHP: install finished. Remove the site stick and keep it OFFLINE: it holds this host's recovery secrets." > /dev/console
  %end

  %post --log=/root/chp-post.log
  # Trust our signing key (the chp-site RPM ships it) and keep vendor online repos off (offline appliance).
  rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
  dnf config-manager --set-disabled baseos appstream extras >/dev/null 2>&1 || true
  # dc2 tailoring: dc2 UNSELECTS sysctl_user_max_user_namespaces; the CUI files are also inside the initramfs.
  grep -rlE 'user\.max_user_namespaces' /etc/sysctl.d /etc/sysctl.conf 2>/dev/null | xargs -r sed -i '/user\.max_user_namespaces/d'
  rm -f /etc/sysctl.d/user_max_user_namespaces.conf
  dracut -f --regenerate-all
  %end
  ```

- [ ] **Step 3: Write `appliance/kickstart/render-ks.sh`** (header lines first):
  ```bash
  #!/usr/bin/env bash
  # render-ks.sh: server.ks and client.ks from chp.ks.in (the only difference is @ROLE@).
  set -Eeuo pipefail
  here="$(cd "$(dirname "$0")" && pwd)"
  for r in server client; do sed "s/@ROLE@/$r/g" "$here/chp.ks.in" > "$here/$r.ks"; done
  echo "rendered: $here/server.ks $here/client.ks"
  ```
  Run it.

- [ ] **Step 4: Run the tests.** `uv run pytest tests/test_kickstarts.py -q`, then `uv run pytest -q`. Expected: all pass. `ksvalidator` accepts
  `timesource`, `repo` and the `%addon` blocks for RHEL9. If it rejects a line, fix the template, not the test.

- [ ] **Step 5: Commit** `appliance/kickstart/` and `tests/test_kickstarts.py` with the message
  `ISO Plan 2 Task 6: server.ks / client.ks (thin; %pre gate before disks; site files to /etc/chp; escrow never on the host)`.

---

### Task 7: The `chp-site` RPM and repo 0.2.0 (signed)

**Files:**
- Create: `appliance/chp-site/chp-site.spec`, `appliance/chp-site/chp.repo`, `appliance/chp-site/build-rpm.sh`
- Modify: `appliance/release/PACKAGES.txt` (add `chp-site ours`)

**Interfaces:**
- Produces: `chp-site-0.1.0-1.chp.el9.noarch.rpm`, owning:
  - `/usr/bin/chp-site` (0755, the zipapp)
  - `/etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene` (0644)
  - `/etc/yum.repos.d/chp.repo` (`%config(noreplace)`, `enabled=0`, baseurl `file:///var/lib/chp/repo`, `gpgcheck=1`, `repo_gpgcheck=1`)
  - `/var/lib/chp/repo` (directory)
  - the licence
- Also a signed, verified `aero:/data/chp-release/0.2.0/repo` (0.1.1's packages plus chp-site), served at `…/chp/0.2.0/`.

- [ ] **Step 1: Write `appliance/chp-site/chp.repo`.**
  ```
  # CyberHygiene packages: updates arrive as a signed repo tarball unpacked into /var/lib/chp/repo.
  # Enable only after unpacking one (dnf will verify every package and the repo metadata against our key).
  [chp]
  name=CyberHygiene Project Lab Installer packages
  baseurl=file:///var/lib/chp/repo
  enabled=0
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
  ```

- [ ] **Step 2: Write `appliance/chp-site/chp-site.spec`.**
  ```
  Name:           chp-site
  Version:        0.1.0
  Release:        1.chp%{?dist}
  Summary:        CyberHygiene site files tool and installer gate
  License:        Apache-2.0
  Vendor:         The CyberHygiene Project
  URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
  BuildArch:      noarch
  Source0:        chp-site.pyz
  Source1:        chp.repo
  Source2:        RPM-GPG-KEY-cyberhygiene
  Source3:        LICENSE
  Requires:       python3, openssl, util-linux

  %description
  chp-site validates the site files (site.conf, hosts, client.conf) and writes client.conf on the identity server.
  It also ships the project signing key and a disabled repo definition for signed update tarballs.

  %install
  install -Dm0755 %{SOURCE0} %{buildroot}%{_bindir}/chp-site
  install -Dm0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/yum.repos.d/chp.repo
  install -Dm0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
  install -dm0755 %{buildroot}%{_sharedstatedir}/chp/repo
  install -Dm0644 %{SOURCE3} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE

  %files
  %license %{_datadir}/licenses/%{name}/LICENSE
  %{_bindir}/chp-site
  %config(noreplace) %{_sysconfdir}/yum.repos.d/chp.repo
  %{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
  %dir %{_sharedstatedir}/chp
  %dir %{_sharedstatedir}/chp/repo

  %changelog
  * Wed Sep 30 2026 The CyberHygiene Project - 0.1.0-1.chp
  - First release: validate, pre, export-client; project key; disabled local repo definition.
  ```

- [ ] **Step 3: Write `appliance/chp-site/build-rpm.sh`**, the same pattern as `appliance/rpm/idm-collect/build-rpm.sh`. It runs
  `appliance/chp-site/build.sh` first, then copies `dist/chp-site.pyz`, `chp.repo`, `appliance/release/RPM-GPG-KEY-cyberhygiene` and `LICENSE`
  to `aero:/tmp/chps/SOURCES/`, runs `rpmbuild -bb --define "_topdir /tmp/chps"`, and copies the RPM to `/data/chp-release/built/`.
  Run it. Expected: `rpm -qlp` lists the five paths above plus the licence.

- [ ] **Step 4: Sign repo 0.2.0 (the user touches the YubiKey).** Append `chp-site ours` to `PACKAGES.txt`, then:
  ```bash
  bash appliance/release/push.sh
  FPR=$(awk '$2=="cyberhygiene"{print $1}' appliance/release/trusted-keys.txt)
  ssh aero 'bash /data/chp-release/tools/assemble-repo.sh /data/chp-release/0.2.0/stage /data/chp-release/built /data/lab-inputs/rpms'
  bash appliance/release/sign-session.sh "bash /data/chp-release/tools/sign-repo.sh /data/chp-release/0.2.0/stage /data/chp-release/0.2.0/repo $FPR /data/chp-release/tools"
  ssh aero 'sudo cp -a /data/chp-release/0.2.0/repo /data/lab-inputs/chp/0.2.0 && curl -fsI http://192.168.100.1:8080/chp/0.2.0/repodata/repomd.xml.asc | head -1'
  ```
  Tell the user first: "a PIN dialog (maybe behind other windows), then about 15 touches". Expected: 8 packages staged,
  `REPO OK: 8 packages`, `HTTP/1.0 200 OK`.

- [ ] **Step 5: Commit** `appliance/chp-site/{chp-site.spec,chp.repo,build-rpm.sh}` and `appliance/release/PACKAGES.txt` with the message
  `ISO Plan 2 Task 7: chp-site RPM (tool + project key + disabled local repo); signed repo 0.2.0`.

---

### Task 8: Install proof on aero

**Files:**
- Create: `lab/iso2/site.conf.in`, `lab/iso2/hosts`, `lab/iso2/make-stick.sh`, `lab/iso2/install.sh`, `lab/iso2/prove.sh`,
  `lab/iso2/PROOF-RECORD.md`

**Interfaces:**
- Consumes: `server.ks`, `client.ks`, `chp-site.pyz`, repo 0.2.0, `~/idm-lab-secrets/iso2_chpadmin{,.pub}` (created here).
- The test site: domain `iso2.lab.test`, SUBNET `192.168.100.0/24`, GATEWAY and NTP `192.168.100.1`, no DNS forwarders.
- The VMs (all created and destroyed by this task only):

  | VM | MAC | IP | Role | Disks |
  |---|---|---|---|---|
  | `iso2-srv` | 52:54:00:c4:02:30 | .30 | server | one 120 GB disk |
  | `iso2-cli` | 52:54:00:c4:02:31 | .31 | client | one 120 GB disk |
  | `iso2-neg1` | 52:54:00:c4:02:3f | | | not in hosts |
  | `iso2-neg2` | 52:54:00:c4:02:39 | .39 | client | two disks, none named |

- [ ] **Step 1: The test site files.** `lab/iso2/site.conf.in` is `GOOD` from Task 1 with `ADMIN_SSH_PUBKEY=@ADMIN_PUBKEY@`. `lab/iso2/hosts` holds:
  ```
  52:54:00:c4:02:30  iso2-srv   192.168.100.30  server
  52:54:00:C4:02:31  iso2-cli   192.168.100.31  client
  52-54-00-c4-02-39  iso2-neg2  192.168.100.39  client
  ```
  (The last two lines deliberately use other MAC notations, as in Review Focus 2.) Create the admin key once:
  `[[ -f ~/idm-lab-secrets/iso2_chpadmin ]] || ssh-keygen -q -t ecdsa -b 384 -N '' -C iso2-chpadmin -f ~/idm-lab-secrets/iso2_chpadmin`.

- [ ] **Step 2: Write `lab/iso2/make-stick.sh`** (aero, sudo): `make-stick.sh DIR IMG` makes a 64 MB raw file, `mkfs.vfat -n OEMDRV`, loop-mounts
  it, copies `DIR/*` in, and unmounts. A companion `read-stick.sh IMG` lists the files and prints `escrow/*.txt` **with the secret
  values masked** (`LUKS_PASSPHRASE=<32 chars>`) so no secret reaches a log.

- [ ] **Step 3: Write `lab/iso2/install.sh`** (aero, sudo): `install.sh NAME MAC ROLE STICK_IMG [NDISKS]`. It uses `virt-install` with:
  - the client1 firmware flags (q35, UEFI Secure Boot with enrolled keys, vTPM)
  - `--network bridge=br-lab,mac=MAC`
  - `--disk path=/data/libvirt/images/NAME.qcow2,size=120` (twice when NDISKS=2)
  - `--disk path=STICK_IMG,format=raw,bus=usb,removable=on`
  - `--initrd-inject` for both `ROLE.ks` and `chp-site.pyz`
  - `--extra-args "inst.ks=file:/ROLE.ks chp.repo=http://192.168.100.1:8080/chp/0.2.0 fips=1 console=ttyS0,115200 inst.text"`
  - `--wait 90`, and the serial log to `/var/log/libvirt/qemu/NAME-install.log`

  It exits 0 only when the VM powered off. For negatives, a `--expect-stop` flag waits up to 10 min for the text `CHP: install stopped
  before any disk was touched` in the serial log, then destroys the VM.

- [ ] **Step 4: Write `lab/iso2/prove.sh`** (Mac). Every check prints `PASS|FAIL <what>`, and the script exits non-zero on any FAIL:
  1. `chp-site validate` on the rendered site passes, and on a copy with an ed25519 key fails naming FIPS.
  2. **neg1** (unknown MAC): install stops; the serial log names the MACs; the qcow2 is still empty (`qemu-img info` actual size < 2 MB); no `escrow/` on the stick.
  3. **neg2** (two disks, none named): install stops with "name one in the hosts table"; both disks are empty.
  4. **server** install of `iso2-srv` finishes (VM powered off). Then boot it and check:
     - `ssh -i iso2_chpadmin chpadmin@192.168.100.30` works
     - `hostname -f` = `iso2-srv.iso2.lab.test`; `ip -4 addr` shows .30
     - `fips-mode-setup --check` enabled; `getenforce` Enforcing
     - `lsblk -f` shows `crypto_LUKS`; `/etc/chp/site.conf` and `hosts` exist at 0644, with no `client.conf` and no `escrow`
     - `grep -rs "LUKS_PASSPHRASE\|--passphrase" /root/*.cfg /root/*.log` finds nothing (row 16: the passphrase never reached disk)
     - `rpm -q chp-site` and `rpm -K` show our key
     - root's console password from the escrow works via `su -c id` (expect, with the value read from the stick on aero and never echoed)
     - the escrow's LUKS passphrase opens the disk (`cryptsetup open --test-passphrase`, run as root through the same su)
  5. **export-client:**
     - copy the lab srv1's public `root_ca.crt` and `user_ca.pub` to the Mac (`/tmp`)
     - `chp-site export-client --stick <stick dir> --site lab/iso2 rendered site.conf --root … --ssh-ca …`
     - rebuild the stick image with `client.conf` (the escrow from step 4 carried over)
  6. **client** install of `iso2-cli`: the same checks as step 4, plus `/etc/chp/client.conf` present and equal to the stick's.
  7. **Review Focus 4:** re-run the `iso2-srv` install on the same stick. `escrow/iso2-srv.txt.*.old` now exists, and the new escrow differs.
  8. Clean up: `virsh destroy`/`undefine --nvram --remove-all-storage` for every `iso2-*` VM; shred the rendered stick directory on the Mac.
  Expected: every line PASS. Installs of graphical-server + CUI take about 30–45 min each. Run `prove.sh` in the background and
  **poll its log yourself** at least every 15 minutes, never waiting silently.

- [ ] **Step 5: Write `lab/iso2/PROOF-RECORD.md`:** date, versions (chp-site 0.1.0, repo 0.2.0), each PASS/FAIL line with the observed value,
  install durations, and anything Anaconda did differently from the plan's assumptions. In particular, record whether
  Anaconda verified package signatures from the `repo --baseurl` repo, which is **not assumed**: check `/root/chp-post.log`,
  `/var/log/anaconda/packaging.log` and `dnf.librepo.log` for a gpgcheck statement.

- [ ] **Step 6: Tests, scan, commit.** `uv run pytest -q` passes; `bash lab/tools/secrets-scan.sh` shows only the known fixture hits;
  `grep -r "LUKS_PASSPHRASE=[A-Za-z0-9_-]\{20\}" lab/iso2` finds nothing. Commit `lab/iso2/` with the message
  `ISO Plan 2 Task 8: install proof — %pre gate stops unknown MAC / ambiguous disk before disks; server + client installs from stick`.

---

## Self-review (done while writing)

- **Spec coverage (plan 2, as amended by the user's decisions):**
  - §4.1 format → Tasks 1–3
  - §4.2 validation (every listed rejection: malformed/unknown key, IP outside SUBNET, duplicate MAC/hostname/IP, not exactly one
    server, MAC absent, role mismatch, client.conf missing or inconsistent) → Tasks 1–4
  - §4.3 export → Tasks 3 and 5
  - §5.1 kickstart (graphical-server, UEFI, LUKS2 with swap inside, CUI, FIPS, `%pre` gate, `%post` copy 0644) → Tasks 4 and 6
  - `repo_gpgcheck` on the host → Task 7
  - §10 "anything wrong stops the install in `%pre`" → Tasks 4 and 8
  - Break-glass and disk decisions → Tasks 4 and 8
  - Moved to Plan 3: onboard, revoke, unexpire
- **Not in this plan:**
  - first-boot units: clevis bind, shred `original-ks.cfg`, restorecon (spec §5.2 → Plans 3/4); Task 8 verifies that
    no passphrase reaches disk at all
  - role RPMs (Plans 3/4)
  - the ISO itself and the For Jeff release (Plan 5)
- **New site key vs spec §4.1:** `TIMEZONE` (a kickstart needs it) and `ADMIN_SSH_PUBKEY` (break-glass decision). Both are public values;
  `site.conf` still holds no secrets.
- **Open for Plan 4 (recorded, not built here):** the client role's sshd rule `publickey,keyboard-interactive:pam` (row 10) would also demand
  a GA code from `chpadmin`. Break-glass must then be a `Match User chpadmin` exception (publickey only), which needs an ISSO decision.
