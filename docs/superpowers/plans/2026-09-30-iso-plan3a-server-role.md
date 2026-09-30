# ISO Plan 3a: The Identity-Server Role — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A host installed with `server.ks` comes up after one unattended first boot as a working identity server:
- BIND serves the site zone
- step-ca issues from an **intermediate** (the **root key is moved offline** to the site stick)
- Kanidm serves `https://idm.<DOMAIN>` with an ACME certificate that renews itself
- the collector has a read-only token
- the SSH CA exists
- the disk is **bound to the TPM** (no passphrase at later boots)
- monitors warn until the recovery secrets are moved offline

Proven by a real install on aero.

**Architecture:** Two new RPMs.
- **`chp-base`** is common to both roles. It has three parts:
  - a first-boot unit that does the TPM binding with a one-time key, runs `restorecon` on the identity paths, and shreds `original-ks.cfg`
  - a monitor framework (a timer that runs the checks in `/usr/lib/chp/monitor.d/`, logs to the journal and calls `ALERT_HOOK`)
  - the common checks
- **`chp-identity-server`** is the server role. Its first-boot unit runs idempotent steps (each marked done in `/var/lib/chp/firstboot/`):
  - bind, step-ca, kanidm-cert, kanidmd, recover, collector, ssh-ca
  - it also ships the renewal unit with an ACME fallback and the server checks

`chp-site` (0.2.0) gains two things:
- `get` and `render`, so every config file is generated from the validated site files (the shell never parses them)
- `export-client` now also **moves the pending recovery secrets** (Kanidm admin passwords, the step-ca password, the root CA key) from `/root/chp-escrow-pending/` onto the stick. It then shreds them on the server.

**Tech Stack:** Python 3.9 stdlib (`chp-site`), bash, systemd units, expect (Kanidm login, proven in the lab), step-cli/step-ca 0.30.2,
Kanidm 1.11.2 (FIPS TLS variant), BIND, clevis/tpm2, cryptsetup (LUKS2), RPM, the Plan 2 lab harness (`lab/iso2`).

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md` §5.2–§5.4, §6. Requirements log `lab/iso-requirements.md`
(rows 3, 4, 5, 13, 15, 16, 17, 23, 24, 26, 31, 33, 34). The lab's proven server build is `lab/srv1/*` (Plan 3 of the lab), which this role reproduces unattended.

## Decisions for this plan (user, 2026-09-30)

1. **The server as its own client** (Kanidm login + GA on the server) is added in **Plan 4**, after the client role exists. Until then
   admins reach the server as `chpadmin` (break-glass).
2. **The step-ca root key goes offline.** First boot creates root + intermediate, moves the root key (and a copy of the CA password)
   into `/root/chp-escrow-pending/`, and `chp-site export-client` moves them onto the stick. step-ca runs on the intermediate only.
3. **Plan 3 is split:** this plan (3a) is the server role. `chp-site onboard / revoke / unexpire` are Plan 3b.

**My design choice (recorded; the spec leaves the mechanism open):**
- **The problem:** the TPM binding needs a key the disk already accepts, and the escrowed passphrase must not reach the disk (Plan 2 proof).
- **At install:** `%post --nochroot` adds a **one-time random 64-byte key** to a new LUKS slot, using the passphrase that exists only in installer RAM. It writes that key to `/root/.chp-bind.key` (0400) on the encrypted disk.
- **At first boot:** bind clevis (TPM2, PCR 7) with that key, then **kill that LUKS slot** and shred the file.

## Global Constraints

- All Plan 2 constraints still hold, in particular:
  - secrets never go to a log, the console, `/etc/chp`, argv or the repo
  - validate before writing
  - Python 3.9 stdlib only in `chp-site`
  - the branding header on shipped scripts
  - `Vendor`, `.chp` and Apache-2.0 on our RPMs
  - signing through `sign-session.sh`
- **Signing rounds follow the user's accessibility protocol:**
  - announce the round in one line and **wait for "ready"**
  - `say "PIN dialog open. Eyes on the screen."` when pinentry appears, and `say "Touch the key now."` for touches
  - never ask the user to type while a dialog may be open
- **Nothing site-specific in any RPM.** Every site value comes from `/etc/chp` through `chp-site get` / `chp-site render`.
- **First boot is idempotent.** Every step checks its own `.done` marker and can be re-run after a failure (except the one-way
  Kanidm domain init, which is guarded: it refuses when `/var/lib/chp/kanidm-domain` holds a different domain).
- Services the role enables: `named`, `step-ca`, `kanidmd`, `cert-renew-kanidm.timer`, `chp-monitor.timer`. The firewall is opened for
  `dns`, `https` and `9000/tcp` only; `http` is opened at runtime just for an ACME http-01 challenge.
- **Carry-forward from Plan 2:** the new repo must carry the fixed `chp-site` (this plan builds 0.2.0, which includes those fixes).

## Review Focus

1. **A first-boot step fails halfway (e.g. step-ca fails to start).** Expected: the unit fails loudly (journal + monitor), the step
   has no `.done` marker, re-running `systemctl start chp-server-firstboot` resumes from that step, and completed steps are not redone.
2. **The Kanidm domain init runs again with a changed site DOMAIN.** Expected: refused with a clear message; the existing database is untouched.
3. **`export-client` is interrupted between writing the stick and shredding.** Expected: the pending secrets are shredded only after the
   stick copy is written, synced and read back equal; a failed write leaves them in place, and the monitor keeps warning.
4. **The TPM refuses the binding (no TPM / Secure Boot off).** Expected: the first boot logs it loudly and keeps the one-time key slot
   **and** file, so a later `systemctl start chp-firstboot-common` can retry. The boot never fails; the escrowed passphrase still unlocks.
5. **The Kanidm certificate has already expired when renewal runs** (timer outage longer than the lifetime). Expected: `step ca renew`
   refuses, the unit falls back to an ACME re-issue, and kanidmd restarts on the new certificate (row 26).

---

## File Structure

```
appliance/chp-site/chp_site/
  render.py            + zone(), named_conf(), kanidm_server_toml(), kanidm_client_config(), collect_conf()
  sitevars.py          get(site, hosts, KEY): DOMAIN, SUBNET, SERVER_IP, SERVER_HOSTNAME, SERVER_FQDN, KANIDM_FQDN, CA_FQDN, ALERT_HOOK
  escrow.py            move_pending(pending_dir, stick, server_hostname): write → sync → read-back → shred
  cli.py               + get, render, export-client (auto-mounts LABEL=OEMDRV; moves pending secrets)
  pre.py               + /tmp/chp/luks-pass (0600, installer RAM) for the one-time LUKS key in %post --nochroot
appliance/rpm/chp-base/
  chp-base.spec
  firstboot-common.sh, chp-firstboot-common.service
  monitor.sh, chp-monitor.service, chp-monitor.timer, monitor.d/10-restorecon.sh, monitor.d/20-clock.sh
  build-rpm.sh
appliance/rpm/chp-identity-server/
  chp-identity-server.spec
  server-firstboot.sh, chp-server-firstboot.service
  cert-renew-kanidm.sh, cert-renew-kanidm.service, cert-renew-kanidm.timer
  kanidmd-tls.conf            (drop-in: root pre-start copy of the TLS pair, lab D7)
  kanidm-login.exp            (password from stdin; lab-proven)
  monitor.d/30-kanidm-cert.sh, 31-renew-timer.sh, 40-escrow-pending.sh
  build-rpm.sh
appliance/kickstart/chp.ks.in  + @ROLE_PACKAGES@; %post --nochroot adds the one-time LUKS key
tests/
  test_chp_site_get_render.py, test_chp_site_escrow.py, test_chp_base_monitor.py, test_server_role_static.py
lab/iso3/
  prove.sh, PROOF-RECORD.md   (reuses lab/iso2 helpers; repo URL is a parameter)
```

---

### Task 1: `chp-site get` and `chp-site render`

**Files:**
- Create: `appliance/chp-site/chp_site/sitevars.py`, `tests/test_chp_site_get_render.py`
- Modify: `appliance/chp-site/chp_site/render.py`, `appliance/chp-site/chp_site/cli.py`

**Interfaces:**
- Produces:
  - `sitevars.values(site, hosts) -> dict[str,str]`, with keys `DOMAIN SUBNET SUBNET_CIDR SERVER_IP SERVER_HOSTNAME SERVER_FQDN KANIDM_FQDN CA_FQDN ALERT_HOOK`
  - `render.zone(site, hosts, serial:int) -> str`
  - `render.named_conf(site, hosts) -> str`
  - `render.kanidm_server_toml(site, hosts) -> str`
  - `render.kanidm_client_config(site) -> str`
  - `render.collect_conf(site) -> str`
  - CLI: `chp-site get KEY [--site /etc/chp]` prints one value. `chp-site render WHAT [--site /etc/chp]` prints one file, where WHAT is one of
    `zone named-conf kanidm-server kanidm-config collect-conf`.

- [ ] **Step 1: Write the failing tests** `tests/test_chp_site_get_render.py`:
  ```python
  import re
  import subprocess
  import sys
  from pathlib import Path

  import pytest

  from chp_site.hosts import parse_hosts
  from chp_site.render import collect_conf, kanidm_client_config, kanidm_server_toml, named_conf, zone
  from chp_site.sitefile import parse_site
  from chp_site.sitevars import values
  from tests.test_chp_site_hosts import HOSTS
  from tests.test_chp_site_sitefile import GOOD

  SITE = parse_site(GOOD); HS = parse_hosts(HOSTS, SITE)
  PKG = Path(__file__).resolve().parents[1] / "appliance" / "chp-site"


  def test_values():
      v = values(SITE, HS)
      assert v["SERVER_IP"] == "192.168.100.30" and v["SERVER_FQDN"] == "iso2-srv.iso2.lab.test"
      assert v["KANIDM_FQDN"] == "idm.iso2.lab.test" and v["CA_FQDN"] == "ca.iso2.lab.test"
      assert v["SUBNET_CIDR"] == "192.168.100.0/24"


  def test_zone_has_every_host_and_the_service_names():
      z = zone(SITE, HS, 2026093001)
      assert "@ IN SOA iso2-srv.iso2.lab.test. hostmaster.iso2.lab.test. ( 2026093001" in z
      for name, ip in (("iso2-srv", ".30"), ("iso2-cli", ".31"), ("idm", ".30"), ("ca", ".30")):
          assert re.search(rf"^{name}\s+IN A\s+192\.168\.100{re.escape(ip)}$", z, re.M), name


  def test_named_conf_is_authoritative_only_for_the_subnet():
      n = named_conf(SITE, HS)
      assert "listen-on port 53 { 127.0.0.1; 192.168.100.30; };" in n and "allow-query { 127.0.0.1; 192.168.100.0/24; };" in n
      assert "recursion no;" in n and 'zone "iso2.lab.test" IN { type primary; file "iso2.lab.test.zone";' in n


  def test_named_conf_forwards_when_forwarders_are_set():
      s = parse_site(GOOD.replace("DNS_FORWARDERS=", "DNS_FORWARDERS=192.168.100.1"))
      n = named_conf(s, HS)
      assert "recursion yes;" in n and "forwarders { 192.168.100.1; };" in n and "forward only;" in n


  def test_kanidm_files():
      t = kanidm_server_toml(SITE, HS)
      assert 'bindaddress = "192.168.100.30:443"' in t and 'domain = "idm.iso2.lab.test"' in t
      assert 'origin = "https://idm.iso2.lab.test"' in t and 'tls_key = "/run/kanidmd/tls_key.pem"' in t
      c = kanidm_client_config(SITE)
      assert 'uri = "https://idm.iso2.lab.test"' in c and 'ca_path = "/etc/pki/ca-trust/source/anchors/chp-root.crt"' in c
      assert collect_conf(SITE) == ("KANIDM_URL=https://idm.iso2.lab.test\n"
                                    "CA_ANCHOR=/etc/pki/ca-trust/source/anchors/chp-root.crt\n")


  def cli(*a, site=None):
      return subprocess.run([sys.executable, "-m", "chp_site.cli", *a], cwd=PKG, capture_output=True, text=True)


  def test_cli_get_and_render(tmp_path):
      (tmp_path / "site.conf").write_text(GOOD); (tmp_path / "hosts").write_text(HOSTS)
      r = cli("get", "SERVER_IP", "--site", str(tmp_path))
      assert r.returncode == 0 and r.stdout == "192.168.100.30\n"
      assert cli("get", "NOPE", "--site", str(tmp_path)).returncode == 2
      r = cli("render", "zone", "--site", str(tmp_path))
      assert r.returncode == 0 and "idm" in r.stdout
  ```
  Run: `uv run pytest tests/test_chp_site_get_render.py -q`. Expected: FAIL (module missing).

- [ ] **Step 2: Write `appliance/chp-site/chp_site/sitevars.py`** (with the header):
  ```python
  """Derived site values for the shell (first-boot scripts use `chp-site get KEY`; they never parse site files)."""
  from .hosts import server_of

  ANCHOR = "/etc/pki/ca-trust/source/anchors/chp-root.crt"


  def values(site, hosts):
      srv = server_of(hosts)
      d = site["DOMAIN"]
      return {"DOMAIN": d, "SUBNET": str(site["SUBNET"].network_address), "SUBNET_CIDR": str(site["SUBNET"]),
              "SERVER_IP": srv.ip, "SERVER_HOSTNAME": srv.hostname, "SERVER_FQDN": f"{srv.hostname}.{d}",
              "KANIDM_FQDN": f"idm.{d}", "CA_FQDN": f"ca.{d}", "ALERT_HOOK": site["ALERT_HOOK"]}
  ```

- [ ] **Step 3: Add to `render.py`:**
  ```python
  from .sitevars import ANCHOR, values


  def zone(site, hosts, serial):
      v = values(site, hosts)
      lines = ["$TTL 300",
               f"@ IN SOA {v['SERVER_FQDN']}. hostmaster.{v['DOMAIN']}. ( {serial} 3600 600 86400 300 )",
               f"@ IN NS {v['SERVER_FQDN']}."]
      for h in hosts:
          lines.append(f"{h.hostname:<12} IN A {h.ip}")
      lines += [f"{'idm':<12} IN A {v['SERVER_IP']}", f"{'ca':<12} IN A {v['SERVER_IP']}"]
      return "\n".join(lines) + "\n"


  def named_conf(site, hosts):
      v = values(site, hosts)
      fw = site["DNS_FORWARDERS"]
      rec = (f"    recursion yes;\n    allow-recursion {{ 127.0.0.1; {v['SUBNET_CIDR']}; }};\n"
             f"    forwarders {{ {'; '.join(fw)}; }};\n    forward only;\n") if fw else "    recursion no;\n"
      return ("options {\n"
              f"    listen-on port 53 {{ 127.0.0.1; {v['SERVER_IP']}; }};\n"
              "    listen-on-v6 { none; };\n"
              '    directory "/var/named";\n'
              f"    allow-query {{ 127.0.0.1; {v['SUBNET_CIDR']}; }};\n"
              + rec +
              "    dnssec-validation no;\n"
              '    pid-file "/run/named/named.pid";\n'
              "};\n"
              'logging { channel default_debug { file "data/named.run"; severity dynamic; }; };\n'
              f'zone "{v["DOMAIN"]}" IN {{ type primary; file "{v["DOMAIN"]}.zone"; allow-update {{ none; }}; }};\n')


  def kanidm_server_toml(site, hosts):
      v = values(site, hosts)
      return ('version = "2"\n'
              f'bindaddress = "{v["SERVER_IP"]}:443"\n'
              'db_path = "/var/lib/private/kanidm/kanidm.db"\n'
              'tls_chain = "/run/kanidmd/tls_chain.pem"\n'
              'tls_key = "/run/kanidmd/tls_key.pem"\n'
              f'domain = "{v["KANIDM_FQDN"]}"\n'
              f'origin = "https://{v["KANIDM_FQDN"]}"\n'
              'log_level = "info"\n\n'
              "[online_backup]\n"
              'path = "/var/lib/private/kanidm/backups/"\n'
              'schedule = "00 22 * * *"\n'
              "versions = 7\n")


  def kanidm_client_config(site):
      return f'uri = "https://idm.{site["DOMAIN"]}"\nca_path = "{ANCHOR}"\n'


  def collect_conf(site):
      return f"KANIDM_URL=https://idm.{site['DOMAIN']}\nCA_ANCHOR={ANCHOR}\n"
  ```

- [ ] **Step 4: Add the `get` and `render` sub-commands to `cli.py`.** `--site` defaults to `/etc/chp`. Both read site.conf and hosts through
  `read_file`. An unknown KEY or WHAT gives a SiteError, which is exit 2. For `render zone`, the serial is `int(time.strftime("%Y%m%d")) * 100 + 1`.

- [ ] **Step 5: Run the tests** (the file, then the whole suite). Expected: all pass. **Commit** with the message
  `ISO Plan 3a Task 1: chp-site get/render (zone, named.conf, kanidm server/client config, collect.conf)`.

---

### Task 2: `chp-site` escrow move + the LUKS pass for `%post`; version 0.2.0

**Files:**
- Create: `appliance/chp-site/chp_site/escrow.py`, `tests/test_chp_site_escrow.py`
- Modify: `appliance/chp-site/chp_site/cli.py` (export-client), `appliance/chp-site/chp_site/pre.py`, `appliance/chp-site/chp_site/__init__.py` (VERSION 0.2.0),
  `appliance/chp-site/chp-site.spec` (Version 0.2.0), `tests/test_chp_site_pre.py`, `tests/test_chp_site_cli.py`

**Interfaces:**
- Produces:
  - `escrow.move_pending(pending: Path, stick: Path, server_hostname: str, now: str) -> list[str]`. It writes `stick/escrow/<server>-server.txt`, holding every
    pending file as a `KEY=<base64>` line (`KANIDM_ADMINS_JSON`, `STEP_CA_PASSWORD`, `ROOT_CA_KEY_PEM`), with any old file renamed `.old`. It then syncs,
    reads the file back and compares, and only then shreds the pending files (overwrite with random bytes + unlink). It returns the names moved.
    Nothing to move gives `[]`.
  - `export-client` without `--stick` mounts `/dev/disk/by-label/OEMDRV` on a temporary directory and unmounts it at the end. It moves the pending
    secrets when `/root/chp-escrow-pending` is non-empty, and prints only file names, never values.
  - `pre` also writes `/tmp/chp/luks-pass` (0600): the LUKS passphrase, for `%post --nochroot` only.

- [ ] **Step 1: Write the failing tests** `tests/test_chp_site_escrow.py`:
  ```python
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
  ```
  Add a test to `tests/test_chp_site_pre.py`: `luks-pass` exists at 0600, holds exactly the passphrase from `disk.ks`, and
  `users.ks` still holds no plaintext. Update `test_zipapp_builds_and_runs` to expect `chp-site 0.2.0`. Run the tests. Expected: FAIL.

- [ ] **Step 2: Write `appliance/chp-site/chp_site/escrow.py`** (with the header):
  ```python
  """Move the server's pending recovery secrets onto the site stick: write, sync, read back, THEN shred on the server."""
  import base64
  import os
  from pathlib import Path

  from .sitefile import SiteError

  KEYS = {"kanidm-admins.json": "KANIDM_ADMINS_JSON", "step-ca-password": "STEP_CA_PASSWORD", "root_ca_key": "ROOT_CA_KEY_PEM"}


  def _shred(p):
      n = p.stat().st_size
      with open(p, "r+b") as f:
          f.write(os.urandom(max(n, 1))); f.flush(); os.fsync(f.fileno())
      p.unlink()


  def move_pending(pending, stick, server_hostname, now):
      pending, stick = Path(pending), Path(stick)
      files = sorted(f for f in pending.iterdir() if f.is_file()) if pending.is_dir() else []
      if not files:
          return []
      body = [f"# {server_hostname} server recovery secrets, moved off the server {now}. KEEP THIS STICK OFFLINE."]
      for f in files:
          body.append(f"{KEYS.get(f.name, f.name.upper().replace('-', '_').replace('.', '_'))}="
                      f"{base64.b64encode(f.read_bytes()).decode()}")
      text = "\n".join(body) + "\n"
      d, out = stick / "escrow", stick / "escrow" / f"{server_hostname}-server.txt"
      try:
          d.mkdir(exist_ok=True)
          if out.exists():
              out.rename(d / f"{out.name}.{now}.old")
          out.write_text(text)
          os.sync()
          if out.read_text() != text:
              raise OSError(0, "read-back mismatch")
      except OSError as e:
          raise SiteError(f"could not write the server secrets to the stick ({e.strerror}); they are kept on the server "
                          "and the monitor keeps warning") from None
      for f in files:
          _shred(f)
      return [f.name for f in files]
  ```

- [ ] **Step 3: `pre.py`:** after the snippets, also write `out / "luks-pass"` (0600, the passphrase only, no newline).
  **`cli.py` export-client:**
  - `--stick` becomes optional. Without it, mount `/dev/disk/by-label/OEMDRV` (`mount` + `umount` via subprocess, in a `tempfile.mkdtemp(dir="/run")`).
  - After writing `client.conf`, call `move_pending(Path("/root/chp-escrow-pending"), stick, SERVER_HOSTNAME, now)` and print
    `moved to the stick: <names>` or `no pending server secrets`.
  - Keep the printed fingerprints. Set VERSION and the spec Version to `0.2.0`.

- [ ] **Step 4: Run the tests** (the new ones, then the suite). **Commit** with the message
  `ISO Plan 3a Task 2: chp-site 0.2.0 — export-client moves the server's pending secrets to the stick (write/sync/read-back/shred); luks-pass for %post`.

---

### Task 3: `chp-base`: first-boot common + the monitor framework

**Files:**
- Create: `appliance/rpm/chp-base/{chp-base.spec,firstboot-common.sh,chp-firstboot-common.service,monitor.sh,chp-monitor.service,chp-monitor.timer,build-rpm.sh}`,
  `appliance/rpm/chp-base/monitor.d/{10-restorecon.sh,20-clock.sh}`, `tests/test_chp_base_monitor.py`

**Interfaces:**
- `firstboot-common.sh` (root, run once by `chp-firstboot-common.service`) does three things:
  1. **TPM binding.** When `/root/.chp-bind.key` exists, find the LUKS device (`lsblk -rpno NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1}'`, exactly one).
     Run `clevis luks bind -y -k /root/.chp-bind.key -d DEV tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'`. On success, find that
     key's slot (`cryptsetup luksOpen --test-passphrase --key-file … --verbose` reports "Key slot N unlocked"), run `cryptsetup luksKillSlot -q DEV N`, and
     shred the file. On failure, log `CHP: TPM binding failed (<reason>); the escrowed passphrase still unlocks; retry: systemctl start chp-firstboot-common`,
     and leave the key file and slot in place (Review Focus 4).
  2. `restorecon -R` over `/etc/chp /etc/kanidm /etc/pki/kanidm /etc/ssh-ca /var/lib/ssh-ca /etc/step-ca /etc/idm-collect` (existing paths only).
  3. `shred -u /root/original-ks.cfg /root/anaconda-ks.cfg` if present (row 16).

  The `.done` marker `/var/lib/chp/firstboot/common.done` is set only when all three succeeded. A binding failure still sets `common.bind-failed`
  and exits 0 (the boot never fails).
- `monitor.sh` runs every executable in `/usr/lib/chp/monitor.d/` (sorted). Each check prints `OK <text>` or `ALERT <text>` and exits 0.
  - Every `ALERT` goes to `logger -p auth.warning -t chp-monitor` and, when `chp-site get ALERT_HOOK` is non-empty and executable, to `$HOOK "<text>"`.
  - It exits 1 if any check alerted. `CHP_MONITOR_DIR` overrides the directory for tests.
- The checks shipped here: `10-restorecon.sh` (`restorecon -nRv` over the identity paths prints nothing, otherwise ALERT with the paths), and `20-clock.sh`
  (`chronyc tracking` "System time" offset ≤ 30 s, otherwise ALERT; #30).

- [ ] **Step 1: Write the failing test** `tests/test_chp_base_monitor.py`. It runs `monitor.sh` with `CHP_MONITOR_DIR` pointing at temp checks, and `PATH`
  stubs for `logger` and `chp-site` that record their calls:
  - two OK checks: exit 0, no logger call
  - one ALERT check: exit 1; logger called once with the text; the hook is called when `chp-site get ALERT_HOOK` returns an executable path
  - a non-executable file in the directory is skipped
  - a check that itself fails (exit 3) is reported as `ALERT <name> failed (exit 3)`

  Run it. Expected: FAIL.
- [ ] **Step 2: Write `monitor.sh`, the two checks and the units.**
  - `chp-monitor.timer`: `OnBootSec=10min`, `OnUnitActiveSec=15min`.
  - `chp-firstboot-common.service`: `Type=oneshot`, `After=network-online.target`, `ConditionPathExists=!/var/lib/chp/firstboot/common.done`, `WantedBy=multi-user.target`.

  Then `firstboot-common.sh` as described above.
- [ ] **Step 3: Write `chp-base.spec`** (noarch; `Requires: clevis clevis-luks clevis-systemd tpm2-tools cryptsetup policycoreutils chrony chp-site`).
  It installs the scripts to `/usr/libexec/chp/`, the checks to `/usr/lib/chp/monitor.d/` (0755), the units to `%{_unitdir}`, and creates `/var/lib/chp/firstboot` (0700).
  `%post` runs `%systemd_post chp-firstboot-common.service chp-monitor.timer`; the kickstart's `%post` enables them. Also write `build-rpm.sh`, following
  `appliance/chp-site/build-rpm.sh`.
- [ ] **Step 4: Run the tests** (the monitor test, then the suite). Run `bash -n` on every script. **Commit** with the message
  `ISO Plan 3a Task 3: chp-base — TPM bind via one-time LUKS key (slot killed after), restorecon, shred ks files; monitor framework + common checks`.

---

### Task 4: `chp-identity-server`: first boot, renewal with ACME fallback, server checks

**Files:**
- Create: everything under `appliance/rpm/chp-identity-server/` (see File Structure), `tests/test_server_role_static.py`

**Interfaces:**
- `server-firstboot.sh` (root, `chp-server-firstboot.service`, `After=chp-firstboot-common.service network-online.target`,
  `ConditionPathExists=!/var/lib/chp/firstboot/server.done`). Every value comes from `chp-site get …`. The steps, in order, each guarded by `/var/lib/chp/firstboot/<step>.done`:
  1. **bind:**
     - write `chp-site render named-conf` to `/etc/named.conf` (0640 root:named) and `render zone` to `/var/named/$DOMAIN.zone` (0640 root:named)
     - `restorecon`, `named-checkconf`, `named-checkzone`, `systemctl enable --now named`, firewall `dns`
     - check that `dig +short @$SERVER_IP $KANIDM_FQDN` equals `$SERVER_IP`
  2. **step-ca:**
     - `STEPPATH=/etc/step-ca`; the password is 32 random bytes base64 in `/etc/step-ca/password` (0600, owned by step)
     - `step-cli ca init --name "$DOMAIN CA" --dns $CA_FQDN --dns $SERVER_FQDN --address $SERVER_IP:9000 --provisioner admin --password-file … --provisioner-password-file … --deployment-type standalone --acme`
     - **move** `/etc/step-ca/secrets/root_ca_key` to `/root/chp-escrow-pending/root_ca_key` (0600), and copy the password to `/root/chp-escrow-pending/step-ca-password`
     - `chown -R step:step /etc/step-ca`
     - install the root cert as `/etc/pki/ca-trust/source/anchors/chp-root.crt` (0644), then `update-ca-trust`
     - `systemctl enable --now step-ca` (the unit ships in the step-ca RPM), firewall `9000/tcp`
     - `step-cli ca health`
  3. **kanidm-cert:**
     - `STEPPATH=/root/.step step-cli ca bootstrap` with the root fingerprint
     - issue `$KANIDM_FQDN` via the `acme` provisioner (http-01; `firewall-cmd --add-service=http` at runtime only, removed by trap) into `/etc/pki/kanidm/{chain,key}.pem` (dir 0700, files 0600)
     - `systemctl enable --now cert-renew-kanidm.timer`
  4. **kanidmd:**
     - **domain guard:** if `/var/lib/chp/kanidm-domain` exists and differs from `$KANIDM_FQDN`, then ALERT and exit 1 (Review Focus 2); otherwise write it
     - `render kanidm-server` goes to `/etc/kanidm/server.toml` (0644); `render kanidm-config` goes to `/etc/kanidm/config` (0644)
     - `systemctl enable --now kanidmd`, firewall `https`
     - wait up to 60 s for `curl -fsS --cacert <anchor> https://$KANIDM_FQDN/status`
  5. **recover:** `kanidmd recover-account admin` and `idm_admin` (`-c /etc/kanidm/server.toml -o json`). Their passwords go into
     `/root/chp-escrow-pending/kanidm-admins.json` (0600, `{"admin":…,"idm_admin":…}`) through python reading stdin; nothing is printed.
  6. **collector:**
     - log in as `idm_admin` (`kanidm-login.exp`, password on stdin from the JSON)
     - create service account `idm-collect` (in `idm_service_desk` and `idm_unix_admins`)
     - generate a **read-only** API token into `/etc/idm-collect/kanidm.token` (0600)
     - `render collect-conf` goes to `/etc/idm-collect/collect.conf` (0644)
     - the collector must report no `collect.conf` errors
  7. **ssh-ca:** `/etc/ssh-ca` (0700) with a P-384 `user_ca`; `/var/lib/ssh-ca/{keys,issued}` (0755); `restorecon`.

  Finally touch `server.done` and log `CHP: server first boot complete. Move the recovery secrets offline: plug in the site stick and run chp-site export-client`.
  Any failing step exits non-zero with `CHP: server first boot failed at <step>` (Review Focus 1).
- `cert-renew-kanidm.sh`: `step-cli ca renew --force --expires-in 8h --exec "systemctl try-restart kanidmd" chain key`. **If renew fails and the certificate has
  expired** (`step-cli certificate needs-renewal`, or openssl `-checkend 0` fails), re-issue via ACME exactly as in step 3, then restart kanidmd (row 26, Review Focus 5).
- `kanidmd-tls.conf` is the lab D7 drop-in (root pre-start `install -o kanidmd -g kanidmd -m 0400 …` into `/run/kanidmd/`).
- Server checks:
  - `30-kanidm-cert.sh`: ALERT when the served certificate expires within 7 days, or cannot be fetched (row 24)
  - `31-renew-timer.sh`: ALERT when `cert-renew-kanidm.timer` is not active (row 24)
  - `40-escrow-pending.sh`: ALERT `recovery secrets still on the server (<names>): plug in the site stick and run chp-site export-client` while
    `/root/chp-escrow-pending` is non-empty
- Spec `chp-identity-server.spec`: noarch; `Requires: chp-base chp-site kanidm-server kanidm-clients step-ca step-cli bind bind-utils idm-collect expect python3 curl openssl`.

- [ ] **Step 1: Write the failing test** `tests/test_server_role_static.py`:
  - every `.sh` starts with the branding header and passes `bash -n`
  - no `.sh`, unit or spec contains a lab value (`kanidm.lab.test`, `192.168.100`, `iso2`)
  - `server-firstboot.sh` contains the seven step names in order, each guarded by a `.done` check
  - the domain guard reads `/var/lib/chp/kanidm-domain`
  - `root_ca_key` is **moved** (`mv`), not copied, out of `/etc/step-ca/secrets`
  - no command line contains `password=` or `--password ` followed by a literal
  - `cert-renew-kanidm.sh` has an ACME re-issue branch
  - the units carry the `ConditionPathExists=!…done` guards

  Run it. Expected: FAIL.
- [ ] **Step 2: Write the scripts, units, checks and spec** as described. `kanidm-login.exp` is `lab/srv1/kanidm-login.exp` with the header added.
- [ ] **Step 3: Run the tests** (the static test, then the suite). **Commit** with the message
  `ISO Plan 3a Task 4: chp-identity-server — unattended first boot (bind, step-ca w/ offline root, ACME cert, kanidmd w/ domain guard, recover, collector, SSH CA), renewal w/ ACME fallback, server checks`.

---

### Task 5: Kickstart: role packages + the one-time LUKS key

**Files:**
- Modify: `appliance/kickstart/chp.ks.in`, `appliance/kickstart/render-ks.sh`, `tests/test_kickstarts.py`

- [ ] **Step 1: Failing tests.**
  - `server.ks` `%packages` lists `chp-base` and `chp-identity-server`; `client.ks` lists `chp-base` (the client role arrives in Plan 4).
  - `%post --nochroot` adds a LUKS key from `/tmp/chp/luks-pass` (`cryptsetup luksAddKey --key-file=/tmp/chp/luks-pass <dev> /mnt/sysimage/root/.chp-bind.key`)
    after creating the key file with `head -c 64 /dev/urandom` at 0400, and **shreds `/tmp/chp/luks-pass`**.
  - The chroot `%post` enables `chp-firstboot-common.service` and `chp-monitor.timer`, plus `chp-server-firstboot.service` in `server.ks` only.
- [ ] **Step 2: Implementation.** `render-ks.sh` substitutes `@ROLE_PACKAGES@` (server: `chp-base\nchp-identity-server`; client: `chp-base`) and
  `@ROLE_ENABLE@` (server: `chp-server-firstboot.service`; client: empty). Put the key steps into `%post --nochroot` (with `--erroronfail`, `set -e`):
  ```bash
  dev=$(lsblk -rpno NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1}')
  [ "$(echo "$dev" | wc -l)" -eq 1 ]
  ( umask 0377; head -c 64 /dev/urandom > /mnt/sysimage/root/.chp-bind.key )
  cryptsetup luksAddKey --key-file=/tmp/chp/luks-pass "$dev" /mnt/sysimage/root/.chp-bind.key
  shred -u /tmp/chp/luks-pass
  ```
- [ ] **Step 3: Run the tests** (including `ksvalidator`). **Commit** with the message
  `ISO Plan 3a Task 5: kickstart — role packages; one-time LUKS key for the first-boot TPM bind (escrowed passphrase never on disk)`.

---

### Task 6: Build the RPMs and sign repo 0.3.0 (the user's signing round)

- [ ] **Step 1: Build.** Bump `chp-site.spec` to `Version: 0.2.0`, `Release: 1.chp`. Run `appliance/chp-site/build-rpm.sh`, `appliance/rpm/chp-base/build-rpm.sh`
  and `appliance/rpm/chp-identity-server/build-rpm.sh` (all noarch, built on aero with fapolicyd enforcing: shell and data only, plus the shebang-less zipapp).
  Add `chp-base ours` and `chp-identity-server ours` to `PACKAGES.txt`, then assemble `/data/chp-release/0.3.0/stage` (10 packages).
- [ ] **Step 2: Signing round (protocol).** Tell the user in one line and **wait for "ready"**. Then start `sign-session.sh … sign-repo.sh … 0.3.0`. The moment
  it starts, `say "PIN dialog open. Eyes on the screen."`; while it runs, `say "Touch the key now."` every 20 seconds until it finishes.
  Expected: `REPO OK: 10 packages`. Serve it at `…/chp/0.3.0/`.
- [ ] **Step 3: Commit** the spec bumps, the build scripts and `PACKAGES.txt` with the message `ISO Plan 3a Task 6: RPMs + signed repo 0.3.0`.

---

### Task 7: Install proof on aero

**Files:** create `lab/iso3/prove.sh` and `lab/iso3/PROOF-RECORD.md`; parameterise `lab/iso2/install.sh` with `CHP_REPO` (default `0.2.0`).

- [ ] **Step 1: `lab/iso3/prove.sh`** reuses the iso2 helpers (it copies `lab/iso2/{stick.sh,install.sh,unlock.sh,luks-send.exp,rootcheck.exp}`).
  Its stages are `prep`, `server`, `firstboot`, `reboot`, `export`, `renew` and `cleanup`, with `CHP_REPO=0.3.0` and a site `iso3.lab.test` (hosts: `iso3-srv` .30,
  `iso3-cli` .31, not installed here). Checks, all run as root through the `rootcheck.exp` pattern (su with the escrowed root password, commands fixed in the script):
  - **server:** install + the escrow unlock (as in Plan 2).
  - **firstboot:** wait up to 20 min for `/var/lib/chp/firstboot/server.done`. Then check:
    - `common.done` exists, `.chp-bind.key` is gone, and `cryptsetup luksDump` shows **one** keyslot plus a clevis token
    - `/root/original-ks.cfg` and `/root/anaconda-ks.cfg` are gone
    - `dig` answers for `idm` and `ca`
    - `step-cli ca health` is ok, and **no `root_ca_key` exists under `/etc/step-ca`**
    - Kanidm `/status` is true over TLS verified by `chp-root.crt`
    - `cert-renew-kanidm.timer` is active
    - the collector (`idm-collect --user admin`) reports `errors: []`
    - `/root/chp-escrow-pending` holds the three secrets
    - `chp-monitor` alerts **only** "recovery secrets still on the server"
    - fapolicyd FANOTIFY count is 0; AVC count since boot is 0
  - **reboot:** `virsh reboot`. The disk **unlocks without the passphrase** (no LUKS prompt in the console log within 3 min; SSH answers), so the TPM binding works.
  - **export:**
    - `virsh attach-disk` the stick image as USB, then run `chp-site export-client` (as root, no `--stick`: auto-mount)
    - the stick now has `client.conf` and `escrow/iso3-srv-server.txt` (listed masked)
    - `/root/chp-escrow-pending` is empty
    - `chp-monitor` exits 0
    - `step-ca` still issues (a new ACME cert for a test name succeeds **without the root key**)
  - **renew (Review Focus 5):** stop the timer, make kanidmd's certificate expire (issue a 5-minute cert via ACME for `idm`, then wait until it has expired),
    run `cert-renew-kanidm.service`, and require a **fresh valid** certificate served on :443 afterwards.
  - **cleanup:** as in Plan 2.
- [ ] **Step 2: Run the stages** (the installs take about 12 min; poll the logs yourself every ≤ 10 min, and never wait silently). Every line must be PASS; for
  any FAIL, stop and debug with superpowers:systematic-debugging.
- [ ] **Step 3: `PROOF-RECORD.md`:** results and findings. Update `lab/iso-requirements.md` rows 15/16/23/24/26/31 with this evidence.
- [ ] **Step 4: Tests, scans, commit** with the message `ISO Plan 3a Task 7: server role proven — unattended first boot, TPM auto-unlock, root key offline, renew fallback`.

---

## Self-review (done while writing)

- **Spec coverage:**
  - §6.1 services (BIND, step-ca with `GODEBUG` in its RPM unit, ACME Kanidm cert + fallback, Kanidm file modes/TLS drop-in, SSH CA + records) → Task 4
  - §6.2 first boot (domain guard, collector account/read-only token, secrets root-only with a warning monitor) → Tasks 2 and 4
  - §5.2 common (clevis PCR 7 on the first real boot, shred ks, restorecon) → Tasks 3 and 5
  - §5.4 monitors (cert lifetime, timer, restorecon drift, secrets file, clock) → Tasks 3 and 4
  - Decision 2 (offline root) → Tasks 2, 4 and 7
- **Not in this plan:**
  - onboard / revoke / unexpire (Plan 3b)
  - the server as its own client, the diag account, TrustedUserCAKeys and the SSH CA record helper usage (Plan 4)
  - the GDM/GA stack (Plan 4)
  - ISO assembly and row 37 (Plan 5)
  - `authselect check` / `sshd -T` drift checks (client-role monitors, Plan 4)
- **Known assumption to verify in Task 7 (not assumed):** clevis TPM2 PCR 7 binding made on the first boot unlocks the next boot of the same VM.
  The lab proved this for client1 (UEFI Secure Boot + vTPM, Plan 4). If it does not hold, Review Focus 4 behaviour keeps the host usable, and the finding is recorded.
