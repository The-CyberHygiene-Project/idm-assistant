# Security bundle Plan W2 (Wazuh in ISO 0.3.0) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A site that sets `SECURITY_ADDONS=yes` on its site stick and installs from ISO 0.3.0 gets Wazuh at first boot: the manager on the server and an agent on every client, hardened exactly as W1. With the setting off, an install is the same as 0.2.0.

**Architecture:**
- **Keys travel like the client tokens.** The server's first boot runs `chp-site security enable --firstboot`, which writes the agent keys to the pending folder `/root/chp-escrow-pending/wazuh/`. `export-client` moves them to the stick (`wazuh/<host>.key`), with read-back, then shreds them. A client's `chp-site pre` stages its own key, `%post --nochroot` installs it as `/var/lib/chp/wazuh/agent.key` (0600), and the client's first boot uses it and shreds it.
- **Packages come from the ISO's signed repo.** When the setting is on, `%post --nochroot` copies it to `/var/lib/chp/repo`, so first boot installs the packages with `dnf --enablerepo=chp` (signature and `repo_gpgcheck` enforced). The host also keeps that repo for later updates.
- **No new USB access:** the stick is read only by the installer (before USBGuard exists) and by `export-client` (its existing pinned-stick path).

**Tech Stack:** Python 3.9 standard library (`chp-site`), bash, kickstart, RPM, the W1 packages.

**Spec:** `docs/superpowers/specs/2026-10-27-security-bundle-wazuh-design.md` §3 (new installs), §7 proofs 4–6, §8 Plan W2 (owner-approved 2026-10-27). Builds on branch `security-w1` (PR #35).

## Global Constraints

- **Additive site keys:**
  - `SECURITY_ADDONS=yes|no` (default `no`) and `SECURITY_ALERT_LEVEL=<3..15>` (default 10).
  - Older sticks without them still validate.
  - Automated_Compliance reads the kit, so this is flagged as additive in the PR.
- **With `SECURITY_ADDONS` off:** no Wazuh package, no repo copy, no `security` first-boot step, no `wazuh/` on the stick.
- **The W1 behaviour is unchanged:** `chp-site security enable` without `--firstboot` keeps using the stick, as on the update path.
- **Secrets:**
  - an agent key exists only in the server's `client.keys` (0640 root:wazuh), the pending folder (0700, AIDE-excluded), the stick, the installer's `/tmp/chp` (0600), and the client's `agent.key` (0600, shredded after use) and `client.keys`;
  - never in logs, audit records or command lines.
- **Proof 4 (spec §7):** fresh ISO 0.3.0 installs, with the add-on **off** (the server's package set has no Wazuh) and **on** (all three hosts, everything in place from first boot, and nothing to accept in AIDE for Wazuh, since the baseline is taken after first boot).
- **Proof 5:** the CUI scan shows no new failing rules against 0.2.0 (a deviation table, including the FIPS POA&M item).
- **Proof 6:** resources are recorded.
- **USBGuard:** the on-install proof must show no `allow-device` events other than those from `export-client`.
- **Commits** end with the session attribution lines. The owner merges. Each YubiKey signature waits for the owner's "go"; restart gpg-agent first.
- **Test command:** `cd ~/idm-assistant && .venv/bin/python -m pytest -q` (baseline on `security-w1`: 985 passed).

## Review Focus

1. **A client installed before `export-client` ran** has no `wazuh/<host>.key`. With the add-on on, `pre` must stop the install with a clear message, before any disk is touched, just as it does for a missing token.
2. **First boot fails halfway** (for example, the repo copy is missing). The `security` step must leave its `.done` marker unset, so a restart retries it, and `security enable` must be idempotent (W1).
3. **Key leakage:**
   - the staged files are 0600 and shredded;
   - the pending folder is excluded from AIDE;
   - `agent.key` is shredded only after `client.keys` is written.
4. **The repo copy fills `/var`.** 640 MB into the 20 GB `/var` is acceptable, but the copy must run only when the setting is on.
5. **A server whose first boot made keys, then the site re-ran `security enable`:** the keys must not change (W1 idempotence), so a stick written earlier stays valid.

---

### Task 1: Site keys `SECURITY_ADDONS` and `SECURITY_ALERT_LEVEL`

**Files:**
- Modify: `appliance/chp-site/chp_site/sitefile.py` (`parse_site`), `appliance/chp-site/chp_site/sitevars.py` (`values`), `appliance/site-stick-kit/site.conf.template`
- Test: `tests/test_chp_site_sitefile.py` (find the existing site-file tests with `grep -ln "parse_site" tests/`; append there), `tests/test_chp_site_sitevars.py` or the existing sitevars test

**Interfaces:**
- Produces:
  - `parse_site(...)["SECURITY_ADDONS"] in ("yes", "no")` (default `"no"`);
  - `parse_site(...)["SECURITY_ALERT_LEVEL"]`: an int, 3–15, default 10;
  - `values(...)` gains `"SECURITY_ADDONS"` and `"SECURITY_ALERT_LEVEL"` (as str), so first-boot scripts can run `chp-site get`.

- [ ] **Step 1: Write the failing tests** (append to the site-file test module; reuse its existing helper that builds a valid `site.conf` text, found by reading the file's first 40 lines)

```python
def test_security_keys_default_off(tmp_path):
    s = parse_site(VALID)                       # VALID: the module's existing minimal valid site.conf text
    assert s["SECURITY_ADDONS"] == "no" and s["SECURITY_ALERT_LEVEL"] == 10


def test_security_keys_parse():
    s = parse_site(VALID + "SECURITY_ADDONS=yes\nSECURITY_ALERT_LEVEL=12\n")
    assert s["SECURITY_ADDONS"] == "yes" and s["SECURITY_ALERT_LEVEL"] == 12


@pytest.mark.parametrize("line,msg", [("SECURITY_ADDONS=maybe", "SECURITY_ADDONS: yes or no"),
                                      ("SECURITY_ALERT_LEVEL=2", "SECURITY_ALERT_LEVEL: a number from 3 to 15"),
                                      ("SECURITY_ALERT_LEVEL=ten", "SECURITY_ALERT_LEVEL: a number from 3 to 15")])
def test_security_keys_refuse_bad_values(line, msg):
    with pytest.raises(SiteError, match=msg):
        parse_site(VALID + line + "\n")
```

For sitevars, add a test that `values(site, hosts)["SECURITY_ADDONS"] == "yes"` and `["SECURITY_ALERT_LEVEL"] == "12"` for that site. Use the existing `HOSTS` fixture from `tests/test_chp_site_hosts.py`.

If the module names its valid text differently, use its name. That is not a deviation.

- [ ] **Step 2: Run them to verify they fail.** Run: `.venv/bin/python -m pytest -q <the site-file test module>`. Expected: FAIL (`unknown key SECURITY_ADDONS`, and a `KeyError`).

- [ ] **Step 3: Implement.** In `parse_site`:
  - add `"SECURITY_ADDONS", "SECURITY_ALERT_LEVEL"` to `known`;
  - after the `ALERT_HOOK` block, add:

```python
    sa = raw.get("SECURITY_ADDONS", "no") or "no"
    if sa not in ("yes", "no"):
        raise SiteError("SECURITY_ADDONS: yes or no")
    s["SECURITY_ADDONS"] = sa
    lv = raw.get("SECURITY_ALERT_LEVEL", "10") or "10"
    if not (lv.isdigit() and 3 <= int(lv) <= 15):
        raise SiteError("SECURITY_ALERT_LEVEL: a number from 3 to 15 (Wazuh rule level; default 10)")
    s["SECURITY_ALERT_LEVEL"] = int(lv)
```

In `values()`, add `"SECURITY_ADDONS": site.get("SECURITY_ADDONS", "no")` and `"SECURITY_ALERT_LEVEL": str(site.get("SECURITY_ALERT_LEVEL", 10))`.

In `site.conf.template`, after the `ALERT_HOOK` block, add:

```
# Optional (0.3.0 on): the security add-on (Wazuh log monitoring and intrusion detection). yes = the installer sets it
# up at first boot on every host; no (default) = the same as 0.2.0. Important alerts go to ALERT_HOOK.
SECURITY_ADDONS=no
# Optional: the Wazuh alert level sent to ALERT_HOOK right away (3-15, default 10). Lower levels go into a daily summary.
SECURITY_ALERT_LEVEL=10
```

- [ ] **Step 4: Run the full suite.** Expected: all pass. Any kit or template test that pins the template's keys must be updated, with a ledger ruling.

- [ ] **Step 5: Commit**: `git commit -m "Site keys SECURITY_ADDONS and SECURITY_ALERT_LEVEL (additive; default off)"`.

---

### Task 2: `security enable --firstboot` (no stick: pending folder on the server, staged key file on clients)

**Files:**
- Modify: `appliance/chp-site/chp_site/security.py`, `appliance/chp-site/chp_site/cli.py`
- Test: `tests/test_chp_site_security.py`

**Interfaces:**
- Consumes: Task 1 (`site["SECURITY_ALERT_LEVEL"]`).
- Produces: `enable(role, host, site, hosts, *, stick=None, pending=None, key_file=None, run, root, …)`:
  - server with `stick=None` → keys go to `<pending>/wazuh/<host>.key` (folder 0700, files 0600);
  - client with `stick=None` → its key line is read from `key_file`, which is shredded after `client.keys` is written;
  - a new `security.conf` takes `ALERT_LEVEL` from `site["SECURITY_ALERT_LEVEL"]`, unless an existing one sets it.
- CLI: `chp-site security enable --firstboot`. The server uses pending `/root/chp-escrow-pending`; the client uses key file `/var/lib/chp/wazuh/agent.key`. Neither touches USB.

- [ ] **Step 1: Write the failing tests** (append; reuse `Run`, `Api`, `root`, `hosts` from the module)

```python
def test_firstboot_server_writes_keys_to_pending_not_a_stick(tmp_path):
    r = root(tmp_path, "server"); pend = tmp_path / "pending"
    sec.enable("server", "srv1", {"ALERT_HOOK": "", "SECURITY_ALERT_LEVEL": 12}, hosts(), stick=None, pending=pend,
               run=Run(), root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None,
               api=Api(), sleep=lambda x: None)
    k = (pend / "wazuh" / "ws1.key")
    assert k.read_text().split()[:3] == ["001", "ws1", "192.0.2.21"]
    assert oct(k.stat().st_mode & 0o777) == "0o600" and oct((pend / "wazuh").stat().st_mode & 0o777) == "0o700"
    assert "ALERT_LEVEL=12" in (r / "etc/chp/security.conf").read_text()


def test_firstboot_client_reads_and_shreds_its_staged_key(tmp_path):
    r = root(tmp_path, "client"); kf = tmp_path / "agent.key"
    kf.write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    sec.enable("client", "ws1", {"ALERT_HOOK": ""}, hosts(), stick=None, key_file=kf, run=Run(), root=r,
               data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None)
    assert (r / "var/ossec/etc/client.keys").read_text().startswith("001 ws1 192.0.2.21 ")
    assert not kf.exists()


def test_firstboot_client_without_a_staged_key_is_refused(tmp_path):
    r = root(tmp_path, "client")
    with pytest.raises(SiteError, match="no staged Wazuh key"):
        sec.enable("client", "ws1", {"ALERT_HOOK": ""}, hosts(), stick=None, key_file=tmp_path / "none.key",
                   run=Run(), root=r, data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None)


def test_staged_key_must_be_this_hosts(tmp_path):
    r = root(tmp_path, "client"); kf = tmp_path / "agent.key"
    kf.write_text("002 ws2 192.0.2.22 " + "ab" * 32 + "\n")
    with pytest.raises(SiteError, match="not ws1's"):
        sec.enable("client", "ws1", {"ALERT_HOOK": ""}, hosts(), stick=None, key_file=kf, run=Run(), root=r,
                   data_is_mount=False, chown=lambda *a: None, record=lambda *a, **k: None)
    assert kf.exists()                                  # refused before anything changed
```

- [ ] **Step 2: Run them to verify they fail.** Expected: FAIL (`unexpected keyword 'pending'`, or similar).

- [ ] **Step 3: Implement** in `security.py`:
  - `enable`/`_enable` gain `pending=None, key_file=None`, and `stick` defaults to `None`.
  - **Client, before any change:** the key line comes from `Path(stick)/"wazuh"/f"{host}.key"` when `stick` is set, else from `key_file`. If it is missing, raise `SiteError("no staged Wazuh key for {host} (…/agent.key): reinstall with the site stick, after export-client")`. Validate the line with `re.fullmatch(rf"\d{{3}} {re.escape(host)} \S+ [0-9a-f]{{64}}", line.strip())`; otherwise raise `SiteError(f"the staged Wazuh key is not {host}'s")`.
  - **Client:** after `client.keys` is written, if `key_file` was used, shred it (`run(["shred", "-u", str(key_file)])`, falling back to `os.unlink` if `shred` is missing; tests run `Run`, so also `unlink` when the file still exists).
  - **Server:** the mirror loop writes to `Path(stick)/"wazuh"` when `stick` is set, else to `Path(pending)/"wazuh"`, created with `mkdir(mode=0o700)` and each file via `os.open(..., 0o600)`.
  - **`_conf`:** a new file takes `ALERT_LEVEL` from `site.get("SECURITY_ALERT_LEVEL", 10)`.

In `cli.py` `_security`, add a `--firstboot` flag. With it, call `enable(..., stick=None, pending=Path("/root/chp-escrow-pending"), key_file=Path("/var/lib/chp/wazuh/agent.key"), run=subprocess.run)` without `site_stick`; print the steps; and on the server print "agent keys staged for export-client". Without the flag, the behaviour is unchanged. Register `se.add_argument("--firstboot", action="store_true", help="first boot: no site stick (keys via the pending folder / the staged key)")`.

- [ ] **Step 4: Run the full suite.** Expected: all pass, including every W1 security test, unchanged.

- [ ] **Step 5: Commit**: `git commit -m "security enable --firstboot: server keys to the pending folder, client key from the staged file (no USB)"`.

---

### Task 3: Keys over the stick: `export-client` moves them, `pre` stages them, the kickstart installs them and copies the repo

**Files:**
- Modify:
  - `appliance/chp-site/chp_site/escrow.py` (`move_wazuh_keys`), `cli.py` (`_export_to`), `appliance/chp-site/chp_site/pre.py` (`run_pre`);
  - `appliance/kickstart/client.ks`, `appliance/kickstart/server.ks`, `appliance/kickstart/chp.ks.in`, the same `%post --nochroot` addition in each. Check `render-ks.sh` for which files are generated and which are edited; edit the source the build uses, and record a ruling if the generated ones are committed copies.
- Test: `tests/test_chp_site_escrow.py` (or the module testing `move_tokens`), `tests/test_chp_site_pre.py` (or the `run_pre` tests), `tests/test_iso_build_static.py` (kickstart content)

**Interfaces:**
- Consumes: Task 2's pending layout (`<pending>/wazuh/<host>.key`).
- Produces:
  - `escrow.move_wazuh_keys(pending_wazuh, stick, now) -> list[str]` (the same write, fsync, read-back and shred guarantee as `move_tokens`);
  - `run_pre` writes `out/wazuh.key` (0600) for a client when `site["SECURITY_ADDONS"] == "yes"`, and `out/security-addons` (the text `yes` or `no`) for every role. **Owner 2026-10-29: the ISO may be on a different device from the stick**, so `run_pre` also writes `out/repo-dir`, the local path of the repo it was given (`repo_url` without `file://`, the same repo the install itself uses). The stick never carries the repo. A `repo_url` that is not `file://` (a network install) writes nothing, and first boot then refuses clearly (Task 4);
  - kickstart `%post --nochroot`:
    - if `/tmp/chp/security-addons` says `yes` and `/tmp/chp/repo-dir` names a directory, `rsync -a "$(cat /tmp/chp/repo-dir)/" /mnt/sysimage/var/lib/chp/repo/` (the ISO's own repo, wherever the ISO is mounted);
    - if `/tmp/chp/wazuh.key` exists, install it 0600 as `/mnt/sysimage/var/lib/chp/wazuh/agent.key`, then shred the original.

- [ ] **Step 1: Write the failing tests**

Escrow (next to the `move_tokens` tests):

```python
def test_move_wazuh_keys_reads_back_then_shreds(tmp_path):
    pend = tmp_path / "p" / "wazuh"; pend.mkdir(parents=True)
    (pend / "ws1.key").write_text("001 ws1 192.0.2.21 " + "ab" * 32 + "\n")
    stick = tmp_path / "stick"; stick.mkdir()
    moved = escrow.move_wazuh_keys(pend, stick, "20261029T000000Z")
    assert moved == ["ws1.key"] and (stick / "wazuh" / "ws1.key").read_text().startswith("001 ws1 ")
    assert not (pend / "ws1.key").exists()


def test_move_wazuh_keys_nothing_pending(tmp_path):
    assert escrow.move_wazuh_keys(tmp_path / "none", tmp_path, "x") == []
```

`pre` (next to the existing token tests; reuse their stick and facts builders):

```python
def test_pre_stages_this_clients_wazuh_key_when_the_add_on_is_on(tmp_path):
    stick, out = make_client_stick(tmp_path, extra_site="SECURITY_ADDONS=yes\n")   # the module's existing builder
    (stick / "wazuh").mkdir(); (stick / "wazuh" / f"{CLIENT}.key").write_text(f"001 {CLIENT} 192.0.2.21 " + "ab" * 32 + "\n")
    run_pre("client", stick, out, "file:///run/install/repo/chp", FACTS)
    assert oct((out / "wazuh.key").stat().st_mode & 0o777) == "0o600"
    assert (out / "security-addons").read_text().strip() == "yes"
    assert (out / "repo-dir").read_text().strip() == "/run/install/repo/chp"      # the ISO's repo, not the stick


def test_pre_network_repo_writes_no_repo_dir(tmp_path):
    stick, out = make_client_stick(tmp_path, extra_site="SECURITY_ADDONS=yes\n")
    (stick / "wazuh").mkdir(); (stick / "wazuh" / f"{CLIENT}.key").write_text(f"001 {CLIENT} 192.0.2.21 " + "ab" * 32 + "\n")
    run_pre("client", stick, out, "http://192.0.2.1/chp", FACTS)
    assert not (out / "repo-dir").exists()


def test_pre_refuses_a_client_without_its_wazuh_key_before_any_disk(tmp_path):
    stick, out = make_client_stick(tmp_path, extra_site="SECURITY_ADDONS=yes\n")
    with pytest.raises(SiteError, match="no Wazuh agent key for .* run .*export-client"):
        run_pre("client", stick, out, "file:///run/install/repo/chp", FACTS)
    assert not (stick / "escrow").exists() or not list((stick / "escrow").iterdir())   # nothing written yet


def test_pre_add_on_off_stages_nothing(tmp_path):
    stick, out = make_client_stick(tmp_path)
    run_pre("client", stick, out, "file:///run/install/repo/chp", FACTS)
    assert not (out / "wazuh.key").exists() and (out / "security-addons").read_text().strip() == "no"
```

Before running, read the existing `run_pre` tests and use their real builder names and facts (`CLIENT`, `FACTS` and `make_client_stick` stand for them). Adapting names is not a deviation; adding a builder parameter `extra_site` is, so record it in the ledger.

Kickstart static (in `tests/test_iso_build_static.py`):

```python
def test_kickstart_copies_the_repo_and_installs_the_agent_key_only_when_needed():
    for ks in ("server.ks", "client.ks"):
        t = (KS / ks).read_text()                        # KS: the module's kickstart dir constant
        assert "grep -qx yes /tmp/chp/security-addons" in t and 'rsync -a "$(cat /tmp/chp/repo-dir)/" /mnt/sysimage/var/lib/chp/repo/' in t
    c = (KS / "client.ks").read_text()
    assert "install -D -m 0600 /tmp/chp/wazuh.key /mnt/sysimage/var/lib/chp/wazuh/agent.key" in c
    assert "shred -u /tmp/chp/wazuh.key" in c
```

- [ ] **Step 2: Run them to verify they fail.**

- [ ] **Step 3: Implement.**
  - **`escrow.py`:** factor `move_tokens`'s body into `_move_files(pending_dir, stick, sub, suffix, now, what)`. Have `move_tokens` call it with `("tokens", ".token", "client tokens")` and the new `move_wazuh_keys` with `("wazuh", ".key", "Wazuh agent keys")`. The existing `move_tokens` tests must stay green.
  - **`cli._export_to`:** after the tokens, add:

```python
    wk = move_wazuh_keys(pending / "wazuh", stick, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())) \
        if (pending / "wazuh").is_dir() else []
    print("Wazuh agent keys moved to the stick: " + ", ".join(wk) if wk else "no Wazuh agent keys pending")
```

  - **`pre.run_pre`:** in the client branch, after the token check (still before any secret is written), when `site["SECURITY_ADDONS"] == "yes"`:
    - read `stick/"wazuh"/f"{host.hostname}.key"`. If it is missing, raise `SiteError(f"no Wazuh agent key for {host.hostname} on the site stick: on the server run `chp-site export-client` (the add-on is on)")`;
    - validate it with the same regex as Task 2.

    After the token write, write `out/wazuh.key` (0600) when one was read. For every role, write `out/security-addons` with `site["SECURITY_ADDONS"]`.
  - **Kickstarts (`%post --nochroot`):** after the unixd-token line, add:

```bash
# Security add-on (0.3.0, spec §3): the signed ISO repo stays on the host so first boot can install Wazuh; the agent's
# key (staged by chp-site pre, 0600) becomes /var/lib/chp/wazuh/agent.key and is shredded here.
if grep -qx yes /tmp/chp/security-addons 2>/dev/null && [ -d "$(cat /tmp/chp/repo-dir 2>/dev/null)" ]; then
  install -d -m 0755 /mnt/sysimage/var/lib/chp/repo && rsync -a "$(cat /tmp/chp/repo-dir)/" /mnt/sysimage/var/lib/chp/repo/
fi
if [ -f /tmp/chp/wazuh.key ]; then install -D -m 0600 /tmp/chp/wazuh.key /mnt/sysimage/var/lib/chp/wazuh/agent.key; shred -u /tmp/chp/wazuh.key; fi
```

  `rsync` must be in the installer environment. Check with `grep -n rsync` in the kickstart's `%packages` (it is listed for the target). The installer runtime has `rsync`; if the lab proves otherwise, use `cp -a` and record a ruling.

- [ ] **Step 4: Run the full suite.** Expected: all pass.

- [ ] **Step 5: Commit**: `git commit -m "Wazuh agent keys over the site stick like the client tokens; the ISO repo stays on the host when the add-on is on"`.

---

### Task 4: First boot runs `security enable --firstboot` (server and clients), plus the package bumps

**Files:**
- Modify:
  - `appliance/rpm/chp-identity-server/server-firstboot.sh` (+ its spec, version bump);
  - `appliance/rpm/chp-identity-client/client-enrol.sh` (+ its spec, version bump);
  - `appliance/chp-site/chp-site.spec` and `chp_site/__init__.py` (0.9.0);
  - `appliance/rpm/chp-base/monitor.d/*` (if the pending-escrow monitor check lists the pending subfolders by name, add `wazuh`).
- Test: `tests/test_server_role_static.py`, `tests/test_client_role_static.py`, version pins

**Interfaces:**
- Consumes: Task 2's CLI flag, and Task 1's `chp-site get SECURITY_ADDONS`.
- Produces:
  - the server's first boot has the step `security` (after `self-client`): `[ "$(chp-site get SECURITY_ADDONS)" = yes ] || return 0; chp-site security enable --firstboot`;
  - before installing anything, `security enable --firstboot` checks that `/var/lib/chp/repo/repodata/repomd.xml` exists. If it does not, it raises `SiteError("the security add-on is on but this host has no local package repo (the ISO's repo is copied at install; a network install does not copy it): unpack a signed repo tarball into /var/lib/chp/repo, then run chp-site security enable")` (test `test_firstboot_without_a_local_repo_is_refused`, added in Task 2's style);
  - the client enrolment ends with the same call (after enrolment, before its done marker).

- [ ] **Step 1: Write the failing tests**

```python
def test_server_firstboot_runs_the_security_step_only_when_on():
    t = (SRV / "server-firstboot.sh").read_text()              # SRV: the module's server-role dir constant
    assert "step security do_security" in t and t.index("step self-client") < t.index("step security")
    assert '[ "$(chp-site get SECURITY_ADDONS)" = yes ] || return 0' in t and "chp-site security enable --firstboot" in t


def test_client_enrol_runs_the_security_step_only_when_on():
    t = (CLI / "client-enrol.sh").read_text()
    assert "chp-site security enable --firstboot" in t and "SECURITY_ADDONS" in t
```

Also check the pending-escrow monitor. Run `grep -rn "chp-escrow-pending" appliance/rpm/chp-base/monitor.d appliance/rpm/*/monitor.d`. If its alert names only `tokens`, add a test that a pending `wazuh/` folder also triggers the "run export-client" reminder.

- [ ] **Step 2: Run them to verify they fail.**

- [ ] **Step 3: Implement.** Add the `do_security` function and the `step security do_security` line to `server-firstboot.sh`, after `step self-client do_self_client`. In `client-enrol.sh`, read how it ends (it is shared by `--role client`). Before its final done-marker line, add:

```bash
# Security add-on (0.3.0): Wazuh agent with the key staged by the installer (no site stick at first boot).
if [ "$(chp-site get SECURITY_ADDONS 2>/dev/null)" = yes ]; then chp-site security enable --firstboot; fi
```

Bump the versions:
- `chp-identity-server` +0.0.1;
- `chp-identity-client` +0.0.1;
- `chp-site` 0.9.0.

Each gets a changelog line. Update the version pins in the tests.

- [ ] **Step 4: Run the full suite.** Expected: all pass.

- [ ] **Step 5: Commit**: `git commit -m "First boot: security enable --firstboot on the server and clients when SECURITY_ADDONS=yes; chp-site 0.9.0"`.

---

### Task 5: Repo 0.7.9 and ISO 0.3.0, then the lab proofs (off, then on)

**Files:**
- Modify: `lab/iso5/site.conf.in` (a `SECURITY_ADDONS` line, chosen per run), `lab/iso5/prove.sh` (new stages `wazuh-off` and `wazuh-on`)
- Create: `lab/security/PROOF-RECORD-W2.md`

**Lab note for the owner (decision point, stop and ask before Step 3):** the fresh installs **replace the iso5 VMs and their golden snapshots**, which are rebuilt from ISO 0.3.0. W1's update path stays proven by its record.

- [ ] **Step 1: Build and sign.**
  - Build `chp-site` 0.9.0, `chp-identity-server` and `chp-identity-client`, then assemble repo 0.7.9 (the W1 recipe).
  - Sign it (owner "go").
  - Build the ISO on aero: `sudo bash build-iso.sh 0.7.9 0.3.0-rc1`, after updating `/data/chp-release/iso-src` with the changed kickstarts (follow `release-iso.sh` / `RELEASE-RECORD-ISO-0.2.0.md`).
- [ ] **Step 2: Off-install proof** (`SECURITY_ADDONS=no`; server only):
  - prove.sh stages `prep`, `server` and `firstboot`;
  - evidence: `rpm -q wazuh-manager chp-security` reports not installed, `/var/lib/chp/repo` is empty, there is no `security.done` marker, and `rpm -qa` matches the 0.2.0 server list, save the newer versions of the CHP packages (show the diff).
- [ ] **Step 3: On-install proof** (`SECURITY_ADDONS=yes`; the full lab):
  - prove.sh stages `prep`, `server`, `firstboot`, `export`, `client1` and `client2`;
  - evidence:
    - the `export` output says "Wazuh agent keys moved to the stick: iso5-cli1.key, iso5-cli2.key";
    - on each client, `/var/lib/chp/wazuh/agent.key` is gone after first boot;
    - `agent_control -l` shows **both** clients Active;
    - the W1 checks pass on every host: the ports, default API logins refused (401), `update_check no`, 0 "No such tag" warnings, the agent upgrade module off, the bind mount, and 0 Wazuh SELinux or fapolicyd denials;
    - the AIDE first baseline includes the Wazuh files, so the next daily check reports **no** Wazuh changes;
    - `journalctl -u usbguard` shows `allow-device` only during `export-client`;
    - the pending folder is empty after `export`.
- [ ] **Step 4: Proof 5 (CUI scan):** the prove.sh `scan` stage, then the deviation table against 0.2.0 (`lab/iso5/deviations.py`). No new failing rules; the FIPS POA&M item is listed.
- [ ] **Step 5: Proof 6 (resources):** the manager's RSS and the data folder size after 24 hours; and the catch smoke test (one brute-force burst reaches the hook, using the lab hook set as in W1).
- [ ] **Step 6:** prove.sh stages `adapter`, `nvram`, `snapspike` and `golden`, which give the new 0.3.0 golden snapshots. Commit the proof record.

---

### Task 6: Release ISO 0.3.0, kit, notes, final review, PR

- [ ] Release notes `appliance/release/RELEASE-RECORD-ISO-0.3.0.md` and the kit README section (the `SECURITY_ADDONS` setting, and the order: install the server, `export-client`, then the clients).
- [ ] The final whole-branch review (a fresh reviewer, the most capable model, with this plan's Review Focus), then one fix pass.
- [ ] Release the ISO and the kit (owner "go" for each signature), and add the share README rows.
- [ ] The pre-publication scan, then push and open the PR (the owner merges). Copy the release notes to the Desktop as "ISO 0.3.0 - REVIEW.md".

## Out of scope

- YARA (part 2), Suricata, metrics, the indexer and dashboard.
- Adding a client after install (row 48).
- The disk-layout decision (row 50).
