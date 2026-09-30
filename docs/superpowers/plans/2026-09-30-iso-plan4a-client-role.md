# ISO Plan 4a: The Client Role (core) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A host installed with `client.ks` comes up after one unattended first boot as a working identity client:
- it trusts **only** the site's pinned CA root
- `kanidm-unixd` serves the site's users, using a **per-client** read-only token
- Kanidm users log in over SSH with an **SSH certificate + their Kanidm POSIX password**
- the collector (`diag`) and the revoke fan-out (`chpcache`) can reach it only through pinned, forced-command keys
- the monitors watch for drift

The identity server **becomes its own client** in the same way, and Kanidm admins (`chp_admins`) get `sudo` with their Kanidm password. Proven by installing a server and **two clients** on aero, including a revoke that ends access on both clients at once.

**Architecture:**
- **A new RPM `chp-identity-client`** has two parts:
  - an idempotent enrolment script (`client-enrol`) that does trust, unixd, nsswitch/authselect, the sshd drop-ins and the forced-command accounts
  - the SELinux module `chp_kanidm` (built from the lab's `kanidm_lab.te`), a first-boot unit, and three client monitors

  Both roles install it:
  - **Clients** run it from their first-boot unit, with the values from `client.conf`.
  - **The server** runs it as the last step of its own first boot (`--role server`), with its local CA files.
- **`chp-site` 0.4.0** covers the token lifecycle:
  - the server's first boot mints **one token per client** into `/root/chp-escrow-pending/tokens/`
  - `export-client` moves the tokens to the stick with the same write → fsync → read-back → shred guarantee as the escrow
  - `pre` gives a client only **its own** token
  - `client-token HOST` covers hosts added later
- **Kickstart:** client → `chp-base chp-identity-client` + `chp-client-firstboot.service`; server → adds `chp-identity-client`.

**Tech Stack:** bash, Python 3.9 stdlib, Kanidm 1.11.2 (`kanidm-unixd`, `kanidm` CLI), authselect, OpenSSH 9.9 (Rocky 9.8), step-cli 0.31.0, SELinux (checkmodule/semodule_package on aero), systemd, RPM, the lab harness (`lab/iso3` → `lab/iso4`).

**Spec:** `docs/superpowers/specs/2026-09-29-chp-appliance-iso-design.md`:
- §7 (client role), §5.3 (login), §5.4 (monitoring), §2 (#12, #22, #28)

Requirements log `lab/iso-requirements.md`:
- rows **5, 6, 7, 8, 9, 10, 12, 21, 22, 25, 27, 29, 31, 35, 39**

Lab mechanics reproduced:
- `lab/client/10-enrol.sh`, `lab/client/authselect_patch.py`, `lab/client/10-kanidm.conf`
- `lab/selinux/kanidm_lab.te`, `lab/host/diag-access.sh`
- `lab/srv1/40-groups-svcacct.sh` (per-client unixd service account + read-only token)

## Decisions for this plan (user / ISSO, 2026-09-30)

1. **Plan 4 is split.**
   - **4a (this plan)** is the client core. Until 4b, clients log in with **SSH certificate + Kanidm POSIX password** (`AuthenticationMethods publickey,keyboard-interactive:pam`; the keyboard-interactive step is `pam_kanidm`).
   - **4b** adds Google Authenticator (host-local tokens in `/var/lib/google-authenticator`, `chp_ga`, GDM row 36, the per-host enrolment workflow).
2. **Per-client unixd token.**
   - Each client host gets its own Kanidm service account `unixd-<hostname>`, in `idm_unix_authentication_read` (the lab's least privilege), with one **read-only** API token.
   - The tokens travel on the site stick as `tokens/<hostname>.token`; a client's install copies only its own.
   - A lost client is cut off by deleting its service account (`kanidm service-account delete unixd-<host>`) without touching other clients.
3. **Collector `--user`, validated.**
   - The `diag` key's forced command is `/usr/libexec/chp/diag-collect`, a root-owned wrapper.
   - It accepts, from `SSH_ORIGINAL_COMMAND`, only the engine's form `[sudo -n] [/usr/sbin/]idm-collect [--user NAME]` (NAME = `[a-z][a-z0-9_]{0,31}`), or nothing.
   - It then runs the fixed `sudo -n /usr/sbin/idm-collect [--user NAME]`. Sudoers allows exactly those two command forms.
4. **`chpadmin` stays key-only** (Plan 2's break-glass), through a `Match User` exception shared with `diag` and `chpcache` (both forced-command keys). It is recorded as a deliberate break-glass deviation for the SSP.

**My design choices (recorded; the spec leaves the mechanism open):**
- **Login groups.** The server's first boot creates two POSIX groups:
  - `chp_users`: clients allow logins from it (`pam_allowed_login_groups`)
  - `chp_admins`: the **server** allows only this group, and **both roles** give it `sudo` (`%chp_admins ALL=(ALL) ALL`, authenticated by the Kanidm POSIX password through `pam_kanidm`)

  `chp-site onboard` now **always** adds `chp_users` (admins also pass `--group chp_admins`). Onboarded admins then need neither `chpadmin` nor the escrowed root password for daily work.
- **Getting the CA root on a client.** `step-cli ca root --fingerprint <CA_ROOT_SHA256>` fetches the root from step-ca (step-cli verifies the pin), and `client-enrol` re-checks the SHA-256 itself. A mismatch stops enrolment. It never trusts what is on the wire. `client.conf` keeps its format.
- **The sshd drop-ins are installed by `client-enrol`, not by the RPM,** and only after the CA key is in place. They are validated with `sshd -t` and removed again if sshd rejects them (row 35). The `Match` exceptions live in the **last** drop-in (`99-chp-exceptions.conf`); Task 5 proves on aero, with OpenSSH 9.9, that a `Match` in an included file does not swallow the main `sshd_config` lines that follow the `Include`.
- **Kanidm SSH keys (`AuthorizedKeysCommand`) are not used.** Users log in with CA certificates (row 34); the local `authorized_keys` still serves `chpadmin`, `diag` and `chpcache`.
- **The authselect patcher** gets an appliance copy (`appliance/rpm/chp-identity-client/authselect_patch.py`). The lab copy stays for the lab harness, and a test keeps the two byte-identical.
- **Row 39 correction:** the forced command is `sudo -n /usr/sbin/kanidm-unix cache-invalidate` (the RPM installs `kanidm-unix` in `%{_sbindir}`). Plan 3b's text said `/usr/bin`.

## Global Constraints

- **All earlier constraints hold:**
  - secrets never go to a log, the console, argv, `/etc/chp` or the repo (tokens included)
  - validate before writing
  - Python 3.9 stdlib only in `chp-site`
  - the branding header (`appliance/branding/file-header.txt`) on every shipped script and module
  - `Vendor`, `.chp`, Apache-2.0 and noarch on our RPMs (except where arch-specific)
  - signing only through `sign-session.sh`, with the user's accessibility protocol (announce in one line, **wait for "ready"**, `say` prompts, never ask for typing while a dialog may be open)
- **Nothing site-specific in any RPM.** Every value comes from `/etc/chp` through `chp-site get` / `render`.
- **First boot is idempotent:** each step has a `.done` marker under `/var/lib/chp/firstboot/`, and a failed step resumes on the next boot or `systemctl restart`.
- **Names:** users and groups `[a-z][a-z0-9_]{0,31}`; hostnames as in `hosts` (`[a-z0-9-]`); service accounts `unixd-<hostname>`.
- **Kanidm CLI facts** (Plan 3b captures):
  - `get` of a missing entry prints `No matching entries` and exits 0
  - a missing session gives exit 101 and `No valid authentication tokens found for NAME.`
  - `api-token generate` prints a JWS matching `[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`
- **Paths:**
  - `kanidm-unix` = `/usr/sbin/kanidm-unix`; `idm-collect` = `/usr/sbin/idm-collect`
  - CA anchor = `/etc/pki/ca-trust/source/anchors/chp-root.crt` (`sitevars.ANCHOR`)
  - SSH user CA on clients = `/etc/ssh/chp_user_ca.pub`
  - unixd token = `/etc/kanidm/token` (0600 root)
- **authselect:** profile `custom/kanidm` built from the host's current (CUI) profile, with **every** feature carried over (expected `with-faillock`, `without-nullok`). It is refused if any feature is lost.

## Review Focus

1. **The pinned root does not match what step-ca serves** (wrong stick, rebuilt server, attacker on the wire). Expected: enrolment stops at `trust`; no anchor, unixd, authselect or sshd change is made; the journal names both fingerprints; the step resumes after the fix.
2. **The collector sends anything but the two allowed forms** (`bash`, `idm-collect --user 'x;id'`, extra arguments, `--user` with no name, a different path). Expected: refused with exit 1 and a one-line message; `sudo` is never run.
3. **A client's token is missing from the stick** (a client added after export, or the wrong stick). Expected: `%pre` stops **before any disk is touched**, naming `chp-site client-token <host>` + `export-client`.
4. **sshd rejects the new drop-ins, or a `Match` block leaks into later configuration.** Expected: the drop-ins are removed again before any reload, so the running sshd and its next restart keep working; the `Match` placement is proven not to leak (Task 5).
5. **Re-running enrolment on an enrolled host** (a failed first boot resumed, or an admin re-run). Expected:
   - authselect is rebuilt from the recorded **original** profile (never from `custom/kanidm` itself)
   - no feature is lost
   - authorized_keys and sudoers are replaced, not appended
   - the unixd token is untouched

---

## File structure

| File | Responsibility |
|---|---|
| `appliance/chp-site/chp_site/sitefile.py` | optional `COLLECTOR_SSH_PUBKEY` (needs `COLLECTOR_IP`) |
| `appliance/chp-site/chp_site/sitevars.py` | `CLIENT_HOSTS`, `COLLECTOR_IP`, `COLLECTOR_SSH_PUBKEY`, and the `client.conf` values when present |
| `appliance/chp-site/chp_site/pre.py` | client: require + stage `tokens/<host>.token` |
| `appliance/chp-site/chp_site/escrow.py` | `move_tokens(pending_tokens, stick)` |
| `appliance/chp-site/chp_site/kanidm.py` | `service_account_exists/create`, `api_token` |
| `appliance/chp-site/chp_site/ops.py` | onboard always adds `chp_users`; `client_token` |
| `appliance/chp-site/chp_site/cli.py` | `get` with `client.conf`; export moves tokens; `client-token` |
| `appliance/kickstart/chp.ks.in`, `render-ks.sh` | role packages/units; install the staged token |
| `appliance/rpm/chp-identity-server/server-firstboot.sh` | `login` helper; steps `unixd-tokens`, `self-client` |
| `appliance/rpm/chp-identity-client/*` (new) | enrolment, patcher, diag wrapper, sshd/sudoers templates, SELinux, monitors, unit, spec |
| `lab/iso4/*` (new) | the 3-host proof |

---

### Task 1: Site values, the per-client token on the stick, and `pre`

**Files:**
- Modify: `appliance/chp-site/chp_site/sitefile.py`, `sitevars.py`, `pre.py`, `cli.py` (`_get`)
- Test: `tests/test_chp_site_sitefile.py`, `tests/test_chp_site_get_render.py`, `tests/test_chp_site_pre.py`

**Interfaces:**
- Produces:
  - site dict key `COLLECTOR_SSH_PUBKEY` (`"type base64"` or `""`)
  - `sitevars.values(site, hosts, client=None)`, which adds:
    - `CLIENT_HOSTS` (space-separated client hostnames in table order), `COLLECTOR_IP`, `COLLECTOR_SSH_PUBKEY`
    - with `client` (the `parse_client_conf` dict): `CA_ROOT_SHA256`, `SSH_CA_PUBKEY`, `SSH_CA_FPR`, `CACHE_PUBKEY`, `KANIDM_URL`
  - `pre.TOKEN_RE`
  - `run_pre` for a client writes `out/unixd.token` (0600)

- [ ] **Step 1: Failing tests.** Add to `tests/test_chp_site_sitefile.py`, using its `GOOD` text and the fixture key `tests/fixtures/chp-site/cache_key.pub` as a stand-in collector key:

```python
from pathlib import Path

COLL = (Path(__file__).parent / "fixtures" / "chp-site" / "cache_key.pub").read_text().strip()


def test_collector_key_optional_and_validated():
    assert parse_site(GOOD)["COLLECTOR_SSH_PUBKEY"] == ""
    s = parse_site(GOOD + f"COLLECTOR_SSH_PUBKEY={COLL}\n")
    assert s["COLLECTOR_SSH_PUBKEY"] == " ".join(COLL.split()[:2])


def test_collector_key_ed25519_refused_with_its_own_name():
    with pytest.raises(SiteError, match="COLLECTOR_SSH_PUBKEY.*FIPS"):
        parse_site(GOOD + "COLLECTOR_SSH_PUBKEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyH x\n")


def test_collector_key_needs_collector_ip():
    text = "\n".join(l for l in GOOD.splitlines() if not l.startswith("COLLECTOR_IP=")) + "\n"
    with pytest.raises(SiteError, match="COLLECTOR_SSH_PUBKEY needs COLLECTOR_IP"):
        parse_site(text + f"COLLECTOR_SSH_PUBKEY={COLL}\n")
```

   (If `GOOD` has no `COLLECTOR_IP` line, the last test's filter is a no-op, and the test still holds. If `GOOD` *does* set it inside the subnet, keep the filter.)

   Add to `tests/test_chp_site_get_render.py` (use the module's existing `SITE`/`HOSTS` names; the table has one server and at least one client):

```python
def test_values_client_hosts_and_collector():
    from chp_site.hosts import parse_hosts
    from chp_site.sitevars import values
    from tests.test_chp_site_hosts import HOSTS
    from tests.test_chp_site_sitefile import GOOD
    from chp_site.sitefile import parse_site
    site = parse_site(GOOD); hosts = parse_hosts(HOSTS, site)
    v = values(site, hosts)
    assert v["CLIENT_HOSTS"] == " ".join(h.hostname for h in hosts if h.role == "client")
    assert v["COLLECTOR_SSH_PUBKEY"] == "" and "CA_ROOT_SHA256" not in v


def test_values_with_client_conf():
    from chp_site.clientconf import make_client_conf, parse_client_conf
    from chp_site.hosts import parse_hosts
    from chp_site.sitevars import values
    from tests.test_chp_site_clientconf import CACHE, PEM, PUB
    from tests.test_chp_site_hosts import HOSTS
    from tests.test_chp_site_sitefile import GOOD
    from chp_site.sitefile import parse_site
    site = parse_site(GOOD); hosts = parse_hosts(HOSTS, site)
    c = parse_client_conf(make_client_conf(site["DOMAIN"], PEM, PUB, CACHE), site)
    v = values(site, hosts, c)
    assert v["CA_ROOT_SHA256"] == c["CA_ROOT_SHA256"] and v["CACHE_PUBKEY"] == c["CACHE_PUBKEY"]
    assert v["KANIDM_URL"] == f"https://idm.{site['DOMAIN']}"
```

   Add to `tests/test_chp_site_pre.py` (`stick()`, `facts()` and a client MAC exist there; `CLIENT_MAC` is the client line of `HOSTS`; use the MAC the existing client tests use):

```python
TOKEN = "eyJhbGciOiJFUzI1NiJ9AAAAAAAAAAAA.eyJzdWIiOiJ1bml4ZC1jbGkifQAAAAAAA.c2lnbmF0dXJlc2lnbmF0dXJlc2ln"


def test_client_needs_its_own_token_before_any_disk(tmp_path):
    s = stick(tmp_path)
    with pytest.raises(SiteError, match=r"no unixd token for iso2-cli.*chp-site client-token iso2-cli"):
        run_pre("client", s, tmp_path / "out", "file:///r", facts(CLIENT_MAC))
    assert not (s / "escrow").exists()          # refused before the escrow (and so before any disk)


def test_client_token_staged_0600(tmp_path):
    s = stick(tmp_path); (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text(TOKEN + "\n")
    run_pre("client", s, tmp_path / "out", "file:///r", facts(CLIENT_MAC))
    t = tmp_path / "out" / "unixd.token"
    assert t.read_text() == TOKEN and oct(t.stat().st_mode & 0o777) == "0o600"


def test_client_token_garbage_refused(tmp_path):
    s = stick(tmp_path); (s / "tokens").mkdir(); (s / "tokens" / "iso2-cli.token").write_text("not a token\n")
    with pytest.raises(SiteError, match="is not a Kanidm API token"):
        run_pre("client", s, tmp_path / "out", "file:///r", facts(CLIENT_MAC))
```

   (Adapt the `facts(...)` call and the hostname to how the file's existing client tests build facts; the hostname `iso2-cli` is the client in `HOSTS`. Existing client `pre` tests must now write a token on the stick first. Update them with a small helper `with_token(s)`.)

- [ ] **Step 2: Run to verify failure.** `.venv/bin/python -m pytest tests/test_chp_site_sitefile.py tests/test_chp_site_get_render.py tests/test_chp_site_pre.py -q`. Expected: the new tests FAIL (`KeyError: 'COLLECTOR_SSH_PUBKEY'`, `KeyError: 'CLIENT_HOSTS'`, no token error raised).

- [ ] **Step 3: Implement.**
  - **`sitefile.py`:** add `"COLLECTOR_SSH_PUBKEY"` to `known`. After `ADMIN_SSH_PUBKEY`:

```python
    ck = raw.get("COLLECTOR_SSH_PUBKEY", "")
    if ck:
        if not s["COLLECTOR_IP"]:
            raise SiteError("COLLECTOR_SSH_PUBKEY needs COLLECTOR_IP (the diag key is pinned to the collector's address)")
        try:
            ck = ssh_pubkey(ck)
        except SiteError as e:
            raise SiteError(str(e).replace("ADMIN_SSH_PUBKEY", "COLLECTOR_SSH_PUBKEY")) from None
    s["COLLECTOR_SSH_PUBKEY"] = ck
```

    `_plain` already rejects shell characters. A public key contains `+` and `/` only, which pass.
  - **`sitevars.py`:**

```python
def values(site, hosts, client=None):
    srv = server_of(hosts)
    d = site["DOMAIN"]
    v = {"DOMAIN": d, "SUBNET": str(site["SUBNET"].network_address), "SUBNET_CIDR": str(site["SUBNET"]),
         "SERVER_IP": srv.ip, "SERVER_HOSTNAME": srv.hostname, "SERVER_FQDN": f"{srv.hostname}.{d}",
         "KANIDM_FQDN": f"idm.{d}", "CA_FQDN": f"ca.{d}", "ALERT_HOOK": site["ALERT_HOOK"],
         "CLIENT_HOSTS": " ".join(h.hostname for h in hosts if h.role == "client"),
         "COLLECTOR_IP": site.get("COLLECTOR_IP", ""), "COLLECTOR_SSH_PUBKEY": site.get("COLLECTOR_SSH_PUBKEY", "")}
    if client:
        v.update({k: client[k] for k in ("CA_ROOT_SHA256", "SSH_CA_PUBKEY", "SSH_CA_FPR", "CACHE_PUBKEY", "KANIDM_URL")})
    return v
```

  - **`cli.py` `_get`:** after `_load`, if `Path(a.site, "client.conf").exists()`, parse it (`parse_client_conf(read_file(...), site)`) and pass it as `client`.
  - **`pre.py`:** add `TOKEN_RE = r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"`. In `run_pre`, right after the client `parse_client_conf` line (so still before `choose_disk` and the escrow):

```python
        tp = stick / "tokens" / f"{host.hostname}.token"
        if not tp.is_file():
            raise SiteError(f"no unixd token for {host.hostname} on the site stick: on the server run "
                            f"`chp-site client-token {host.hostname}` then `chp-site export-client`")
        token = read_file(tp, f"unixd token for {host.hostname}").strip()
        if not re.fullmatch(TOKEN_RE, token):
            raise SiteError(f"tokens/{host.hostname}.token is not a Kanidm API token")
```

    After the `luks-pass` write:

```python
    if role == "client":
        fd = os.open(out / "unixd.token", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token)
```

    (Add `import re`. Initialise `token = None` before the role check.)
- [ ] **Step 4: Run** the three files, then the whole suite. Expected: all pass. Existing client tests have been given a token.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4a Task 1: collector key + client values in chp-site get; pre requires and stages the client's own unixd token"`

---

### Task 2: Token lifecycle: `export-client` moves tokens, `client-token HOST`, and `onboard` adds `chp_users`

**Files:**
- Modify: `appliance/chp-site/chp_site/escrow.py`, `kanidm.py`, `ops.py`, `cli.py`
- Test: `tests/test_chp_site_escrow.py`, `tests/test_chp_site_kanidm.py`, `tests/test_chp_site_ops.py`, `tests/test_chp_site_cli.py`

**Interfaces:**
- Consumes: `escrow._write_synced`, `_read_back`, `_shred`; `Kanidm._k`; `pre.TOKEN_RE`.
- Produces:
  - `escrow.move_tokens(pending_tokens_dir, stick, now) -> list[str]` (hostnames moved)
  - `Kanidm.service_account_exists(name) -> bool`, `Kanidm.service_account_create(name, display)`, `Kanidm.api_token(name, label) -> str`
  - `ops.LOGIN_GROUP = "chp_users"`
  - `ops.client_token(k, hosts, hostname, pending=Path("/root/chp-escrow-pending"), rec=audit.record) -> Path`
  - CLI `chp-site client-token HOST [--as NAME] [--site DIR]`

- [ ] **Step 1: Failing tests.**
  - `tests/test_chp_site_escrow.py`:

```python
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
```

  - `tests/test_chp_site_kanidm.py` (it reuses `Fake`):

```python
JWS = "eyJhbGciOiJFUzI1NiJ9AAAAAAAAAAAA.eyJzdWIiOiJ1bml4ZC1jbGkifQAAAAAAA.c2lnbmF0dXJlc2lnbmF0dXJlc2ln"


def test_service_account_and_token():
    f = Fake((0, "No matching entries\n", ""), (0, "Success\n", ""), (0, f"blah\n{JWS}\n", ""))
    k = Kanidm("idm_admin", run=f)
    assert k.service_account_exists("unixd-cli1") is False
    k.service_account_create("unixd-cli1", "unixd on cli1")
    assert k.api_token("unixd-cli1", "cli1-unixd") == JWS
    assert f.calls[1][:4] == ["service-account", "create", "unixd-cli1", "unixd on cli1"]
    assert f.calls[2][:5] == ["service-account", "api-token", "generate", "unixd-cli1", "cli1-unixd"]
    assert "--readwrite" not in f.calls[2]


def test_service_account_names_allow_a_hostname():
    f = Fake((0, "---\nname: unixd-iso4-cli\n", ""))
    assert Kanidm("idm_admin", run=f).service_account_exists("unixd-iso4-cli") is True
    with pytest.raises(SiteError, match="not a valid service account"):
        Kanidm("idm_admin", run=Fake()).service_account_exists("unixd-X;")


def test_api_token_missing_is_an_error():
    with pytest.raises(SiteError, match="no API token"):
        Kanidm("idm_admin", run=Fake((0, "odd\n", ""))).api_token("unixd-cli1", "cli1-unixd")
```

  - `tests/test_chp_site_ops.py`: update the two onboard tests whose expected log changes. `test_onboard_new_user_full_path` now expects `["create", "posix", "add", "add", "token"]` (`chp_users` first, then `lab_users`). `test_onboard_is_idempotent_...` gives `lab01` `directmemberof: ["lab_users@idm.x", "chp_users@idm.x"]`. Then add:

```python
def test_onboard_always_adds_the_login_group(ca, tmp_path):
    k = FakeK()
    ops.onboard(k, ca, "lab09", "x.test", out=tmp_path / "o", rec=Rec(), say=lambda *_: None)
    assert ("add", "chp_users", "lab09") in k.log


class FakeSA(FakeK):
    def __init__(self):
        super().__init__(); self.sa = set()

    def service_account_exists(self, n):
        return n in self.sa

    def service_account_create(self, n, d):
        self.log.append(("sa-create", n)); self.sa.add(n)

    def add_member(self, g, n):
        self.log.append(("add", g, n))

    def api_token(self, n, label):
        self.log.append(("token", n, label)); return "t" * 20 + ".t" + "t" * 20 + ".t" + "t" * 20


def test_client_token_mints_into_pending(tmp_path):
    from chp_site.hosts import Host
    hosts = [Host("m1", "srv", "10.0.0.1", "server", None), Host("m2", "cli1", "10.0.0.2", "client", None)]
    k, rec = FakeSA(), Rec()
    p = ops.client_token(k, hosts, "cli1", pending=tmp_path / "pend", rec=rec)
    assert p == tmp_path / "pend" / "tokens" / "cli1.token" and oct(p.stat().st_mode & 0o777) == "0o600"
    assert k.log == [("sa-create", "unixd-cli1"), ("add", "idm_unix_authentication_read", "unixd-cli1"),
                     ("token", "unixd-cli1", "cli1-unixd")]
    assert [c[0] for c in rec.calls] == ["client-token", "client-token.done"]


def test_client_token_refuses_unknown_or_server_hosts(tmp_path):
    from chp_site.hosts import Host
    hosts = [Host("m1", "srv", "10.0.0.1", "server", None)]
    with pytest.raises(SiteError, match="not a client in the hosts table"):
        ops.client_token(FakeSA(), hosts, "srv", pending=tmp_path, rec=Rec())
    with pytest.raises(SiteError, match="not a client in the hosts table"):
        ops.client_token(FakeSA(), hosts, "nope", pending=tmp_path, rec=Rec())
```

  - `tests/test_chp_site_cli.py`: `export-client` with a `--pending` dir holding `tokens/iso2-cli.token` moves it to `stick/tokens/`, and the output lists `tokens moved to the stick: iso2-cli`.

- [ ] **Step 2: Run to verify failure.** Expected: the new tests FAIL (`ImportError: move_tokens`, `AttributeError: service_account_exists`, `client_token`, onboard log mismatch).

- [ ] **Step 3: Implement.**
  - **`escrow.py`:**

```python
def move_tokens(pending_tokens, stick, now):
    """Per-client unixd tokens -> stick/tokens/<host>.token with the same guarantee as the escrow: written, fsync'd,
    read back from the DEVICE and compared, only then shredded on the server."""
    pending_tokens, d = Path(pending_tokens), Path(stick) / "tokens"
    files = sorted(f for f in pending_tokens.iterdir() if f.is_file() and f.name.endswith(".token")) \
        if pending_tokens.is_dir() else []
    if not files:
        return []
    try:
        d.mkdir(exist_ok=True)
        for f in files:
            v = f.read_text()
            out = d / f.name
            if out.exists():
                out.rename(d / f"{f.name}.{now}.old")
            _write_synced(out, v)
            if _read_back(out) != v:
                raise OSError(0, f"read-back of {f.name} from the stick does not match")
    except OSError as e:
        raise SiteError(f"could not write the client tokens to the stick ({getattr(e, 'strerror', None) or e}); they are "
                        "kept on the server and the monitor keeps warning") from None
    for f in files:
        _shred(f)
    try:
        pending_tokens.rmdir()
    except OSError:
        pass
    return [f.name[:-len(".token")] for f in files]
```

  - **`kanidm.py`:** add `SA_RE = r"[a-z][a-z0-9_-]{0,63}"` and `_sa(n)` (like `_name`, message `not a valid service account name`). Add to `Kanidm`:

```python
    def service_account_exists(self, name):
        return parse_entry(self._k("service-account", "get", _sa(name))) is not None

    def service_account_create(self, name, display):
        self._k("service-account", "create", _sa(name), display, "idm_admins")

    def api_token(self, name, label):
        """A READ-ONLY API token (no --readwrite). The token is returned, never logged."""
        out = self._k("service-account", "api-token", "generate", _sa(name), _sa(label))
        m = re.findall(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", out)
        if not m:
            raise SiteError("no API token in the kanidm output")
        return m[-1]
```

    `service_account_create`'s `idm_admins` is the managing group (the lab's form). The test asserts only the first four argv elements.
  - **`ops.py`:**
    - Add `LOGIN_GROUP = "chp_users"`.
    - In `onboard`, after validating `groups`: `groups = (LOGIN_GROUP,) + tuple(g for g in groups if g != LOGIN_GROUP)`.
    - Add:

```python
def client_token(k, hosts, hostname, pending=Path("/root/chp-escrow-pending"), rec=audit.record):
    """A read-only unixd token for a client added after the server's first boot. It goes to the pending dir; the next
    `chp-site export-client` moves it onto the site stick. Never printed."""
    if not any(h.hostname == hostname and h.role == "client" for h in hosts):
        raise SiteError(f"{hostname} is not a client in the hosts table (/etc/chp/hosts)")
    sa = f"unixd-{hostname}"
    fields = {"host": hostname, "operator": audit.operator(), "as": k.as_}
    rec("client-token", fields)
    if not k.service_account_exists(sa):
        k.service_account_create(sa, f"unixd on {hostname}")
    k.add_member("idm_unix_authentication_read", sa)
    tok = k.api_token(sa, f"{hostname}-unixd")
    d = Path(pending) / "tokens"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    p = write_private(d, f"{hostname}.token", tok + "\n")
    rec("client-token.done", fields, after=True)
    return p
```

      `Kanidm.add_member` validates `name` with `_name` (users). For a service account, relax it: `add_member` accepts `_sa`-valid member names (group names still `_name`). Update `add_member` to `self._k("group", "add-members", _name(group, "group name"), _sa(name))`. `_sa` accepts every valid user name too.
  - **`cli.py`:**
    - In `_export_to`, after the `move_pending` call:

```python
    toks = move_tokens(pending / "tokens", stick, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())) \
        if (pending / "tokens").is_dir() else []
    print("tokens moved to the stick: " + ", ".join(toks) if toks else "no client tokens pending")
```

      `move_pending` only moves files, so the `tokens/` subdirectory is left for `move_tokens`.
    - Add `client-token`: `_client_token(a)` → `_ops_env(a)`, `ops.client_token(k, hosts, a.host)`, then print `token for HOST written to <path>; now run chp-site export-client with the site stick`. Sub-parser: `host`, `--as`, `--site`.
- [ ] **Step 4: Run** the four files, then the whole suite. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4a Task 2: per-client unixd tokens (export-client moves them with read-back; client-token HOST); onboard adds chp_users"`

---

### Task 3: The client enrolment script and the authselect patcher

**Files:**
- Create in `appliance/rpm/chp-identity-client/`:
  - `client-enrol.sh` (→ `/usr/libexec/chp/client-enrol`)
  - `authselect_patch.py` (a byte copy of `lab/client/authselect_patch.py` with the branding header added above its docstring; → `/usr/libexec/chp/authselect-patch`)
  - `unixd.toml.in`
- Modify: `tests/test_pam_patch.py` (imports the appliance copy)
- Test: `tests/test_client_role_static.py` (new)

**Interfaces:**
- Consumes: `chp-site get` keys from Task 1.
- Produces: `client-enrol [--role client|server] [--step NAME]`. Steps are `trust`, `unixd`, `authselect`, `sshd` and `accounts`, each marked `/var/lib/chp/firstboot/client-<step>.done`; `client.done` is written at the end. Exit 0 = enrolled.

- [ ] **Step 1: Failing static tests** `tests/test_client_role_static.py`:

```python
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "appliance/rpm/chp-identity-client"


def text(n):
    return (C / n).read_text()


def test_enrol_is_bash_strict_and_branded():
    t = text("client-enrol.sh")
    assert t.startswith("#!/bin/bash\n# CyberHygiene Project Lab Installer") and "set -Eeuo pipefail" in t
    assert subprocess.run(["bash", "-n", str(C / "client-enrol.sh")]).returncode == 0


def test_trust_is_pinned_and_rechecked():
    t = text("client-enrol.sh")
    assert 'step-cli ca root "$T/root.pem" --ca-url "https://$CA:9000" --fingerprint "$PIN" --force' in t
    assert "openssl x509 -in \"$T/root.pem\" -outform DER | sha256sum" in t
    assert re.search(r'\[ "\$got" = "\$PIN" \] \|\| \{ log "CHP: refusing', t)


def test_unixd_token_is_never_copied_or_printed():
    t = text("client-enrol.sh")
    assert "LoadCredential=unixd_token:/etc/kanidm/token" in t
    assert "cat /etc/kanidm/token" not in t and "echo \"$token" not in t


def test_authselect_rebuilt_from_the_recorded_original():
    t = text("client-enrol.sh")
    assert "/var/lib/chp/authselect-original" in t
    assert "authselect select custom/kanidm" in t and "--force" in t
    assert "LOST authselect feature" in t


def test_sshd_validated_before_reload_and_removed_on_failure():
    t = text("client-enrol.sh")
    i, j = t.index("sshd -t"), t.index("systemctl reload sshd")
    assert i < j and "rm -f /etc/ssh/sshd_config.d/10-chp.conf /etc/ssh/sshd_config.d/99-chp-exceptions.conf" in t


def test_lab_and_appliance_patchers_do_not_drift():
    lab = (ROOT / "lab/client/authselect_patch.py").read_text()
    app = text("authselect_patch.py")
    assert app.endswith(lab) and app.startswith("# CyberHygiene Project Lab Installer")
```

   Change `tests/test_pam_patch.py` line 2 to load the appliance copy by path:

```python
import importlib.util
_spec = importlib.util.spec_from_file_location("authselect_patch", Path(__file__).resolve().parents[1] / "appliance/rpm/chp-identity-client/authselect_patch.py")
_m = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_m)
patch_pam, patch_nsswitch = _m.patch_pam, _m.patch_nsswitch
```

- [ ] **Step 2: Run to verify failure.** `.venv/bin/python -m pytest tests/test_client_role_static.py tests/test_pam_patch.py -q`. Expected: FAIL (the files do not exist).

- [ ] **Step 3: Implement** `client-enrol.sh` (the branding header follows the shebang):

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# client-enrol [--role client|server] [--step NAME]: make this host a Kanidm client of the site (spec §7). Idempotent;
# each step is marked /var/lib/chp/firstboot/client-<step>.done. Every value comes from `chp-site get` (client.conf on a
# client; the server's own CA files with --role server). The unixd token (/etc/kanidm/token, 0600) is never read here.
set -Eeuo pipefail
ROLE=client; ONLY=""
while [ $# -gt 0 ]; do case $1 in --role) ROLE=$2; shift 2 ;; --step) ONLY=$2; shift 2 ;; *) echo "usage: client-enrol [--role client|server] [--step NAME]" >&2; exit 2 ;; esac; done
case $ROLE in client|server) ;; *) echo "client-enrol: --role client|server" >&2; exit 2 ;; esac
M=/var/lib/chp/firstboot; ANCHOR=/etc/pki/ca-trust/source/anchors/chp-root.crt; install -d -m 0700 "$M"
log() { echo "chp-client-enrol: $*"; logger -t chp-client-enrol -- "$*"; }
current=""; trap 'log "CHP: client enrolment failed at ${current:-setup} (resume: systemctl restart chp-client-firstboot)"' ERR
step() { local n=$1; shift; current=$n; if [ -n "$ONLY" ] && [ "$ONLY" != "$n" ]; then return 0; fi
         if [ -z "$ONLY" ] && [ -e "$M/client-$n.done" ]; then return 0; fi; log "step $n"; "$@"; touch "$M/client-$n.done"; }
g() { chp-site get "$1"; }
CA=$(g CA_FQDN); IDM=$(g KANIDM_FQDN); SIP=$(g SERVER_IP)
if [ "$ROLE" = server ]; then LOGIN_GROUP=chp_admins; else LOGIN_GROUP=chp_users; fi

do_trust() {
  if [ "$ROLE" = server ]; then [ -s "$ANCHOR" ]; return; fi       # the server made the root itself (first boot)
  PIN=$(g CA_ROOT_SHA256); T=$(mktemp -d); trap 'rm -rf "$T"' RETURN
  STEPPATH="$T" step-cli ca root "$T/root.pem" --ca-url "https://$CA:9000" --fingerprint "$PIN" --force >/dev/null 2>&1 \
    || { log "CHP: refusing: step-ca at $CA did not serve a root matching the pinned $PIN"; return 1; }
  got=$(openssl x509 -in "$T/root.pem" -outform DER | sha256sum | cut -d' ' -f1)
  [ "$got" = "$PIN" ] || { log "CHP: refusing: root fingerprint $got is not the pinned $PIN (client.conf)"; return 1; }
  install -m 0644 "$T/root.pem" "$ANCHOR"; restorecon "$ANCHOR"; update-ca-trust extract
}

do_unixd() {
  [ -s /etc/kanidm/token ] || { log "CHP: no unixd token at /etc/kanidm/token (installer staged none)"; return 1; }
  chmod 0600 /etc/kanidm/token; chown root:root /etc/kanidm/token
  chp-site render kanidm-config > /etc/kanidm/config
  sed "s/@LOGIN_GROUP@/$LOGIN_GROUP/" /usr/share/chp/client/unixd.toml.in > /etc/kanidm/unixd
  chmod 0644 /etc/kanidm/config /etc/kanidm/unixd                  # the CUI umask would leave them unreadable to unixd
  install -d -m 0755 /etc/systemd/system/kanidm-unixd.service.d
  printf '[Service]\nLoadCredential=unixd_token:/etc/kanidm/token\nEnvironment=KANIDM_SERVICE_ACCOUNT_TOKEN_PATH=%%d/unixd_token\n' \
    > /etc/systemd/system/kanidm-unixd.service.d/chp-token.conf
  restorecon -R /etc/kanidm /etc/systemd/system/kanidm-unixd.service.d
  systemctl daemon-reload; systemctl enable --now kanidm-unixd kanidm-unixd-tasks; systemctl restart kanidm-unixd
  for _ in $(seq 30); do if kanidm-unix status 2>/dev/null | grep -q "Kanidm: online"; then return 0; fi; sleep 2; done
  log "CHP: kanidm-unixd is not online (check https://$IDM reachability and the token)"; return 1
}

words() { tr ' ' '\n' | sed '/^$/d'; }
do_authselect() {
  O=/var/lib/chp/authselect-original
  # Record the ORIGINAL (CUI) profile once; a re-run never bases custom/kanidm on custom/kanidm itself.
  if [ ! -s "$O" ]; then
    cur=$(authselect current -r | words | head -1)
    [ "$cur" != custom/kanidm ] || { log "CHP: refusing: already custom/kanidm but no record of the original profile"; return 1; }
    authselect current -r | words > "$O"
  fi
  base=$(head -1 "$O"); mapfile -t feats < <(tail -n +2 "$O")
  [ "${#feats[@]}" -gt 0 ] || { log "CHP: refusing: the original profile $base has no features (CUI expects with-faillock)"; return 1; }
  case $base in custom/*) bdir=/etc/authselect/$base ;; *) bdir=/usr/share/authselect/default/$base ;; esac
  [ -d /etc/authselect/custom/kanidm ] || authselect create-profile kanidm -b "$base" >/dev/null
  for f in system-auth password-auth nsswitch.conf; do cp "$bdir/$f" "/etc/authselect/custom/kanidm/$f"; done
  python3 /usr/libexec/chp/authselect-patch /etc/authselect/custom/kanidm
  authselect select custom/kanidm "${feats[@]}" --force >/dev/null
  for f in "${feats[@]}"; do authselect current -r | words | grep -qx -- "$f" || { log "CHP: LOST authselect feature: $f"; return 1; }; done
  for db in passwd group initgroups; do
    [ "$(awk -v d="$db:" '$1==d{print $2}' /etc/nsswitch.conf)" = kanidm ] || { log "CHP: nsswitch $db does not start with kanidm"; return 1; }
  done
  authselect check >/dev/null
}

do_sshd() {
  D=/etc/ssh/sshd_config.d
  if [ "$ROLE" = server ]; then key=$(cut -d' ' -f1,2 /etc/ssh-ca/user_ca.pub); else key=$(g SSH_CA_PUBKEY); fi
  printf '%s chp-user-ca\n' "$key" > /etc/ssh/chp_user_ca.pub; chmod 0644 /etc/ssh/chp_user_ca.pub
  if [ "$ROLE" = client ]; then
    [ "$(ssh-keygen -lf /etc/ssh/chp_user_ca.pub | awk '{print $2}')" = "$(g SSH_CA_FPR)" ] \
      || { log "CHP: refusing: SSH user CA key does not match SSH_CA_FPR (client.conf)"; return 1; }
  fi
  install -m 0600 /usr/share/chp/client/sshd-10-chp.conf "$D/10-chp.conf"
  install -m 0600 /usr/share/chp/client/sshd-99-chp-exceptions.conf "$D/99-chp-exceptions.conf"
  restorecon /etc/ssh/chp_user_ca.pub "$D/10-chp.conf" "$D/99-chp-exceptions.conf"
  if ! sshd -t; then
    rm -f /etc/ssh/sshd_config.d/10-chp.conf /etc/ssh/sshd_config.d/99-chp-exceptions.conf
    log "CHP: sshd rejected the CHP drop-ins; removed them (sshd unchanged)"; return 1
  fi
  systemctl reload sshd
}

do_accounts() { /usr/libexec/chp/client-accounts --role "$ROLE"; }

step trust do_trust
step unixd do_unixd
step authselect do_authselect
step sshd do_sshd
step accounts do_accounts
if [ -z "$ONLY" ]; then current=done; touch "$M/client.done"; log "CHP: client enrolment complete ($ROLE; logins: $LOGIN_GROUP)"; fi
```

   `unixd.toml.in`:

```toml
version = '2'

[kanidm]
pam_allowed_login_groups = ["@LOGIN_GROUP@"]
```

- [ ] **Step 4: Run** the two test files, then the whole suite. Expected: all pass.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4a Task 3: client-enrol (pinned trust, per-host unixd token, authselect from the recorded CUI profile) + appliance authselect patcher"`

---

### Task 4: Accounts, sshd drop-ins and sudoers: `diag`, `chpcache`, `chp_admins`

**Files:**
- Create in `appliance/rpm/chp-identity-client/`:
  - `client-accounts.sh` (→ `/usr/libexec/chp/client-accounts`)
  - `diag-collect.sh` (→ `/usr/libexec/chp/diag-collect`)
  - `sshd-10-chp.conf`, `sshd-99-chp-exceptions.conf` (→ `/usr/share/chp/client/`)
- Test: `tests/test_client_accounts.py` (new)

**Interfaces:**
- Consumes: `chp-site get COLLECTOR_IP COLLECTOR_SSH_PUBKEY CACHE_PUBKEY SERVER_IP`.
- Produces:
  - `client-accounts --role client|server`
  - `diag-collect` (a forced command; reads `SSH_ORIGINAL_COMMAND`; the `CHP_SUDO` override exists **only** for tests, and sshd never passes client environment because `PermitUserEnvironment` is `no`)

- [ ] **Step 1: Failing tests** `tests/test_client_accounts.py`:

```python
import os
import subprocess
from pathlib import Path

import pytest

C = Path(__file__).resolve().parents[1] / "appliance/rpm/chp-identity-client"


def diag(cmd, tmp_path):
    fake = tmp_path / "sudo"; fake.write_text('#!/bin/bash\necho "SUDO $*"\n'); fake.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin", "CHP_SUDO": str(fake)}
    if cmd is not None:
        env["SSH_ORIGINAL_COMMAND"] = cmd
    return subprocess.run(["bash", str(C / "diag-collect.sh")], env=env, capture_output=True, text=True)


@pytest.mark.parametrize("cmd,want", [
    (None, "SUDO -n /usr/sbin/idm-collect"),
    ("sudo -n /usr/sbin/idm-collect", "SUDO -n /usr/sbin/idm-collect"),
    ("sudo -n /usr/sbin/idm-collect --user lab09", "SUDO -n /usr/sbin/idm-collect --user lab09"),
    ("idm-collect --user ops_1", "SUDO -n /usr/sbin/idm-collect --user ops_1"),
])
def test_allowed_forms(tmp_path, cmd, want):
    r = diag(cmd, tmp_path)
    assert r.returncode == 0 and r.stdout.strip() == want


@pytest.mark.parametrize("cmd", [
    "bash", "sudo -n /usr/sbin/idm-collect --user 'x;id'", "idm-collect --user", "idm-collect --user a b",
    "sudo /usr/sbin/idm-collect", "/usr/bin/idm-collect", "idm-collect --json", "sudo -n /bin/sh",
    "idm-collect --user Root", "idm-collect --user $(id)", "idm-collect; id",
])
def test_everything_else_refused_and_sudo_never_runs(tmp_path, cmd):          # Review Focus 2
    r = diag(cmd, tmp_path)
    assert r.returncode == 1 and "SUDO" not in r.stdout and "refused" in r.stderr


def test_sshd_dropins():
    t10 = (C / "sshd-10-chp.conf").read_text()
    for line in ("PubkeyAuthentication yes", "KbdInteractiveAuthentication yes", "UsePAM yes",
                 "AuthenticationMethods publickey,keyboard-interactive:pam", "TrustedUserCAKeys /etc/ssh/chp_user_ca.pub"):
        assert line in t10.splitlines()
    t99 = (C / "sshd-99-chp-exceptions.conf").read_text()
    assert "Match User chpadmin,diag,chpcache" in t99 and "    AuthenticationMethods publickey" in t99
    assert "Match" not in t10


def test_accounts_script_pins_keys_and_exact_sudo():
    t = (C / "client-accounts.sh").read_text()
    assert 'from=\\"$CIP\\",command=\\"/usr/libexec/chp/diag-collect\\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding' in t
    assert 'from=\\"$SIP\\",command=\\"sudo -n /usr/sbin/kanidm-unix cache-invalidate\\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding' in t
    assert "diag ALL=(root) NOPASSWD: /usr/sbin/idm-collect, /usr/sbin/idm-collect --user *" in t
    assert "chpcache ALL=(root) NOPASSWD: /usr/sbin/kanidm-unix cache-invalidate" in t
    assert "%chp_admins ALL=(ALL) ALL" in t
    assert t.count("visudo -cf") >= 3
    assert subprocess.run(["bash", "-n", str(C / "client-accounts.sh")]).returncode == 0
```

- [ ] **Step 2: Run to verify failure.** Expected: FAIL (files missing).

- [ ] **Step 3: Implement.**
  - **`diag-collect.sh`** (bash 3.2-safe, because the tests run on macOS; no empty-array expansion under `set -u`):

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# diag-collect: the diag key's FORCED command (ISSO #22). Accepts only [sudo -n] [/usr/sbin/]idm-collect [--user NAME]
# (or nothing) from SSH_ORIGINAL_COMMAND and runs the FIXED sudo command itself. Anything else is refused; sudo never runs.
set -eu
SUDO=${CHP_SUDO:-/usr/bin/sudo}     # CHP_SUDO: tests only (sshd passes no client environment: PermitUserEnvironment no)
deny() { echo "diag-collect: refused: only 'idm-collect [--user NAME]' is allowed" >&2; exit 1; }
cmd=${SSH_ORIGINAL_COMMAND:-}
case $cmd in *[!a-z0-9_/\ -]*) deny ;; esac        # no quotes, ;, $, (, `, |, &, glob characters, upper case
set -f; set -- $cmd; set +f                          # split on spaces only; globbing off
if [ "${1:-}" = sudo ]; then [ "${2:-}" = -n ] || deny; shift 2; fi
case ${1:-idm-collect} in /usr/sbin/idm-collect|idm-collect) ;; *) deny ;; esac
[ $# -gt 0 ] && shift
if [ $# -eq 0 ]; then exec "$SUDO" -n /usr/sbin/idm-collect; fi
if [ $# -eq 2 ] && [ "$1" = --user ] && printf '%s' "$2" | grep -Eqx '[a-z][a-z0-9_]{0,31}'; then
  exec "$SUDO" -n /usr/sbin/idm-collect --user "$2"
fi
deny
```

  - **`sshd-10-chp.conf`:**

```
# CHP client role (spec §7, row 10, row 35). Owned by chp-identity-client; drift is checked by the monitor (sshd -T).
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive:pam
TrustedUserCAKeys /etc/ssh/chp_user_ca.pub
```

  - **`sshd-99-chp-exceptions.conf`:**

```
# CHP key-only exceptions (decisions: chpadmin break-glass = Plan 2; diag + chpcache = forced-command keys, ISSO #22/#28).
# Kept in the LAST drop-in: Task 5 proves a Match here does not swallow the main sshd_config lines after the Include.
Match User chpadmin,diag,chpcache
    AuthenticationMethods publickey
```

  - **`client-accounts.sh`:**

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# client-accounts --role client|server: the forced-command accounts and sudo rules (ISSO #22, #28; chp_admins).
# Files are REPLACED on every run (never appended). Every sudoers file is checked with visudo before it is installed.
set -Eeuo pipefail
ROLE=${2:-client}
g() { chp-site get "$1"; }
sudoers() {   # sudoers NAME LINE: validate, then install 0440
  local t; t=$(mktemp); printf '%s\n' "$2" > "$t"; visudo -cf "$t" >/dev/null; install -o root -g root -m 0440 "$t" "/etc/sudoers.d/$1"; rm -f "$t"
}
keyfile() {   # keyfile USER LINE: authorized_keys holding exactly LINE
  local h; h=$(getent passwd "$1" | cut -d: -f6)
  install -d -o "$1" -g "$1" -m 0700 "$h/.ssh"
  printf '%s\n' "$2" > "$h/.ssh/authorized_keys"; chown "$1:$1" "$h/.ssh/authorized_keys"; chmod 0600 "$h/.ssh/authorized_keys"
  restorecon -R "$h/.ssh"
}
account() { id "$1" >/dev/null 2>&1 || useradd -r -m -s /bin/bash -c "$2" "$1"; passwd -l "$1" >/dev/null 2>&1 || true; }

sudoers 60-chp-admins "%chp_admins ALL=(ALL) ALL"

CIP=$(g COLLECTOR_IP); CKEY=$(g COLLECTOR_SSH_PUBKEY)
if [ -n "$CKEY" ]; then
  account diag "CHP read-only collector (forced command)"
  keyfile diag "from=\"$CIP\",command=\"/usr/libexec/chp/diag-collect\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $CKEY diag"
  sudoers 61-chp-diag "diag ALL=(root) NOPASSWD: /usr/sbin/idm-collect, /usr/sbin/idm-collect --user *"
fi

if [ "$ROLE" = client ]; then
  SIP=$(g SERVER_IP); KKEY=$(g CACHE_PUBKEY)
  account chpcache "CHP revoke fan-out (forced command)"
  keyfile chpcache "from=\"$SIP\",command=\"sudo -n /usr/sbin/kanidm-unix cache-invalidate\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $KKEY chpcache"
  sudoers 62-chp-cache "chpcache ALL=(root) NOPASSWD: /usr/sbin/kanidm-unix cache-invalidate"
fi
```

    (`ROLE=${2:-client}` reads the value after `--role`; `client-enrol` always passes `--role X`.)
- [ ] **Step 4: Run.** `.venv/bin/python -m pytest tests/test_client_accounts.py -q` → all pass; then the whole suite.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4a Task 4: diag forced command (validated --user), chpcache, chp_admins sudo, sshd drop-ins"`

---

### Task 5: Prove the sshd `Match` placement on OpenSSH 9.9 (aero), before anything relies on it

**Files:** create `lab/iso4/sshd-match-check.sh` (runs on aero as a normal user, in a temp dir, and never touches aero's sshd); record the result in `lab/iso4/PROOF-RECORD.md`.

- [ ] **Step 1: Write the check.** It builds a config tree like Rocky's:
  - the main file: `Include $T/d/*.conf`, then `X11Forwarding no` and `MaxAuthTries 3` **after** the Include (as the CUI main file has)
  - `d/10-chp.conf` and `d/99-chp-exceptions.conf` (the Task 4 files, with `TrustedUserCAKeys` pointing at a temp key)
  - a temp host key (`ssh-keygen -t ecdsa`)

  It then runs `/usr/sbin/sshd -T -f $T/main -h $T/hk -C user=X,host=h,addr=1.2.3.4` for `X` in `alice`, `chpadmin`, `diag`, and prints `authenticationmethods`, `x11forwarding` and `maxauthtries`.
- [ ] **Step 2: Run** `scp lab/iso4/sshd-match-check.sh aero:/tmp/ && ssh aero bash /tmp/sshd-match-check.sh`. **Expected:**
  - `alice`: `authenticationmethods publickey,keyboard-interactive:pam`
  - `chpadmin` and `diag`: `authenticationmethods publickey`
  - **for all three:** `x11forwarding no` and `maxauthtries 3`

  If any value leaks (e.g. `maxauthtries 6` for `chpadmin`), the `Match` swallowed the lines after the `Include`. Then move the exceptions **into the main-file position** instead: `client-enrol` appends a marked block at the end of `/etc/ssh/sshd_config`, replaced idempotently between `# BEGIN CHP` / `# END CHP`. Ledger a ruling, and update Task 4's files and tests. Stop here and use systematic-debugging until the check passes.
- [ ] **Step 3: Commit** the script and the record: `git commit -m "ISO Plan 4a Task 5: sshd Match placement proven on OpenSSH 9.9 (no leak past the Include)"`

---

### Task 6: `chp_kanidm` SELinux module, client monitors, first-boot unit, and the RPM

**Files:**
- Create in `appliance/rpm/chp-identity-client/`:
  - `selinux/chp_kanidm.te` (from `lab/selinux/kanidm_lab.te`, module renamed `chp_kanidm 1.0`, comments updated: shipped per ISSO #12, unixd unconfined = POA&M)
  - `selinux/chp_kanidm.fc`: `/run/kanidm-unixd(/.*)?  gen_context(system_u:object_r:kanidm_unixd_var_run_t,s0)`
  - `monitor.d/50-authselect.sh`, `51-sshd.sh`, `52-kanidm-tls.sh`
  - `client-firstboot.sh`, `chp-client-firstboot.service`
  - `chp-identity-client.spec`, `build-rpm.sh`
- Test: `tests/test_client_role_static.py` (more tests)

**Interfaces:** the RPM `chp-identity-client-0.1.0-1.chp.el9.noarch` installs:
- `/usr/libexec/chp/{client-enrol,client-accounts,diag-collect,authselect-patch,client-firstboot}`
- `/usr/share/chp/client/*`
- `/usr/share/selinux/packages/chp_kanidm.pp`
- `/usr/lib/chp/monitor.d/5[0-2]-*.sh`
- `chp-client-firstboot.service`

It `Requires: chp-base chp-site kanidm-unixd kanidm-clients idm-collect step-cli authselect policycoreutils-python-utils`.

- [ ] **Step 1: Failing tests** (append to `tests/test_client_role_static.py`):

```python
def test_selinux_module_is_the_lab_policy_renamed():
    te = text("selinux/chp_kanidm.te")
    assert "module chp_kanidm 1.0;" in te and "type kanidm_unixd_var_run_t;" in te
    assert "allow nsswitch_domain kanidm_unixd_var_run_t:sock_file { getattr write };" in te
    assert "/run/kanidm-unixd(/.*)?" in text("selinux/chp_kanidm.fc")


def test_monitors_print_ok_or_alert():
    for n in ("50-authselect.sh", "51-sshd.sh", "52-kanidm-tls.sh"):
        t = text(f"monitor.d/{n}")
        assert t.startswith("#!/bin/bash\n# CyberHygiene") and "ALERT " in t and "OK " in t
        assert subprocess.run(["bash", "-n", str(C / "monitor.d" / n)]).returncode == 0
    assert "authselect check" in text("monitor.d/50-authselect.sh")
    assert "sshd -T -C user=chp-monitor-probe" in text("monitor.d/51-sshd.sh")
    assert "curl -fsS --max-time 10 --cacert /etc/pki/ca-trust/source/anchors/chp-root.crt" in text("monitor.d/52-kanidm-tls.sh")


def test_spec_installs_policy_and_requires_the_stack():
    s = text("chp-identity-client.spec")
    for r in ("kanidm-unixd", "kanidm-clients", "idm-collect", "step-cli", "policycoreutils-python-utils", "chp-site", "chp-base"):
        assert re.search(rf"^Requires:\s+.*\b{re.escape(r)}\b", s, re.M), r
    assert "semodule -i %{_datadir}/selinux/packages/chp_kanidm.pp" in s
    assert "semodule -r chp_kanidm" in s and "Vendor:         The CyberHygiene Project" in s


def test_firstboot_unit_runs_enrol_once():
    u = text("chp-client-firstboot.service")
    assert "ConditionPathExists=!/var/lib/chp/firstboot/client.done" in u and "Environment=HOME=/root" in u
    assert "After=chp-firstboot-common.service network-online.target" in u
    assert "exec /usr/libexec/chp/client-enrol --role client" in text("client-firstboot.sh")
```

- [ ] **Step 2: Run to verify failure.** Expected: FAIL (files missing).

- [ ] **Step 3: Implement.**
  - **`50-authselect.sh`:** `authselect check` must pass, and `authselect current -r` must equal `custom/kanidm` plus the features recorded in `/var/lib/chp/authselect-original` (lines 2+). Print `OK authselect custom/kanidm (features)` or `ALERT authselect …`. If `/var/lib/chp/firstboot/client.done` is absent, print `OK authselect (not enrolled yet)`.
  - **`51-sshd.sh`:** `sshd -T -C user=chp-monitor-probe,host=x,addr=127.0.0.2` must show `authenticationmethods publickey,keyboard-interactive:pam` and `trustedusercakeys /etc/ssh/chp_user_ca.pub`. With `user=chpadmin`, it must show `authenticationmethods publickey`. The CA key's `ssh-keygen -lf` fingerprint must equal `chp-site get SSH_CA_FPR` on a client (on the server: the fingerprint of `/etc/ssh-ca/user_ca.pub`). Otherwise print `ALERT sshd drift: …`.
  - **`52-kanidm-tls.sh`:** `curl -fsS --max-time 10 --cacert /etc/pki/ca-trust/source/anchors/chp-root.crt https://$(chp-site get KANIDM_FQDN)/status` must print `true` (row 29: TLS reachability from clients, not `kanidm-unix status`).
  - **`client-firstboot.sh`:**

```bash
#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# client-firstboot (chp-client-firstboot.service): enrol this client once (spec §7). Resume: systemctl restart chp-client-firstboot.
exec /usr/libexec/chp/client-enrol --role client
```

  - **`chp-client-firstboot.service`:** the Plan 3a server unit's pattern:
    - `Description=CHP first boot (client): pinned trust, Kanidm unixd, authselect, sshd, forced-command accounts`
    - `After=chp-firstboot-common.service network-online.target`, `Wants=network-online.target`
    - `ConditionPathExists=!/var/lib/chp/firstboot/client.done`
    - `Type=oneshot`, `Environment=HOME=/root`, `ExecStart=/usr/libexec/chp/client-firstboot`, `RemainAfterExit=yes`, `TimeoutStartSec=15min`
    - `WantedBy=multi-user.target`
  - **`chp-identity-client.spec`:** based on `chp-identity-server.spec`.
    - `Version: 0.1.0`, `Release: 1.chp%{?dist}`, `BuildArch: noarch`, the `Requires` above.
    - `%install`: copy each file (the modes as in the interfaces: 0755 scripts, 0644 data, 0600 nothing).
    - `%post`:
      ```
      semodule -i %{_datadir}/selinux/packages/chp_kanidm.pp
      semanage fcontext -a -t kanidm_unixd_var_run_t '/run/kanidm-unixd(/.*)?' 2>/dev/null || semanage fcontext -m -t kanidm_unixd_var_run_t '/run/kanidm-unixd(/.*)?'
      restorecon -R /run/kanidm-unixd 2>/dev/null || :
      %systemd_post chp-client-firstboot.service
      ```
    - `%postun` (on `$1 -eq 0`): `semanage fcontext -d '/run/kanidm-unixd(/.*)?' || :; semodule -r chp_kanidm || :`
    - `%changelog` entry.
  - **`build-rpm.sh`:** the `chp-identity-server/build-rpm.sh` pattern. It **first** compiles the policy on aero:
    `checkmodule -M -m -o chp_kanidm.mod chp_kanidm.te && semodule_package -o chp_kanidm.pp -m chp_kanidm.mod -f chp_kanidm.fc`. The `.pp` becomes a `Source`, and `rpmbuild -bb` follows.
- [ ] **Step 4: Run** the static tests and the whole suite (expected: all pass). Then **build on aero:** `bash appliance/rpm/chp-identity-client/build-rpm.sh` prints the file list, and it contains every path in the interfaces.
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4a Task 6: chp-identity-client RPM (chp_kanidm policy, first-boot unit, authselect/sshd/TLS monitors)"`

---

### Task 7: Server first boot: login groups, per-client tokens, and the server as its own client; kickstart wiring

**Files:**
- Modify:
  - `appliance/rpm/chp-identity-server/server-firstboot.sh`
  - `chp-identity-server.spec` (`Version: 0.1.1`, `Release: 1.chp`, `Requires: chp-identity-client`)
  - `appliance/kickstart/chp.ks.in`, `render-ks.sh`, `server.ks`, `client.ks` (re-rendered)
- Test: `tests/test_server_role_static.py`, `tests/test_kickstarts.py`

**Interfaces:**
- Consumes: `chp-site get CLIENT_HOSTS SERVER_HOSTNAME`; `/usr/libexec/chp/client-enrol --role server`.
- Produces:
  - first-boot steps `unixd-tokens` and `self-client` (after `cache-key`)
  - pending `tokens/<client>.token`
  - `/etc/kanidm/token` on the server
  - kickstart:
    - client packages `chp-base chp-identity-client`, enabling `chp-client-firstboot.service`
    - server packages `chp-base chp-identity-server chp-identity-client`
    - `%post --nochroot` installs `/tmp/chp/unixd.token` → `/mnt/sysimage/etc/kanidm/token` (0600) and shreds the copy

- [ ] **Step 1: Failing tests.** `tests/test_server_role_static.py`:

```python
def test_firstboot_tokens_and_self_client_after_cache_key():
    t = (ROOT / "appliance/rpm/chp-identity-server/server-firstboot.sh").read_text()
    order = [t.index(s) for s in ("step cache-key do_cachekey", "step unixd-tokens do_unixd_tokens",
                                  "step self-client do_self_client", 'touch "$M/server.done"')]
    assert order == sorted(order)
    assert 'service-account api-token generate "unixd-$h" "$h-unixd"' in t and "--readwrite" not in t
    assert "idm_unix_authentication_read" in t and "group posix set chp_users" in t and "group posix set chp_admins" in t
    assert '"$P/tokens/$h.token"' in t and "/etc/kanidm/token" in t
    assert "/usr/libexec/chp/client-enrol --role server" in t
    assert t.count("kanidm_login") >= 3          # defined once, used by collector and unixd-tokens
```

   `tests/test_kickstarts.py`:

```python
def test_role_packages_and_units():
    s, c = (KS / "server.ks").read_text(), (KS / "client.ks").read_text()
    assert "chp-identity-client" in s and "chp-identity-server" in s
    assert "chp-identity-client" in c and "chp-identity-server" not in c
    assert "chp-client-firstboot.service" in c and "chp-client-firstboot.service" not in s


def test_client_token_installed_0600_and_shredded():
    c = (KS / "client.ks").read_text()
    assert "install -D -m 0600 /tmp/chp/unixd.token /mnt/sysimage/etc/kanidm/token" in c
    assert "shred -u /tmp/chp/unixd.token" in c
```

   (Use the file's existing name for the kickstart directory. If there is none, `KS = ROOT / "appliance/kickstart"`.)
- [ ] **Step 2: Run to verify failure.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - **`server-firstboot.sh`:** turn `do_collector`'s login loop into a function, and call it in `do_collector` in place of the loop:

```bash
kanidm_login() {   # log in as idm_admin with the pending password (stdin only); Kanidm may still be busy after recover
  for try in 1 2 3 4 5; do
    if python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["idm_admin"])' "$P/kanidm-admins.json" \
         | expect /usr/libexec/chp/kanidm-login.exp idm_admin >/dev/null; then return 0; fi
    log "kanidm login not ready yet (try $try/5); retrying in 10 s"; sleep 10
  done
  return 1
}
```

    Add these steps:

```bash
do_unixd_tokens() {
  # Login groups (decision: clients allow chp_users, the server chp_admins) and one READ-ONLY unixd token per host.
  kanidm_login
  k() { kanidm "$@" -D idm_admin >/dev/null 2>&1; }
  for grp in chp_users chp_admins; do
    got=$(kanidm group get "$grp" -D idm_admin 2>/dev/null || true)
    grep -qx "name: $grp" <<< "$got" || k group create "$grp"
    k group posix set "$grp"
  done
  install -d -m 0700 "$P/tokens"
  for h in $(g CLIENT_HOSTS) "$(g SERVER_HOSTNAME)"; do
    got=$(kanidm service-account get "unixd-$h" -D idm_admin 2>/dev/null || true)
    grep -qx "name: unixd-$h" <<< "$got" || k service-account create "unixd-$h" "unixd on $h" idm_admins
    k group add-members idm_unix_authentication_read "unixd-$h"
    if [ "$h" = "$(g SERVER_HOSTNAME)" ]; then out=/etc/kanidm/token; else out="$P/tokens/$h.token"; fi
    if [ ! -s "$out" ]; then
      ( umask 077
        kanidm service-account api-token generate "unixd-$h" "$h-unixd" -D idm_admin 2>/dev/null \
          | grep -oE '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' | tail -1 > "$out.new"
        [ -s "$out.new" ] && mv "$out.new" "$out" )
    fi
  done
  kanidm logout -D idm_admin >/dev/null 2>&1 || true
}

do_self_client() { /usr/libexec/chp/client-enrol --role server; }
```

    Add `step unixd-tokens do_unixd_tokens` and `step self-client do_self_client` after `step cache-key do_cachekey`. Update the header comment's step list.
  - **`chp.ks.in`:** in `%post --nochroot`, after the `site-stick.id` line:

```bash
# This client's own unixd token (chp-site pre staged ONLY this host's token, 0600): to /etc/kanidm/token, then shred.
if [ -f /tmp/chp/unixd.token ]; then install -D -m 0600 /tmp/chp/unixd.token /mnt/sysimage/etc/kanidm/token; shred -u /tmp/chp/unixd.token; fi
```

  - **`render-ks.sh` roles:**
    - server: `"@ROLE_PACKAGES@": "chp-base\nchp-identity-server\nchp-identity-client"`, enable `chp-server-firstboot.service`
    - client: `"@ROLE_PACKAGES@": "chp-base\nchp-identity-client"`, `"@ROLE_ENABLE@": "chp-client-firstboot.service"`

    Re-render: `bash appliance/kickstart/render-ks.sh`.
- [ ] **Step 4: Run** the whole suite. Expected: all pass (the kickstart-equals-template test compares with the renderer's output, per the Plan 3a ruling).
- [ ] **Step 5: Commit.** `git commit -m "ISO Plan 4a Task 7: server first boot mints per-client tokens + becomes its own client; kickstart role wiring"`

---

### Task 8: Build the RPMs and sign repo 0.4.0 (the user's signing round)

- [ ] **Step 1: Build and assemble.**
  - Bump `chp-site` to `0.4.0` (`__init__.VERSION`, `chp-site.spec` with changelog; update the CLI version test).
  - Build `chp-site`, `chp-identity-server` (0.1.1) and `chp-identity-client` (0.1.0).
  - Add `chp-identity-client ours` to `appliance/release/PACKAGES.txt`, push the tools (`appliance/release/push.sh`), and assemble `/data/chp-release/0.4.0/stage` (**11 packages**) with `assemble-repo.sh … /data/chp-release/0.3.3/stage` as the third-party directory.
  - Check `rpm -qp` on each new package.
- [ ] **Step 2: Signing round (protocol).**
  1. Stage `sign040.sh` in the scratchpad.
  2. Tell the user in one line, and **wait for "ready"**.
  3. Run it in the background. `say "PIN dialog open. Eyes on the screen."`, then `say "Touch the key now."` every 20 s; at the end, `say "Signing finished."`.

  Expected: `REPO OK: 11 packages`. `verify-repo.sh` passes.
- [ ] **Step 3: Publish** by copying `/data/chp-release/0.4.0/repo` to `/data/lab-inputs/chp/0.4.0` (HTTP 200 on `repomd.xml.asc`). Write `appliance/release/RELEASE-RECORD-0.4.0.md` in the 0.3.3 record's format.
- [ ] **Step 4: Commit.** `git commit -m "ISO Plan 4a Task 8: signed repo 0.4.0 (chp-identity-client 0.1.0, chp-identity-server 0.1.1, chp-site 0.4.0)"`

---

### Task 9: Install proof on aero: a server and two clients

**Files:**
- Create in `lab/iso4/`:
  - `prove.sh`
  - `site.conf.in` (`DOMAIN=iso4.lab.test`, `COLLECTOR_IP=192.168.100.1`, `COLLECTOR_SSH_PUBKEY=@DIAG_PUBKEY@`, otherwise as iso3)
  - `hosts` (`iso4-srv` .40 `52:54:00:c4:04:40`, `iso4-cli1` .41 `…:41`, `iso4-cli2` .42 `…:42`)
  - `ssh-ki.exp`
  - `PROOF-RECORD.md`
- Reuse: `lab/iso2/{stick.sh,install.sh,unlock.sh,luks-send.exp}`, `lab/iso3/{rootrun.exp,rs.sh}`.
- Modify: `lab/iso-requirements.md`

**The harness:**
- `prove.sh` copies `lab/iso3/prove.sh`'s helpers (`A`, `V`, `Rt`, `Rv`, `Rs`, `check`) parameterised by `IP`/`VM`, with `CHP_REPO=0.4.0`. It adds `V2 IP CMD` / `Rv2 IP CMD`, which run on a client with **that client's** escrowed root password (`stick.sh escrow $STICK <client>.txt`).
- `ssh-ki.exp IP USER KEY CERT` logs in with the key + certificate, then answers the keyboard-interactive `Password:` with **stdin line 1** (never argv), and prints `id -un`. It prints `LOGIN_OK <name>` or `LOGIN_REFUSED`.

**Stages and checks.** Every line is PASS/FAIL; any FAIL stops and goes to systematic-debugging.

- [ ] **Step 1: `prep`.** Render the site (`@ADMIN_PUBKEY@`, `@DIAG_PUBKEY@` from `~/idm-lab-secrets/iso4_diag_ecdsa.pub`, made if missing), the lab kickstarts (embedded `chp-site`) and the stick. The Mac-side `chp-site validate` passes.
- [ ] **Step 2: `server`, `firstboot`, `reboot`, `export`.** These are the iso3 checks with iso4 names, plus:
  - `ls /var/lib/chp/firstboot` includes `unixd-tokens.done self-client.done client.done client-accounts.done`
  - two tokens are pending before export (`tokens/iso4-cli1.token`, `tokens/iso4-cli2.token`)
  - `/etc/kanidm/token` is 0600 root
  - **the server as client:**
    - `kanidm-unix status` shows `Kanidm: online`
    - `authselect current -r` = `custom/kanidm with-faillock without-nullok`
    - the nsswitch `passwd`, `group` and `initgroups` lines start with `kanidm`
  - `sshd -T -C user=alice,host=x,addr=1.1.1.1 | grep ^authenticationmethods` = `publickey,keyboard-interactive:pam`, and `user=chpadmin` gives `publickey`
  - `export-client` prints `tokens moved to the stick: iso4-cli1, iso4-cli2`, and `stick.sh list` shows both `tokens/*.token` (masked)
  - the server monitors are quiet
- [ ] **Step 3: `client1`, `client2`.** Install each from the stick (`install.sh VM MAC client`), unlock, and wait for `client.done`. Then check each client:
  - no pending token copy: `/tmp/chp` does not exist on the installed system, and `/etc/kanidm/token` is 0600 root
  - `/etc/pki/ca-trust/source/anchors/chp-root.crt`'s DER SHA-256 = `CA_ROOT_SHA256` from the stick's `client.conf`
  - `kanidm-unix status` online
  - authselect and nsswitch as on the server
  - `sshd -T` (normal user / `chpadmin`) as on the server
  - `semodule -l | grep -c ^chp_kanidm` = 1, and `ls -Zd /run/kanidm-unixd` shows `kanidm_unixd_var_run_t`
  - monitors quiet
  - AVC 0 and fapolicyd 0 since boot
  - the TPM reboot unlocks
- [ ] **Step 4: `ops`.** Onboard `ops$(date +%H%M)` (a fresh user, as in Plan 3b), with the lab stand-in enrolment.
  - **The POSIX password is generated on aero** (`python3 -c 'import secrets…'`) into `~/idm-lab-secrets/iso4_ops.pw` (0600). It is sent to the server through a variant of `rs.sh` that reads the second secret from that file (`rsx.sh`, stdin only).
  - Then check:
    1. **SSH certificate + Kanidm password:** `ssh-ki.exp` to `iso4-cli1` and `iso4-cli2` gives `LOGIN_OK <user>` on both.
    2. **Without the certificate** (key only, no CA cert), the login is refused.
    3. **A user outside `chp_users`** (onboarded, then `revoke <user> --group chp_users`) is refused on both clients **within 30 s** (the fan-out, not the ~2 min cache).
    4. **revoke:** `chp-site revoke <user>` exits **0** with `ok iso4-cli1` and `ok iso4-cli2` in its cache report (the fan-out reached both clients). `ssh-ki.exp` is then refused on both **within 30 s**.
    5. **unexpire** (ISSO) + `onboard <user> --ssh-key …` (re-register the key and issue a new certificate) → `LOGIN_OK` again.
    6. **Admins' sudo on the server:** a second user onboarded with `--group chp_admins` logs in to the **server** (`LOGIN_OK`) and runs `sudo -S true` with its Kanidm POSIX password (stdin) → exit 0. `LOGIN_REFUSED` for a `chp_users`-only user on the server.
    7. **diag (from aero, with `iso4_diag_ecdsa`):**
       - `ssh diag@<client> 'sudo -n /usr/sbin/idm-collect'` → a JSON report with `"schema":"idm-report/1"`
       - `… --user <user>` also returns a report
       - `ssh diag@<client> bash` → refused
       - `ssh diag@<client> 'idm-collect --user x;id'` → refused
       - from the server IP (`V ssh -i … diag@…`), the key is refused by `from=`
    8. **chpcache from anywhere but the server** (aero) → refused by `from=`.
    9. **`chpadmin` still logs in with its key alone** on every host (break-glass).
    10. AVC 0 and fapolicyd 0 on all three hosts.
- [ ] **Step 5: Negative trust check (Review Focus 1)** on `iso4-cli2`:
  - Move the anchor aside and put a wrong `CA_ROOT_SHA256` in `/etc/chp/client.conf`.
  - Run `client-enrol --step trust` → exit ≠ 0, the journal says `refusing: step-ca … did not serve a root matching the pinned`, and **no anchor file** exists.
  - Restore the original `client.conf` and run `client-enrol --step trust` again → the anchor is back and its SHA-256 matches.
- [ ] **Step 6: `cleanup`.** Remove all three VMs, the stick, the helpers and the lab password file.
- [ ] **Step 7: Records.**
  - Write `lab/iso4/PROOF-RECORD.md`.
  - Update `lab/iso-requirements.md`: evidence for rows 5, 6, 7, 8, 9, 10, 12, 21, 22, 25, 27, 29, 31, 35, 39. Correct row 39's path to `/usr/sbin/kanidm-unix`, and add row **41**: per-client unixd tokens, and what cutting off a lost client takes.
  - Run the whole suite and the pre-publication secrets scan of the branch diff.
  - Commit: `git commit -m "ISO Plan 4a Task 9: client role proven — server + 2 clients from repo 0.4.0 (pinned trust, cert+password SSH, fan-out revoke, diag forced command)"`.

---

## Self-review (done while writing)

- **Spec coverage (§7):**
  - enrolment with the pinned root (row 31) → Tasks 3, 9
  - `TrustedUserCAKeys` drop-in pinned by fingerprint (row 35) → Tasks 3, 4, 6
  - unixd → `KANIDM_URL` → Task 3
  - nsswitch (row 6), authselect with pinned features and a jump-safe `pam_kanidm` (rows 7, 8, 27) → Task 3 (the patcher and its property test come from the lab)
  - sshd methods (row 10) + the `Match` exceptions (#22, decision 4) → Tasks 4, 5
  - collector account + pinned key + sudo (#22, decision 3) → Task 4
  - SELinux `chp_kanidm` (#12) → Task 6. **`chp_ga` is 4b.**
  - monitors from §5.4: `authselect check` (27), `sshd -T` (35), TLS from clients (29) → Task 6. The others already exist in `chp-base` / the server.
- **Moved to 4b** (decision 1): `pam_google_authenticator` on sshd/login/sudo/gdm, `/var/lib/google-authenticator` + `chp_ga`, GDM + row 36, the GA enrolment workflow.
- **Plan 5** covers acceptance: regression 33/33, the CUI scan and the deviation table (including the `chpadmin` key-only exception).
- **Type consistency:**
  - `values(site, hosts, client)` is used by `chp-site get` (Task 1), `client-enrol` (Task 3) and `client-accounts` (Task 4)
  - token paths are the same in Tasks 1, 2, 7 and 9
  - the service account name `unixd-<host>` is the same in Tasks 2 and 7
  - the login groups `chp_users` / `chp_admins` are the same in Tasks 2, 3, 4, 7 and 9
- **Assumptions verified in the proof (not assumed):**
  - `step-cli ca root --fingerprint` refuses a mismatching root (Task 9 Step 5)
  - the `Match` placement (Task 5)
  - `pam_kanidm` answers the keyboard-interactive step with the POSIX password under the CUI profile (Task 9 Step 4)
  - `semanage` works in the Anaconda `%post` chroot (Task 9 Step 3: the module is loaded on installed clients)
