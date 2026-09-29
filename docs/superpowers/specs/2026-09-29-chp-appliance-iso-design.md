# CHP Identity Appliance Installer ISO

**Date:** 2026-09-29 · **Status:** DRAFT: design approved in conversation 2026-09-29, awaiting the user's review of this written spec
**Owner:** D. Shannon (System Owner / ISSO)
**Inputs:** `lab/iso-requirements.md` (rows 1–35 from Plans 2–7, row 36 added here);
ADR 0001 *Replace FreeIPA with four independent identity components*; the lab spec
`2026-09-26-idm-diagnostic-lab-design.md`

## 1. Purpose

Turn what the aero lab proved into a **reusable installer** for the CyberHygiene identity
stack (Kanidm, step-ca, SSH CA, standalone BIND): one ISO that installs either an
**identity server** or a **client workstation**, hardened to the CUI profile, with every
lab finding built in as a default rather than a runbook step.

It is an **appliance**: nothing site-specific is baked in. RS#3 (dc2 /
cyberappliance.tech, Jeff) is the first intended user, not the only one.

**Audience during development:** the CyberHygiene Project development team only. It is not
a public release (§8).

### Success criteria (acceptance gates)
1. **Install from nothing on aero:** 1 server + 2 clients from the ISO and a site USB, with no
   console typing beyond choosing the boot entry.
2. **Lab regression 33/33:** the existing 11 scenarios (L1–L6, L3n, C1–C4) run GREEN ×3
   against the installed hosts, plus the new **gdm-password** check (row 36).
3. **CUI compliance scan:** OpenSCAP CUI profile on each installed host; every failure is
   either fixed or listed in a deviation table with the ISSO decision behind it.

Not gates for this project (recorded so that nobody assumes otherwise): a real-hardware install
(physical UEFI/TPM PCRs), and a separate signature-chain test. Row 1's `gpgcheck=1` is
still a build requirement.

## 2. Decisions settled during design (2026-09-29)

| Topic | Decision |
|---|---|
| Scope | Reusable appliance; one ISO; **server and client roles**, chosen by boot entry |
| Site values | Site file on a USB stick labelled `OEMDRV`: `site.conf` + a **MAC-keyed host table** |
| Desktop | **Server with GUI on both roles** (`graphical-server`, graphical target) |
| Approach | **Config RPMs + thin kickstart + first-boot one-shot units** (not a fat `%post`, not Ansible) |
| Distribution | Prebuilt, signed ISO on the Synology share **For Jeff** during development |
| Signing key | Dedicated project GPG key **on a YubiKey the owner holds** (non-exportable) |
| ISSO #12 SELinux | Ship the proven policy as two modules, **`chp_kanidm`** (unixd socket contexts, `nsswitch_domain` only) and **`chp_ga`** (token paths); unixd stays unconfined → **POA&M**; full confinement is a follow-on project |
| ISSO #14 FIPS | Kanidm server **and** unixd built with the **AWS-LC FIPS TLS variant**; Argon2 / TOTP app crypto documented as a **POA&M item (3.13.11)**; CMVP status of every module verified, not assumed (§9) |
| ISSO #20 CHP kit | **Not a dependency.** Hardening = kickstart OpenSCAP CUI profile + tailoring + role RPMs. The kit (with `CHP_IDENTITY=kanidm` and the K1–K6 fixes) remains a separate, optional tool |
| ISSO #22 Collector | `diag` account, **SSH key only** via an sshd `Match` exception to row 10; key pinned `from=<collector IP>`, `command="sudo -n /usr/bin/idm-collect"`, `no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`; sudoers allows **exactly** that command with no arguments |
| ISSO #28 Cache | Keep the unixd default (~2 min revocation delay, measured); document it in the SSP; `chp-site revoke` invalidates the cache on every client (the proven ~14 s repair) |
| ISSO #30 Time | Keep CUI `makestep 1.0 3` (slew, no silent steps on a running host); **alert when offset > 30 s**; chronyd restart after any image restore (row 18) |
| ISSO #32 Unexpire | Only the **ISSO or a delegate named in `site.conf`** approves; `chp-site unexpire` requires approver + reason and logs them; never an automated repair |

## 3. Architecture

```
 build host (aero)                      site
 ─────────────────                      ────
 Rocky 9 DVD (verified) ─┐
 specs + vendored crates ├─► builder VM ─► RPMs ─► YubiKey sign ─► signed repo
 (repo)                  ┘                                          │
                                       mkksiso ◄── kickstarts ──────┤
                                          │                         │
                                          ▼                         │
                              chp-appliance.iso ──► For Jeff share  │
                                                                    │
  OEMDRV USB: site.conf + hosts table ──► boot "Install identity server"
                                            │  %pre: chp-site validate (before disks)
                                            ▼
                                         server first boot: Kanidm domain, step-ca,
                                         SSH CA, collector account, clevis, shred ks
                                            │
                          chp-site export-client ──► client values back to the USB
                                            │
  same ISO + USB ──► boot "Install client" ─► client first boot: pinned trust, unixd,
                                              authselect, GA, sshd, clevis, shred ks
```

### 3.1 Units

| Unit | One job | Depends on |
|---|---|---|
| `kanidm` RPMs (server, unixd, tools) | Kanidm 1.11.x, FIPS TLS variant | vendored crates; `lab/kanidm-rpm` (Plan 2) |
| `step-ca` RPM | step-ca + `step` CLI, unit with `GODEBUG=fips140=on` | vendored Go modules |
| `idm-collect` RPM | the collector + redaction rules (rows 21, 23) | none (shell) |
| `chp-site` RPM | site file validate / host lookup / export / onboarding / revoke / unexpire | none; also runs on macOS/Linux admin boxes |
| `chp-identity-server` RPM | server config files, first-boot units, monitoring timers, `chp_kanidm` policy | kanidm, step-ca, bind, chp-site |
| `chp-identity-client` RPM | client config, enrolment first-boot unit, authselect profile, GA/sshd, `chp_kanidm` + `chp_ga` policy, diag account | kanidm-unixd, idm-collect, chp-site, google-authenticator |
| kickstarts (`server.ks`, `client.ks`) | disks, packages, OEMDRV copy, `%pre` gate. No configuration logic | chp-site |
| `build-iso.sh` | verified inputs → signed repo → ISO → checksums | lorax (`mkksiso`), createrepo_c, rpm-sign, gpg |

Every configuration file is **owned by an RPM**. Three things follow from that: fapolicyd trusts them (row 1), `rpm -V`
and the drift monitors have a reference, and a site takes fixes through `dnf` without
reinstalling.

## 4. Site file (`chp-site`)

### 4.1 Format
Plain `KEY=value` lines (no shell evaluation: parsed by a strict reader; every key has a
type and a pattern). Two parts:

- **`site.conf`**: `DOMAIN` (DNS domain; the Kanidm domain is derived as `idm.<DOMAIN>`),
  `SUBNET`, `GATEWAY`, `DNS_FORWARDERS`, `NTP_UPSTREAM`, `ISSO_NAME`, `UNEXPIRE_DELEGATES`,
  `COLLECTOR_IP`, `ACCESSIBILITY` (`off` default | `on`: GNOME zoom and large text allowed and
  pre-configured), `ALERT_HOOK` (script path; default logs only). **`site.conf` holds no
  secrets.**
- **`hosts`**: one line per host: `MAC  hostname  IP  role(server|client)`.
- **`client.conf`**: written by the server (§4.3), never by hand: `CA_ROOT_SHA256`,
  `SSH_CA_PUBKEY`, `SSH_CA_FPR`, `KANIDM_URL`.

### 4.2 Validation (`chp-site validate`)
Runs in kickstart `%pre` **before any disk is touched**, and on an admin's Mac or Linux box
beforehand. It fails the install with a readable message on: a malformed or unknown key, IP outside `SUBNET`,
duplicate MAC/hostname/IP, not exactly one `server`, the booting host's MAC absent from
`hosts`, role mismatch with the chosen boot entry, and for clients a missing or
inconsistent `client.conf`. There are **no console prompts**: a one-way-door value (the
domain) is never typed at a console.

### 4.3 Export (`chp-site export-client`)
Run by the admin on the server after first boot; writes `client.conf` to the mounted
OEMDRV stick, reading the values from the live services (not from files an attacker could
pre-seed), and prints the fingerprints for a human to compare.

### 4.4 Operations
- `chp-site onboard <user>`: checklist: primary credential, **POSIX password set** (row 25),
  GA enrolled per host, SSH public key registered with the SSH CA (row 34).
- `chp-site revoke <user|group>`: Kanidm change + unixd cache invalidation on every client (#28).
- `chp-site unexpire <user> --approver <name> --reason <text>`: refused unless the approver
  is `ISSO_NAME` or in `UNEXPIRE_DELEGATES`; logged to the audit log (#32).

## 5. Both roles (kickstart + common RPM content)

### 5.1 Kickstart (thin)
- Environment `graphical-server`; boot to graphical target.
- UEFI; LUKS2 root with swap inside (row 15). `%pre` generates a **random per-host LUKS
  recovery passphrase** and writes it to the stick as `escrow/<hostname>.luks`. It is the
  recovery path when the TPM refuses (firmware / Secure Boot change, row 17). From then on
  **the site stick is a secret**: it is stored offline like the initial admin secrets and never
  copied to a network share. `/root/original-ks.cfg` is shredded after the clevis bind (row 16).
- OpenSCAP CUI profile + the site tailoring (from `lab/kickstart/dc2-reference`), FIPS on.
- Repos: the in-ISO signed repo only, `gpgcheck=1` and `repo_gpgcheck=1` (row 1); no compilers (row 2).
- `%pre`: `chp-site validate`. `%post`: copy `site.conf`/`hosts`/`client.conf` to
  `/etc/chp/` (0644, row 5), enable the role's first-boot unit. **Nothing else.**

### 5.2 First-boot units (both roles)
Each is a `ConditionPathExists=!/var/lib/chp/<step>.done` one-shot, so it runs exactly once.
Each writes a line to the journal and to `/var/log/chp-firstboot.log`.
- `chp-clevis-bind`: bind TPM2 PCR 7 **on the first real boot** (row 15), then shred
  `original-ks.cfg` (row 16). If there's no TPM, or Secure Boot is off, it logs loudly and leaves the
  passphrase in place. It never fails the boot.
- `chp-restorecon`: `restorecon -R` over the identity paths (row 33).
- chronyd: CUI `makestep 1.0 3` kept; offset monitor alerts > 30 s (#30).

### 5.3 GUI and login
GDM with the CUI rules (banner, lock, idle timeout, no user list, no auto-login). On
`gdm-password`, `login`, `sshd` and `sudo`: `pam_kanidm` + `pam_google_authenticator`
(no `nullok`). GA tokens live at `/var/lib/google-authenticator/<user>`, labelled
`auth_home_t` (row 11). This fixes the dc1 failure where gdm (`xdm_t`) could not write
`~/.google_authenticator`. **Row 36** (new): a scripted PAM test of the `gdm-password` stack
(Kanidm password + GA code, then the token file's label) joins the regression.

### 5.4 Monitoring (timers → journal + alert hook)
Kanidm certificate lifetime and `cert-renew-kanidm.timer` state (row 24), `authselect
check` (row 27), `restorecon -n` over identity paths (row 33), `sshd -T` vs the owned
drop-in (row 35), Kanidm TLS reachability from clients (row 29), clock offset (#30), and on
the server, **the initial-secrets file still existing** (§6.2). The alert hook is a
script path in `site.conf`; the default only logs.

## 6. Server role (`chp-identity-server`)

### 6.1 Services
- **BIND** (standalone): zone generated from `site.conf` + `hosts`.
- **step-ca**: `GODEBUG=fips140=on` (row 13); issues Kanidm's TLS certificate by ACME;
  renewal timer with **ACME re-issue fallback** when the certificate has already expired (row 26).
- **Kanidm server**: `server.toml` 0644 (row 3); TLS key via root pre-start copy into the
  RuntimeDirectory (row 4); explicit modes on non-secret files (row 5).
- **SSH CA** (P-384): issuance record of every certificate, a registry of each user's
  public key, re-issue signs only the registered key, short validity, **SPN principals**
  (`user@idm.<DOMAIN>`) (rows 9, 34); a self-service renewal path.

### 6.2 First boot (once)
1. Initialise step-ca, then the SSH CA, then the Kanidm domain from `site.conf`. The domain unit
   records the domain it initialised and **refuses to run again if `site.conf`'s domain
   differs**, because Kanidm's domain/origin is a one-way door.
2. Create the `idm-collect` service account in `idm_service_desk` + `idm_unix_admins` with
   a **read-only** token (row 23, residual risk recorded there).
3. Write the `admin` / `idm_admin` recovery secrets to **one root-only file**
   (`/root/chp-initial-secrets`, 0600). The monitor warns until it is gone. The admin moves
   it **offline** (break-glass, dc1 lesson), **never to a network share** (including For Jeff).
4. Common units (§5.2).

**The server is also its own client:** `chp-identity-server` requires
`chp-identity-client`. After step 1 it runs the same enrolment (§7) from locally generated
values, so admins log in to the server with Kanidm identities + GA like anywhere else, and the
local break-glass account remains.

## 7. Client role (`chp-identity-client`)

- **Enrolment (first boot, once, from `client.conf`):** install the step-ca root as the
  single `ca_path` anchor and verify its **pinned SHA-256** (row 31); install the
  `TrustedUserCAKeys` drop-in, key pinned by fingerprint (row 35); point unixd at
  `KANIDM_URL`. A mismatch stops enrolment and logs; it never falls back to trusting what's
  on the wire.
- **nsswitch:** `kanidm` first on `passwd`, `group` **and** `initgroups` (row 6).
- **authselect:** `custom/kanidm` based on the site's CUI profile, feature set pinned
  (`with-faillock`, `without-nullok`), `pam_kanidm` placed where no numeric jump skips it,
  verified after selecting (rows 7, 8, 27).
- **sshd:** `AuthenticationMethods publickey,keyboard-interactive:pam` (row 10), plus the
  `Match User diag` exception (#22).
- **Collector:** `idm-collect` RPM, `diag` account, pinned key and the exact sudo rule (#22).
- **SELinux:** `chp_kanidm` + `chp_ga` modules (#12).

## 8. Build and release

1. **Inputs:** a Rocky 9 DVD verified against Rocky's checksum and signature; specs, vendored
   Rust crates and vendored Go modules from the repo. All offline.
2. **RPM build** in a disposable builder VM on aero (the Plan 2 build1 pattern; fapolicyd
   permissive **there only**). Kanidm is rebuilt as the FIPS TLS variant (#14).
3. **Sign** at release time with the YubiKey on aero: `rpmsign` every package, and sign the repo
   metadata. The public key ships in the ISO and in the release folder.
4. **Assemble:** `createrepo_c`, then `mkksiso` adds the repo, both kickstarts and the two boot
   entries (*Install identity server*, *Install client*). Rocky's signed shim, grub and kernel are
   **not modified**, so Secure Boot keeps working (row 17).
5. **Release** to `/Volumes/For Jeff/chp-appliance/<version>/`: the ISO, `SHA256SUMS`,
   `SHA256SUMS.asc`, the public key, and `VERIFY.md`. Also a signed repo tarball, so RPM fixes
   can be taken without reinstalling.
6. **Cadence:** rebuild for each Rocky 9 point release and for fixes to our RPMs.

**Deferred to any future public release** (open release items, not work in this project):
the Rocky Linux trademark and rebranding requirements for a remastered ISO; public hosting
(the ISO is about 11 GB and GitHub Releases caps each file at 2 GiB); a license review of every
bundled component (Kanidm MPL-2.0, step-ca Apache-2.0, the rest to be listed).

## 9. Verifications the spec requires (not assumed)

- The CMVP certificate status of AWS-LC FIPS 4.2.0 and of the Rocky 9 OpenSSL FIPS provider, as of
  the build date. It goes into the SSP / POA&M text for #14.
- That `mkksiso` preserves Secure Boot on the Rocky 9 point release in use (install in an
  OVMF + Secure Boot VM).
- That Anaconda picks up an `OEMDRV` volume presented as a VM disk (for the lab) and as a
  USB stick.

## 10. Error handling

- Anything wrong in the site file stops the install in `%pre`, before disks are touched.
- A first-boot step that fails leaves its `.done` marker unset, logs the reason, and the host
  still boots to a console where an admin can read `/var/log/chp-firstboot.log`. Re-running
  a step is safe (idempotent), **except** Kanidm domain init, which is guarded (§6.2).
- A trust-pin mismatch on a client stops enrolment: no identity config gets applied, and the host
  stays reachable only through local accounts (break-glass).
- None of the monitors repair anything. Repairs stay with idm-assistant's allow-listed, human-approved
  playbooks.

## 11. Testing

- **Unit and property tests** (pytest + shell, the same style as the existing repo): the site-file
  reader and validator (every rejection above), MAC lookup, the export round-trip, the PAM,
  nsswitch and authselect patchers (property test: no numeric jump skips `pam_kanidm`), and the
  first-boot run-once guards, including refusal when the domain changes.
- **RPM checks:** a file list and modes against expected (the `lab/kanidm-rpm/check-rpms.sh` pattern),
  `rpm -K` on every package, and 0 fapolicyd denials on install.
- **Acceptance** (§1): install from nothing on aero, the regression 33/33 + row 36, and the CUI scan
  with a deviation table.

## 12. Plans (one spec, five plans)

1. **Signing and repo:** YubiKey key setup and custody note; Kanidm FIPS-variant rebuild;
   step-ca and idm-collect RPMs; the signed repo; CMVP verification (§9).
2. **`chp-site` and the kickstarts:** format, reader, validator, host lookup, export, the
   `%pre` gate, onboarding, revoke and unexpire.
3. **Server role RPM:** services config, first-boot units, monitors, `chp_kanidm`.
4. **Client role RPM:** enrolment, nsswitch, authselect, GA, sshd, `chp_ga`, the diag
   exception, the row-36 check.
5. **ISO assembly, acceptance and release:** `build-iso.sh`, install from nothing, the
   regression and CUI scans, the deviation table, then release to For Jeff.

## 13. Out of scope

A public release (§8); full SELinux confinement of unixd (POA&M, follow-on); running the
CHP kit on appliance hosts (#20); real-hardware acceptance; the sysadmin-RAG and
workbench parts of idm-assistant; dc1 (FreeIPA) and RS#2.
