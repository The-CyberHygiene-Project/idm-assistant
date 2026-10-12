# Site-stick kit — proof record (2026-10-12)

**What was proved.** A site stick made ONLY from `appliance/site-stick-kit/` (templates filled the way `SITE-STICK.md`
says, checked with the RELEASED `chp-site.pyz` from repo 0.6.3 / chp-site-0.6.1-1) installs a fresh identity server from
the RELEASED ISO 0.1.0 bytes (sha256 efcba98a…ff81b2), and the guide's steps work as written: unlock first boot with
`LUKS_PASSPHRASE` from the escrow, the first-boot finish check as `chpadmin` (no root), root by `su -` with
`ROOT_CONSOLE_PASSWORD`, `chp-site export-client`, then the client check on the Mac. Nothing in the product changed.

**How.** `lab/kit/prove-kit.sh all` on aero (VM `iso5-kit`, 192.168.100.59, domain `kit.lab.test`; client `iso5-kitc`
listed in `hosts` but not installed), then `prove-kit.sh cleanup` (VM, disk and stick image removed).

**Run 1 — FAIL, found a guide error.** The guide said first boot is finished at `inactive (dead)` with
`status=0/SUCCESS`. Wrong: `inactive (dead)` is *not started yet* (`chp-firstboot-common` runs first); the unit is
`RemainAfterExit=yes`, so finished = `active (exited)` with `status=0/SUCCESS`. The proof moved on before first boot
began, so export ran early and refused (`missing file: /etc/step-ca/certs/root_ca.crt`; nothing written). Guide and
proof corrected (all four states now listed). Product unchanged.

**Run 2 (from scratch) — 17/17 PASS:**

```
PASS unfilled template is refused (DOMAIN is required)
PASS filled kit validates with the RELEASED chp-site
PASS --mac/--role server check as in the guide (OK: kit.lab.test, 2 hosts, server iso5-kit; this machine is iso5-kit (server, 192.168.100.59))
PASS ISO on aero = released 0.1.0 bytes
PASS kit stick made (FAT, OEMDRV, the two files only)
PASS iso5-kit installed from the released ISO with the kit stick
PASS escrow/iso5-kit.txt written with INSTALL COMPLETED
PASS first boot unlocked with LUKS_PASSPHRASE from escrow
PASS guide's finish check (chpadmin, no root):  Active: active (exited) since Mon 2026-10-12 12:23:56 CDT; 9s ago  Process: 2501 ExecStart=/usr/libexec/chp/server-firstboot (code=exited, status=0/SUCCESS)  Main PID: 2501 (code=exited, status=0/SUCCESS) 
PASS first boot marker
  export: moved to the stick: kanidm-admins.json, root_ca_key, step-ca-password (shredded on this server)
  export: tokens moved to the stick: iso5-kitc
PASS export-client (chpadmin + su -) moved the server secrets
PASS export-client moved the listed client's token
PASS stick now holds client.conf, the client token, escrow/iso5-kit-server.txt
PASS server monitor quiet after export
PASS guide's client check passes after export (OK: kit.lab.test, 2 hosts, server iso5-kit; this machine is iso5-kitc (client, 192.168.100.58))
exit=0
```

(The export also printed the SSH CA fingerprint, as the guide says; not recorded here: lab value of a deleted VM.)

**Not proved here:** a client install from the kit stick (the client path is unchanged from ISO 0.1.0 gate 1, 138/138);
real hardware; the `rd.multipath=0` workaround (marked untested in the guide).
**Found for core 0.2.0:** adding a client after the server install is not a supported procedure (`client-token` reads
the server's installed `hosts`; the DNS zone is built from it at install). The guide tells sites to list every client up
front.
