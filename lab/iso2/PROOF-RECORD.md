# ISO Plan 2 install proof: record

**Date:** 2026-09-30 · **On:** aero (KVM; VMs on `br-lab`; UEFI Secure Boot with enrolled keys + vTPM, as client1)
**Versions:** chp-site 0.1.0 (Python 3.9 in the installer and on the hosts), repo 0.2.0 (8 packages, signed), Rocky 9.8 DVD
**Harness:** `lab/iso2/prove.sh` (stages), `install.sh`, `stick.sh`, `unlock.sh`, `luks-send.exp`, `rootcheck.exp`
**Test site:** `iso2.lab.test`, `192.168.100.0/24`; the admin key is `~/idm-lab-secrets/iso2_chpadmin` (ECDSA P-384, never committed)

## Results: every stage PASS

| Stage | Checks | Result |
|---|---|---|
| prep | `chp-site validate` on the Mac; an ed25519 admin key is refused (FIPS); OEMDRV stick image built | 3/3 PASS |
| neg1: MAC not in the table | stops in `%pre` naming the machine's MAC; **disk untouched**; no escrow | 3/3 PASS |
| server `iso2-srv` | the 17 host checks below | 17/17 PASS |
| export | `export-client` from srv1's public CA files → `client.conf` validates; stick keeps the server escrow | 3/3 PASS |
| neg2: two disks, none named | stops in `%pre` ("name one in the hosts table"); **both disks untouched**; no escrow | 3/3 PASS |
| client `iso2-cli` | the host checks plus `client.conf` equal to the stick's | 18/18 PASS |
| reinstall `iso2-srv` | install + unlock; previous escrow kept as `.old`; new passphrase differs | 4/4 PASS |
| cleanup | no `iso2` VMs or disks; stick, helpers and key copy removed; render dir shredded | PASS |

Host checks (server and client):
- the escrowed LUKS passphrase unlocks the disk at first boot (no TPM binding yet; that is Plans 3/4)
- `chpadmin` logs in with the site key only
- FQDN; static IP on the NIC matched by MAC
- FIPS enabled; SELinux Enforcing; root on LUKS2
- `/etc/chp` site files are 0644; **no escrow anywhere on the host**; `client.conf` only on the client
- `chp-site` comes from our signed RPM and runs under the host's python3 with fapolicyd enforcing; `chp-site validate /etc/chp` passes
- `su -` works with the escrowed root console password; root has a SHA-512 hash
- **the LUKS passphrase value is nowhere on disk** (`/root /var/log /etc /var/lib /home`; row 16)
- the CUI profile was applied at install (`/root/openscap_data`)

Install time: about 12 minutes per host (graphical-server + CUI, local repo).

## Findings (how the proof differs from the plan's assumptions)

1. **Files injected into the initrd are gone after switch_root**, so `--initrd-inject chp-site.pyz` cannot deliver the tool. The
   lab kickstart instead prepends a `%pre` that writes `/tmp/chp-site.pyz`, and the committed kickstart looks there first, then at
   the ISO path `/run/install/repo/chp/chp-site.pyz` (Plan 5).
2. **The installer image has no `base64` command** (exit 127, found by tracing to the console). The lab `%pre` decodes with python3.
3. **fapolicyd blocks any access to an untrusted file whose content type is a scripting language**, even reading it. A zipapp
   with a python shebang is such a file, so `chp-site.pyz` has **no shebang** (it is a plain zip) and `/usr/bin/chp-site` is a
   shell wrapper. The RPM builds on aero with fapolicyd enforcing, and the tool runs on hosts with fapolicyd enforcing.
4. **"Disk untouched" needs care:**
   - libvirt preallocates qcow2 metadata: about 255 MB actual size and 242 "data" extents on a fresh 120 GB disk
   - `qemu-img dd` cannot seek to the end of a 120 GB disk
   - The check is therefore `qemu-io read -P 0` on the first and last MiB (where a partition table and its GPT backup
     would be). It was validated both ways: a fresh disk gives 0 failures; one 4 KB write near the end gives 1.
5. **`virsh undefine --remove-all-storage` also deleted the attached stick image.** VMs are now removed with their own disks only.
6. **The LUKS prompt is not the last console line** (kernel messages follow it). `unlock.sh` sends only when a prompt is
   pending: the prompt was seen since the last boot, with no login and no unlock after it.
7. **Anaconda installs with signature checks off** (`gpgcheck = 0`, `repo_gpgcheck = 0` in `packaging.log`), so packages from the
   `chp` repo were **not** checked against our key during installation. The installed hosts enforce signatures from then on (`chp.repo`:
   `gpgcheck=1`, `repo_gpgcheck=1`). **New requirement (row 37), for Plan 5:** the kickstart `%pre` verifies the ISO repo's
   `repomd.xml.asc` against the pinned key before anything is installed, which covers every package through the metadata checksums.
8. **A search for the words `--passphrase=` hit OpenSCAP's own rule documentation** in `/root/openscap_data` (harmless example
   text). The row-16 check now searches for the passphrase **value**, sent through stdin to `read` inside the `su` session.
