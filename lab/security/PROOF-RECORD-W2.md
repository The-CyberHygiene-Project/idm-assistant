# Proof record: security bundle Plan W2 (Wazuh in ISO 0.3.0) on the iso5 lab

Repo **0.7.9** (signed 2026-10-30, 17 packages: `chp-site-0.9.0-2`, `chp-identity-server-0.1.2`,
`chp-identity-client-0.2.4`, `chp-integrity-0.1.7`, `chp-security-0.1.0`, Wazuh 4.14.9 manager and agent, plus the 0.7.8
set). ISO **0.3.0-rc2** (`check-iso.sh`: ISO OK; Secure Boot chain unchanged from the Rocky 9.8 DVD). The installs
replaced the previous iso5 VMs and golden snapshots (owner choice, 2026-10-29).

## Proof 4 (off): `SECURITY_ADDONS=no`, server only (ISO 0.3.0-rc1, 2026-10-29)

prove.sh `prep`, `server`, `firstboot` (all existing checks PASS, incl. "SELinux no AVC since boot"), then `wazuh-off`:

| Check | Result |
|---|---|
| Wazuh / chp-security packages | none installed |
| `/var/lib/chp/repo` | empty (no repo copied) |
| `security` first-boot step | ran and did nothing (marker present; no `/var/ossec`, no `security.conf`) |
| pending `wazuh/` keys | none |
| package set | 1232 packages; the kickstart's `%packages` is unchanged from 0.2.0 (only two conditional `%post` blocks were added) |

## Proof 4 (on): `SECURITY_ADDONS=yes`, all three hosts (ISO 0.3.0-rc2, 2026-10-30)

prove.sh `prep`, `server`, `firstboot`, `export`, `client1`, `client2` (all PASS), then `wazuh-on`:

| Check | Result |
|---|---|
| Agents (`agent_control -l`) | **both Active** (the first run caught iso5-cli2 seconds after its TPM-test reboot: rebooted 09:04:56, reconnected 09:05:07; both agents had first connected during first boot, 08:48 and 09:02) |
| Pending `wazuh/` folder on the server | empty after `export-client` (keys moved to the stick with read-back, then shredded) |
| Default API logins (`wazuh`, `wazuh-wui`) | **401** for both |
| Server listeners | `0.0.0.0:1514`, `127.0.0.1:55000`; no 1515 |
| `update_check` | `no` |
| "No such tag" warnings, every host | **0** |
| Data directory | `/srv/wazuh` bind-mounted at `/var/ossec` on every host |
| `security` first-boot step | done on every host (the server also has its self-client marker, whose step does nothing) |
| SELinux denials (Wazuh) / fapolicyd denials | **0 / 0** on every host |
| **AIDE**: the first daily check after the first-boot baseline | **no Wazuh path** on any host (the baseline already contains Wazuh) |
| Clients: staged `agent.key` | shredded |
| Clients: agent upgrade module | never started |
| USBGuard | allow events only from `export-client` |

**Found and fixed during proof 4** (ledger, Task 5): on rc1 the first daily AIDE check reported Wazuh paths. On the
clients, `etc/shared/{agent.conf,ar.conf,merged.mg}` arrive with the agent's first sync, which came after the baseline.
On the server, `etc/shared/ar.conf` is rewritten unchanged at each start (timestamps only). Fixes:
- chp-integrity 0.1.7: `/var/ossec/etc/shared` is checked by content and permissions (`CHPSHARED`);
- chp-site 0.9.0-2: a client's first boot waits (at most 2 minutes) for the first sync.

rc2 is clean.

## Proof 5: CUI scan (`scan` stage, 2026-10-30)

**108 pass / 2 fail on every host, identical rule by rule to 0.2.0**: `aide_periodic_cron_checking` and
`aide_scan_notification`, both accepted by the ISSO as met by equivalent means. `deviations.py`: **Gate 3 met**. The
Wazuh FIPS and unconfined POA&M items are recorded in `lab/iso5/DEVIATIONS.md` ("Known limits outside the scan").

## Proof 6: resources and catch (pending: 24 h)
