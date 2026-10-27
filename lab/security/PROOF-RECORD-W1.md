# Proof record: security bundle Plan W1 (Wazuh) on the iso5 golden lab

Repo **0.7.8** (signed 2026-10-27; `REPO OK: 17 packages, all signed by pinned keys`): `chp-site-0.8.0-2`,
`chp-integrity-0.1.6`, `chp-security-0.1.0`, and Wazuh's `wazuh-manager-4.14.9-1` and `wazuh-agent-4.14.9-1`, which keep
Wazuh's V3 RSA/SHA-256 signature, key ID `29111145`.

## Proof 1: upgrade a 0.2.0 site and enable (2026-10-27, T0 = 10/27/2026 17:08:23)

Hosts started at rc2 golden. Steps: `lab/security/prove-w1.sh repo`, then `enable srv` and `enable cli2`. Each `enable`
attaches the real site-stick image as a USB disk, so the USBGuard path is exercised, then detaches it.
`iso5-cli1` has no lab-adapter sudo, so it stays **un-enabled on purpose** as the negative case.

| Evidence | Result |
|---|---|
| Upgrade | `chp-site-0.8.0-2`, `chp-integrity-0.1.6` on all hosts |
| Server `security enable` | key verified and imported; `/srv/wazuh` bind-mounted at `/var/ossec`; `wazuh-manager` installed; 2 agent keys made and written to the stick (`wazuh/<host>.key`); firewall 1514/tcp from 2 clients; services started |
| Client `security enable` (iso5-cli2) | key verified; bind mount; `wazuh-agent` installed; started |
| Agents (`agent_control -l`) | iso5-cli2 **Active**; iso5-cli1 **Never connected** (expected) |
| Listening ports (server) | `0.0.0.0:1514`, **`127.0.0.1:55000` only**, **no 1515** |
| Wazuh config tests | `wazuh-analysisd -t` OK (server), `wazuh-agentd -t` OK (client) |
| Vulnerability scanner | 0 starts; data 1.2 GB (server), 28 MB (client) |
| Since T0 | **0** Wazuh SELinux denials and **0** fapolicyd denials on both hosts |
| Firewall rich rules | exactly the two client rules (`192.168.100.51/32`, `.52/32`, port 1514/tcp) |
| Second `security enable` on the server | no new keys; `client.keys`, `fstab` and the rich rules byte-identical before and after |
| Monitor checks | `OK Wazuh services running`; **`ALERT Wazuh agent iso5-cli1 (001) has never connected`**; `OK … 12% full` |
| AIDE | `aide --config-check` OK; `ossec.conf` checked (CHPCONTENT); `client.keys` and `sslmanager.key` excluded (negative rules) |
| Server reboot | `/var/ossec` mounted from `/srv/wazuh`; `wazuh-manager` and `chp-wazuh-alerts` active; iso5-cli2 Active again |

**Found and fixed during the proof** (ledger):
- `verify-repo.sh` accepted only V4 signature packets, so Wazuh's V3 packets were refused; it now accepts V3 from pinned primary keys only (25/25 signing tests pass).
- Wazuh 4.14's API wants `host` as a list; the scalar value stopped `wazuh-apid` and the manager.
- A failed step produced a traceback; it is now a clear message.
