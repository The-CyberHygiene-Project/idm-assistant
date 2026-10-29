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

## Proof 2: catch real events (2026-10-27, lab hook `/usr/local/sbin/lab-hook` → `/var/log/lab-hook.log` on iso5-srv)

| Event | Expected | Seen |
|---|---|---|
| 12 failed SSH logins (invalid users) from iso5-srv to iso5-cli2 | one hook line, level ≥ 10 | `17:19:12 iso5-cli2 rule 5712 level 10: sshd: brute force …` (Wazuh fires 5712 **once per burst**) |
| Two bursts 90 s apart (17:44:34, 17:46:06) | one line, then a grouped summary after 15 min | `17:44:35 … rule 5712 …`; `17:59:36 … (1 more in the last 15 min)` |
| `useradd labprobe` on iso5-cli2 | no hook line (level 8); listed by `chp-site alerts` | none; `chp-site alerts --level 7` lists rule 5902 |
| `systemctl stop wazuh-agent` on iso5-cli2 (17:21:09) | hook line within a minute | `17:21:10 iso5-cli2 rule 506 level 3: Wazuh agent stopped.` |
| Monitor backstop (15-min timer) | agent disconnected or never connected | `17:26:32 Wazuh agent iso5-cli2 (002) is disconnected`, `… iso5-cli1 (001) has never connected`; cleared after the agent restarted |

## Proof 3: quiet check (T0 = 10/27/2026 18:10:25, read 10/28/2026 23:27; about 29 h, lab untouched)

- **Wazuh lines to the hook: 0** (target 0–2). **No tuning needed**; no local-rules file is shipped.
- **One daily summary line:** "8 medium alerts (levels 7-9) on 2 hosts in the last 24 h". These were rule 80717 (level 8, AIDE's
  own `ANOM_RBAC_INTEGRITY_FAIL` audit records from the AIDE checks and accept just before T0; Wazuh relays AIDE's
  findings) plus one rule 533 (level 7, the netstat port list changed, 08:58).
- **Monitor lines (expected, not Wazuh):** iso5-cli1 "never connected" (the deliberate negative case) and "AIDE baseline
  not pinned to the site stick" (the lab accept ran without the stick), each every 15 minutes.
- **Resources after about 30 h:** manager RSS 527 MB, `/srv/wazuh` 1.2 GB (unchanged), host up 1 day 6 h, services active.

**Found and fixed during proofs 2–3** (ledger): `chp-site alerts` double-counted (Wazuh's `alerts.json` is a hard link
to the dated file). AIDE did not count Wazuh-signed packages as explained (Wazuh's key ID was missing from
`PINNED_SIGNERS`; a test now ties that list to `trusted-keys.txt`).

## Re-run after the final-review fixes (2026-10-29, repo 0.7.8 re-signed: chp-site 0.8.0-3, chp-integrity 0.1.6-2)

Fresh golden lab (T0 = 10/29/2026 08:54:40), `prove-w1.sh repo`, `enable srv`, `enable cli2`:

| Check | Result |
|---|---|
| Server `security enable` | all steps as in proof 1, plus **"Wazuh API logins locked (2 default passwords replaced with random ones, not stored)"** |
| Default API logins as non-root `chpadmin` (`wazuh:wazuh`, `wazuh-wui:wazuh-wui`) | **HTTP 401** for both (before the fix both returned an administrator token) |
| `update_check` | `no` |
| "No such tag" warnings (`wazuh-analysisd -t`, `wazuh-modulesd -t`, `wazuh-agentd -t`) | **0** on both hosts (Wazuh's `-t` only warns on unknown tags, so this is the real "setting understood" check) |
| Agent upgrade module | `<agent-upgrade><enabled>no`; **0** "Module Agent Upgrade started" lines (the line appears when the switch is removed) |
| Agents | iso5-cli2 Active; iso5-cli1 Never connected (negative case) |
| AIDE summary (not accepted) | Wazuh files **explained** (wazuh-manager 65 paths, wazuh-agent 5) together with chp-security, chp-site and chp-integrity; the NOT-explained items are the ones listed in `UPDATE-0.2.0-update4.md.in`. client2 also showed lab baseline drift unrelated to Wazuh (`/etc/pki/ca-trust` ×450, `client.conf`, `/usr/libexec/chp`); its first run showed the same |
| Catch (rewritten forwarder) | burst at 09:03:54 → hook `09:03:56 … rule 5712 level 10`; agent stop at 09:04:06 → hook `09:04:06 … rule 506`; the forwarder restart at 09:03:54 re-sent nothing from 09:02 (per-alert checkpoint) |

Lab-side slip (not a product defect): the first catch attempt appended a second `ALERT_HOOK=` to the lab's `site.conf`.
`chp-site get` rightly refused it, and the forwarder then ran with no hook (it logged the alerts). Deferred minor: the
forwarder should log when the hook lookup fails.
