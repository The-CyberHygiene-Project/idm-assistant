# Spike: Suricata under FIPS, ET Open load, resources, clean-day alerts (Plan S1 Task 1, 2026-11-04)

Lab: iso5-srv and iso5-cli2 at the 0.4.0 golden snapshots (FIPS, SELinux enforcing, fapolicyd, USBGuard, Wazuh and
YARA on). Installed by hand with `spike-host.sh` (scratch, not committed); reverted to golden afterwards.

## Package source

- EPEL 9: `suricata-7.0.17-1.el9.x86_64`, plus the EPEL-only dependencies `hiredis-1.0.2-2.el9` and
  `hyperscan-5.4.1-2.el9`. All three "OK signed by EPEL 9" (`verify-epel.sh` on aero); now in `fetch-epel.sh` `PKGS`.
- `libhtp.so.2` is bundled inside the `suricata` package (EPEL has no separate `libhtp`).
- From the Rocky 9.8 DVD (AppStream): `libnetfilter_queue-1.0.5-1.el9` is **not** installed on the appliance hosts and
  must ship in the repo. `libnet`, `libmaxminddb`, `lua-libs`, `jansson`, `libyaml`, `pcre2`, `lz4`, `file-libs`,
  `libpcap`, `libevent`, `libcap-ng` are already present.
- dnf refuses the EPEL RPMs until the EPEL 9 key (`3228467c`) is imported: the repo must pin and ship that key, as
  for Wazuh.
- sha256: suricata `5690e545…0fd10`, hiredis `4131322b…797d7`, hyperscan `fed105e5…ce750`.

## Under FIPS (iso5-cli2 and iso5-srv)

| Check | Result |
|---|---|
| Version / features | 7.0.17; AF_PACKET + fanout, Hyperscan, Lua 5.4, Rust, JA3/JA4, libnet |
| Crypto library | **none**: `readelf -d` NEEDED has no `libcrypto`, `libssl` or `libnss*`. Hashes (JA3 MD5 etc.) are Rust code used only for matching; nothing is protected by them. POA&M note: outside the validated boundary but not a protection function. |
| SELinux domain | `unconfined_service_t` (EPEL ships no Suricata policy; `/usr/sbin/suricata` is `bin_t`). Same as Wazuh. |
| AVCs / fapolicyd denials since start | 0 / 0 |
| Run user | `suricata` (980), created by the package; `/etc/suricata`, `/var/log/suricata`, `/var/lib/suricata` are `suricata:suricata 0750` |
| Unit | `ExecStart=/sbin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid $OPTIONS`; `EnvironmentFile=-/etc/sysconfig/suricata`; stock `OPTIONS="-i eth0 --user suricata "` (wrong interface: hosts have `enp1s0`) |
| Host NIC | `enp1s0`; rx/tx checksum offload on, TSO/GRO off. No invalid-checksum counters, so no `checksum-checks` change needed. |

## Config changes Task 3 must carry (verified with `suricata -T`, then a real start)

1. **Systemd drop-in, not `OPTIONS`.** With the planned `OPTIONS="-c …"`, the process gets **two** `-c` flags (the
   unit's and ours; the later one wins). Works, but fragile. Use
   `/etc/systemd/system/suricata.service.d/chp.conf`: `ExecStart=` (empty) then
   `ExecStart=/sbin/suricata -c /etc/suricata/chp-suricata.yaml --pidfile /var/run/suricata.pid --af-packet=<iface> --user suricata`,
   and write `OPTIONS=""` to `/etc/sysconfig/suricata`. `sysconfig_text()` becomes a `dropin_text(iface)`.
2. **The stock address and port groups are required.** With only `HOME_NET`/`EXTERNAL_NET`, 6,835 of 52,859 rules fail
   (`HTTP_SERVERS` undefined) and loading aborts. Add the stock `HTTP_SERVERS … ENIP_SERVER` (all `$HOME_NET`,
   `AIM_SERVERS: $EXTERNAL_NET`) and the stock `port-groups` (HTTP 80, SHELLCODE !80, ORACLE 1521, SSH 22, DNP3 20000,
   MODBUS 502, FILE_DATA [$HTTP_PORTS,110,143], FTP 21, GENEVE 6081, VXLAN 4789, TEREDO 3544).
3. **A global `stats:` block** (`enabled: yes`, `interval: 60`) or Suricata warns that stats are "legacy".
4. **`tpacket-v3: yes`** under the af-packet interface (warning otherwise).
5. **ET Open has no `reference.config`.** Ship EPEL's `/etc/suricata/reference.config` in `chp-suricata-rules`, or
   point `reference-config-file` at `/etc/suricata/reference.config`. (EPEL's lacks keys `bid`, `bugtraq`, `md5`,
   `mcafee`, `nessus`, `arachnids`: harmless warnings, only for rule references.)
6. **Permissions:** rules-package files must be `0644` (a `0640 root` copy gave "Permission denied" to the `suricata`
   user). Never run `suricata -T` as root with the real log dir before the service starts: it creates root-owned
   `eve.json`/`stats.log` and the service then cannot open them ("eve-log setup failed"). Run the check with
   `--user suricata` or pre-create the files `suricata:suricata`.

## ET Open

- `https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz`, downloaded 2026-11-04 (`ET_DATE`
  `2026.11.04`), sha256 `1fa39a90478f007ad72b485bbab454f47a66dc2542427729f2f0f12f37e0eabb`, 5,651,231 bytes; 54 rule files.
- Merged: 52,859 active rules (19,507 more are commented out by ET). With the changes above: **52,859 loaded, 0 failed,
  0 warnings**; 1,253 IP-only, 4,525 payload, 47,034 application-layer.
- `suricata -T`: 17.5 s, peak RSS 512 MB.

## Resources (at start, both hosts)

| Host | RSS | CPU (first minute, rule compile) |
|---|---|---|
| iso5-cli2 | 490 MB | 34 % |
| iso5-srv | 513 MB | 38 % |

Below the 1.5 GB stop rule. Steady-state figures: see the clean day below.

## Catch test

- Rule 2100498 ("GPL ATTACK_RESPONSE id check returned root") is classtype `bad-unknown` = **priority 2** → level 7
  (daily summary), so it does not prove the level-12 path.
- **Use rule 2017025** ("ET ATTACK_RESPONSE Net User Command Response"): `tcp any any -> any any`, `flow:established`,
  `content:"User accounts for |5C 5C|"` then 79 dashes, classtype `successful-user` = **priority 1**. It needs no
  `EXTERNAL_NET` (the whole lab is `HOME_NET`).
- It must go to a server that **acknowledges** the bytes: a stream rule is inspected on reassembled, acknowledged data.
  Sent to Kanidm 443 (which resets non-TLS input): no alert. Sent to named on TCP 53: alert, severity 1, on both
  hosts. sshd 22 is unsuitable (PerSourcePenalties: a stalled test connection earns "Not allowed at this time").
- Sender (from cli2): open `/dev/tcp/<srv>/53`, write
  `User accounts for \\LAB\r\n\r\n` + 79 `-` + `\r\nchp lab catch test\r\n`, wait 2 s, close.
- Test alerts at 16:15:52 (2100498) and 16:16:16 (2017025) are excluded from the clean day.

## Clean day

- T0 **11/04/2026 16:09:40** (srv), 16:09:35 (cli2); end ≥ 20:10.
- **Deviation from Step 5:** no regression scenario inside the window, because the engine resets both hosts to golden
  before every scenario, which removes the hand-installed Suricata. Scenario traffic is covered by Task 6's regression
  gate, which runs with Suricata enabled by the product.
- Read 11/05/2026 08:08, so the window ran about **15 h 58 m** (overnight; longer than the planned 4 h).
- Results:

| | iso5-srv | iso5-cli2 |
|---|---|---|
| Alerts in `eve.json` outside the test window (16:15–16:20) | **0** | **0** |
| Packets seen / kernel drops | 84,961 / 0 | 71,001 / 0 |
| RSS at the end (`MemoryPeak`) | 532 MB (533 MB) | 513 MB (513 MB) |
| CPU over the window | 6 min 27 s total (0.6 % average) | 9 min 9 s total (0.9 % average) |
| AVCs / fapolicyd denials since 16:00 | 0 / 0 | 0 / 0 |
| `suricata.log` warnings or errors | none (two Notice lines only) | none |

- Memory stayed flat after rule compile (start 513/490 MB → end 532/513 MB): no growth. Host memory 3.8 GB with
  2.3–2.7 GB available.
- **Correction to the catch-test record:** `eve.json` holds **three** test alerts, all cli2 (.52) → srv (.50):
  16:15:52 2100498 → 443, 16:16:16 2017025 → 53, and **16:19:54 2017025 → 443**. So a send to Kanidm 443 did alert
  once; 443 is unreliable (Kanidm resets non-TLS input, so whether the bytes are acknowledged is a race), not
  impossible. Named on TCP 53 stays the catch target. All three are excluded above.
- The verified running config is kept in `spike-suricata/` (`chp-suricata.yaml`, the drop-in and sysconfig), copied
  from iso5-srv before the reset. The scratch scripts (`spike-host.sh`, `catch.sh`, `alerts.py`) were lost when the Mac
  rebooted; Task 3 and Task 5 rebuild them from the notes above.
