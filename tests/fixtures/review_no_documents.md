# Daily security review 2026-11-06

Built 2026-11-07 00:20. Needs attention: 0. Sources: 287 alerts, records srv1 143, ws1 143.

## 1. Intrusions

| kind | source | inside/outside | site host | target | signature | count | first | last |
|---|---|---|---|---|---|---|---|---|
| suricata | 203.0.113.9 | outside |  | 192.0.2.21 | sig 1 | 1 | 01:06 | 01:06 |

## 2. Security status

| host | item | state | detail | watched by |
|---|---|---|---|---|
| srv1 | record | OK | 143 records; last 0 h ago |  |
| srv1 | repo | OK | repo abc123abc123 |  |
| srv1 | cert /etc/pki/kanidm/chain.pem | OK | 23 h left of 24 h | 30-kanidm-cert |
| srv1 | cert /etc/step-ca/certs/root_ca.crt | OK | 3000 days left |  |
| srv1 | key /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH | OK | 200 days left |  |
| srv1 | yara_recent | OK | last 0 h ago | 73-yara-scan |
| srv1 | yara_full | OK | last 2 days ago | 73-yara-scan |
| srv1 | suricata_stats | OK | last 0 h ago | 74-suricata |
| srv1 | aide_check | OK | last 1 h ago | 61-aide-stale |
| srv1 | aide_ok | OK | accepted, no changes | 60-aide-result |
| srv1 | sysstat | OK | 144 samples |  |
| ws1 | record | OK | 143 records; last seen 23:50 |  |
| ws1 | repo | OK | same as srv1 |  |
| ws1 | cert /etc/pki/kanidm/chain.pem | OK | 23 h left of 24 h | 30-kanidm-cert |
| ws1 | cert /etc/step-ca/certs/root_ca.crt | OK | 3000 days left |  |
| ws1 | key /etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH | OK | 200 days left |  |
| ws1 | yara_recent | OK | last 0 h ago | 73-yara-scan |
| ws1 | yara_full | OK | last 2 days ago | 73-yara-scan |
| ws1 | suricata_stats | OK | last 0 h ago | 74-suricata |
| ws1 | aide_check | OK | last 1 h ago | 61-aide-stale |
| ws1 | aide_ok | OK | accepted, no changes | 60-aide-result |
| ws1 | sysstat | OK | 144 samples |  |

## 3. Resources

| host | CPU % avg / peak | memory % avg / peak | disk peak | net kB/s rx / tx |
|---|---|---|---|---|
| srv1 | 3.2 / 10.0 | 20.3 / 20.3 | / 40% | 6.2 / 80.4 |
| ws1 | 3.2 / 10.0 | 20.3 / 20.3 | / 40% | 6.2 / 80.4 |
