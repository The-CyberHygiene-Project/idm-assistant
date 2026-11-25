# Proof record: ISO 0.7.0-rc1 (fresh install on the iso5 lab)

**Ruling (controller, 2026-11-24):** ISO 0.7.0 ships on the already-signed repo **0.14.1** as is; no new packages.

- **ISO:** `aero:/var/lib/libvirt/images/chp-iso/0.7.0-rc1/cyberhygiene-lab-installer-el9.iso`, 16,621,551,616 bytes,
  **sha256 `eed5f77eeec452b9723f1017996355900afa08ee83a8d922405db2b808aa9f17`**. Built by `build-iso.sh 0.14.1
  0.7.0-rc1` after `appliance/iso/push.sh` (repo 0.14.1: REPO OK 72, signed by 2DE0D71BF37D8F5E4201A590521276F43C908F8E).
  Not signed, not released.
- **Logs:** `lab/security/iso-0.7.0-logs/`. Scan results: `lab/security/iso-0.7.0-scan-results/`.

| Gate / proof | Result | Log |
|---|---|---|
| `check-iso.sh` | **ISO OK**: volume ID, El Torito EFI + GPT boot records, Secure Boot chain byte-identical to the DVD (ISO and efiboot.img), our menus, /chp repo verifies, `chp-site verify-repo` accepts it | `rc1-build.log`, `rc1-check-iso.log` |
| Fresh install FROM the ISO: prep, server (1863 GiB sparse, 8 GiB, guard 50), firstboot, export, client1 (120), client2 (512, guard 50), wazuh-on (`SECURITY_ADDONS=yes`) | **ALL PASS** (wazuh-on after a 90 s settle, the known reconnect race) | `rc1-install-chain.log` |
| Installed state | chp-site 0.14.0-12, chp-base 0.1.0-14, chp-identity-client 0.2.4-6 (+ chp-identity-server 0.1.2-8 on srv), chp-security 0.4.1-1; time from first boot: the server serves 192.168.100.50:123 only, both workstations `^*` the server; server journal persistent; SELinux Enforcing, 0 fapolicyd denials on all three | `rc1-hosts.log` |
| **D1: first-ever `documents enable`** on the never-installed server | **PASS in one run** (exit 0; NextCloud installed offline, config.php trusted first; fapolicyd restarted, active 5 s, Denied 0; **0 FANOTIFY denials of php on config.php**) | `rc1-d1-documents-enable-1.log` |
| `onlyoffice enable` on both fresh workstations | **PASS**: Install 11 (chp-templates pulled in: D2 proven fresh), AI Tools absent, egress table, check 83 OK | `rc1-onlyoffice-enable.log` |
| AIDE accept x3 | accepted and pinned | `rc1-aide-accept.log` |
| **Gate 3: CUI scan** | **srv 107/3, cli1 108/2, cli2 108/2**; no rule changed vs Plan 3 round 3; `deviations.py` rc 0, **MET** (the owner-confirmed `chronyd_client_only` row) | `rc1-scan.log`, `rc1-deviations.log` |
| adapter, nvram, snapspike, fixtures | **ALL PASS**, `FIXTURES OK` | `rc1-adapter-nvram-snapspike.log`, `rc1-fixtures.log` |
| Approvers + enable 2 | ISSO lab01, approver lab04 (checked in Kanidm); exit 0 | `rc1-docs-setup.log` |
| **Workflow end to end, CUI and FCI** | `CUI_Policy2`: new → approve (lab04) → publish CR-2026-0001, then checkout → approve → publish CR-2026-0002 (v0.1 to Archive/Superseded); `FCI_Quote2` likewise CR-2026-0003/0004; reader PDFs banner "CUI" / "FCI" first and last. (A first attempt failed only in the lab driver: `CUI/Drafts/lab01` did not exist on the fresh server, so the hand-off upload got 404; it leaves two harmless open "new" cycles, CUI_Policy and FCI_Quote, in the ledger.) | `rc1-workflow-e2e.log` |
| Golden | **ALL PASS** (reset + 0 engine findings) | `rc1-golden.log` |
| **Gate 2: row 36** | **3/3** | `rc1-row36.log` |
| **Gate 2: regression** | **33/33 in one pass** (11 scenarios x 3 GREEN; model `devstral-small-2-2512` 33/33 valid, 33/33 agreeing; c4 3/3); LM Studio started by the controller; lab reset to golden afterwards - `lab/iso5/regression-2026-11-24.md` | `rc1-regress.log` |

## Lab residue (recorded, not removed)

The first workflow attempt left two open `new` cycles in the lab ledger (ledger entries 1 and 2: `CUI_Policy` and
`FCI_Quote`, created, never approved or published). The ledger is append-only and hash-chained by design, so they are
not removed; they only block a later `doc new` of those two names on this throwaway lab (use `doc checkout`-free new
names). `doc-ledger verify` is unaffected.

## Defects

None found in rc1. The open known issues stay Plan 4 carries (P3-D16, P3-D6: `lab/docs-proof/PROOF-RECORD-PLAN3.md`).

## Fault injection

None in this proof (fresh install only). Lab-only state: the lab adapter and fixtures (as every ISO proof); cli2's lab
sessions were ended and /tmp is clean (`rc1-cleanup.log`).
