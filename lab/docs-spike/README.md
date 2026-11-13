# docs spike: rebuild it

ISO 0.7.0 Plan 1 Task 1 (throwaway). Findings: `SPIKE-NEXTCLOUD.md`. Everything runs from the Mac.

**Site.** A site has exactly one server (`chp_site/hosts.py`), so the spike is its own lab site, `docs.lab.test`
(`hosts`, `site.conf.in`, `SECURITY_ADDONS=yes`): `iso5-docs` (server, 192.168.100.53, 1863 GiB sparse, 50 GB size
guard) and `iso5-dcli` (client, 192.168.100.54, 120 GiB, for row 36). It reuses the iso5 helpers already on aero in
`/tmp/iso2` (it never deletes them); its stick is `aero:/data/libvirt/images/iso5-docs-stick.img`.

1. Inputs (Mac, internet): `bash fetch-inputs.sh` -> `~/idm-lab-inputs/docs-spike/` + `MANIFEST.txt` (GPG / app-store
   signatures checked).
2. RPM (Mac, Homebrew `rpm`): `bash build-rpm.sh` -> `aero:/data/chp-release/built/spike/` (unsigned; why not on aero:
   see `SPIKE-NEXTCLOUD.md` "Build host").
3. Hosts: `bash install.sh prep`, `server`, `firstboot`, `export`, `client`, then `scan` (CUI scan, pristine), then
   `adapter` (chpadmin sudo; idm_admin secret to `~/idm-lab-secrets/docs-idm_admin.json`), then `mem` (8 GiB, 4 vCPU).
4. NextCloud: `bash spike.sh dvd-on`, `push`, `run packages`, `dvd-off`, `run db`, `run install`, `run trust`
   (copy `pkg/65-chp-nextcloud.rules` to `/root/spike/` first), `run config`, `run web`, `egress` (+ install
   `pkg/chp-nextcloud-egress.service`). Count denials with `fapolicyd-cli --check-status` (see SPIKE-NEXTCLOUD.md:
   `ausearch -m FANOTIFY` misses daemon denials).
5. Kanidm: `bash kanidm.sh login`, `users`, `oauth2`; then `bash spike.sh run oidc`; tunnel
   `ssh -F ssh_config -f -N -L 18443:192.168.100.53:8443 -L 18444:192.168.100.53:443 aero`; sign-in:
   `python3 -I oidc_login.py ROOT_CA 18443 18444 < ~/idm-lab-secrets/docs-lab01.json` (one JSON line).
6. Folders and tags: `bash folders.sh groups`, `folders`, `tags`, sign everyone in again, `apppw`;
   proofs: `python3 -I proofs.py ROOT_CA 18443 upload|tags|share|see`.
7. Wazuh: `wazuh/chp_nextcloud_rules.xml` -> `/var/ossec/etc/rules/`, `wazuh/localfile.xml` appended to `ossec.conf`.
8. Backup: `pkg/chp-nextcloud-backup` -> `/usr/local/sbin/`, `pkg/chp-nextcloud-backup.{service,timer}`.

Remove: `ssh aero 'sudo virsh destroy iso5-docs; sudo virsh undefine iso5-docs --nvram --snapshots-metadata;
sudo systemctl stop size-guard-iso5-docs'` (same for `iso5-dcli`), then delete `aero:/data/libvirt/images/iso5-d*`.

## Task 2 additions (doc commands: sign-in, freshness, ledger; findings in SPIKE-NEXTCLOUD.md §Transport, §Ledger)

Prototypes in `proto/` (throwaway). Workstation scripts run with `bash proto/on-dcli.sh SCRIPT [ARGS]` (a `lib.py+main.py`
pair is joined; `ENVS="CHP_DOC_AS=labNN"` picks a per-person session). Keep one ssh session to iso5-dcli open while
working (`ssh -F ssh_config dcli sleep 3600 &`): the tokens live in `/run/user/1000`, which logind removes when the last
session ends. The tunnel from step 5 is needed for the Mac-side scripts.

1. Sign-in: `bash proto/auth-setup.sh discovery|kanidm|nextcloud` (logs/43-44); then
   `bash proto/on-dcli.sh doc_auth.py oidc-login --scripted-browser < ~/idm-lab-secrets/docs-lab01.json`, `whoami`,
   `stored`, `logout`; Login Flow v2: `flow2-login --scripted-browser --store home` (logs/45-49, 55, 63-65).
2. Login page: insert `proto/nextcloud-login-rewrite.conf` after `RewriteEngine On` in the NextCloud vhost (logs/62).
3. Freshness: `python3 -I proto/freshness.py ROOT_CA`, `proto/etag_collide.py ROOT_CA` (Mac); on the workstation
   `doc_auth.py+doc_fresh.py checkout|edit|publish`, with `proto/colleague.py` as the other writer (logs/50-53).
4. Ledger: `bash proto/ledger-setup.sh l1`, `l2`, `stick` (logs/54); proofs `bash proto/ledger-run.sh l1|l2|anchor|apache`
   (logs/56-60; needs four route-1 sessions, logs/55).

Remove Task 2's state (iso5-docs): `occ app:disable chp_ledger` and `rm -rf /usr/lib/nextcloud/apps/chp_ledger`;
`systemctl disable --now chp-docs-ledger.path`, remove the three units (`chp-docs-ledger.{path,service}`, `chp-docs-ledger-alert.service`) and `/usr/local/libexec/chp-spike`;
`rm -rf /var/lib/chp-docs /root/spike/stick`; `semanage fcontext -d` the two `/var/lib/chp-docs` entries; `fapolicyd-cli
--file delete` the trust file `chp-spike` entries + `--update`; `occ groupfolders:delete 7` (Approvals);
`occ user_oidc:provider:delete kanidm-cli`, `occ config:system:delete user_oidc`; restore
`/root/spike/nextcloud.conf.before-task2` to `/etc/httpd/conf.d/nextcloud.conf`; `kanidm system oauth2 delete chp-doc`.
On iso5-dcli: `rm -rf ~/chp-docs-work ~/.config/chp-doc`.

Review fixes (logs/66-74): `proto/forged_bearer.py` (Mac; fix 3), `bash proto/cycle-run.sh` (fix 4, needs route-1 sessions
for lab01, lab02, lab04), `proto/open_redirect.py` (workstation, joined with doc_auth.py). chp_ledger is now 0.2.0: after
copying a new version, run `occ upgrade` (logs/67).
