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
