# Repo 0.12.0: unsigned stage and upgrade dry-run (ISO 0.7.0 Plan 2, Task 9 step 1)

**Date:** 2026-11-13 · **Stage:** `aero:/data/chp-release/0.12.0/stage` (UNSIGNED, 61 RPMs + `modules.yaml`, 854 MB)
· **Not signed:** step 2 (owner, YubiKey) runs `sign-repo.sh` on this stage. Logs: `stage-0.12.0-logs/`.

## What is in it

Repo 0.12.0 = repo 0.11.0 (28 packages) with three of our packages replaced and 33 added (`stage-diff.log`,
`stage-sha256.txt`):

| | Packages |
|---|---|
| Replaced (ours) | `chp-site` 0.13.0-2 → **0.14.0-1**, `chp-base` 0.1.0-4 → **0.1.0-10**, `chp-identity-server` 0.1.2-2 → **0.1.2-3** |
| Added (ours) | `nextcloud-chp-35.0.3-4`, `chp-documents-0.1.0-5` |
| Added (Rocky 9.8 DVD, Rocky key `350d275d`) | apr, apr-util, apr-util-bdb, capstone, httpd, httpd-core, httpd-filesystem, httpd-tools, libpq, libzip, mod_ssl, nginx-filesystem, rocky-logos-httpd; **php:8.3** (8.3.29): php-bcmath, -cli, -common, -fpm, -gd, -gmp, -intl, -mbstring, -opcache, -pdo, -pecl-apcu, -pecl-zip, -pgsql, -process, -xml; **postgresql:16** (16.13): postgresql, postgresql-private-libs, postgresql-server |
| Unchanged | the other 25 packages of 0.11.0 |

Only the newest builds are in the stage (assemble-repo takes the newest NEVRA of each name; older chp-base,
chp-documents, nextcloud-chp builds in `built/` are not picked up). `assemble.log` lists each choice.

**How the Rocky list was found.** The site repo is the server's only package source (all Rocky repos are disabled on an
installed host; no internet). The list is the dependency closure of `nextcloud-chp` + `chp-documents` against
**iso5-srv's own rpm database** (copied read-only into a scratch installroot on aero), resolved by dnf against
repo 0.11.0 + the new builds + the Rocky 9.8 DVD (BaseOS, AppStream), streams php:8.3 and postgresql:16 enabled,
`install_weak_deps=False`. Result: 31 DVD packages, all `rpm -K` OK with the Rocky key (pinned in `trusted-keys.txt`
as `rocky9`), byte-identical (`cmp`) to the DVD files, copied into `aero:/data/lab-inputs/rpms` like
libnetfilter_queue for Suricata.

**Weak dependencies left out (decision):** with weak deps the closure adds `apr-util-openssl`, `mod_http2`, `mod_lua`.
Nothing in chp-documents or nextcloud-chp uses them (no HTTP/2, Lua, or apr crypto). They are not in the repo, so a
site's `dnf install` (weak deps on by default) silently skips them: smaller, fixed package set. The spike server had
`apr-util-openssl` (DVD install with weak deps); the Step 4 proofs run on the repo set.

## Modularity (the key risk)

The php and postgresql RPMs are **modular** (`.module+el9…`). A plain `createrepo_c` repo has no module metadata:
`dnf module enable php:8.3` then has nothing to enable and `chp-documents` enable (`documents.py`: `dnf module enable
php:8.3 postgresql:16` from the chp repo, `check=True`) would fail. Before this task our repo build had no module
handling at all (`sign-repo.sh` ran a bare `createrepo_c`).

What was done (branch `iso-0.7.0`):

- **Vendor source:** the DVD's AppStream `modules.yaml.gz`, copied unchanged to
  `aero:/data/lab-inputs/rpms/appstream-modules.yaml.gz` (sha256 `1fc6cf45a6030195d3d53b752dc5f7ba8ded80e52ad6169489c333d2b9e2b101`,
  = the checksum recorded in the DVD's AppStream `repomd.xml`).
- **`appliance/release/MODULES.txt`:** the streams the repo carries: `php 8.3`, `postgresql 16`.
- **`stage-modules.sh`** (called by `assemble-repo.sh`): writes `stage/modules.yaml` = the vendor modulemd documents of
  exactly those streams (unchanged: php 8.3 `9070020260128004856` context 9; postgresql 16 `9080020260422094849`
  context rhel9) + the vendor defaults of the two modules cut to the same streams (profiles only: `8.3: [common]`,
  `16: [server]`; Rocky sets no default stream). Refuses if a stream is missing, has no RPM in the stage, or a modular
  RPM in the stage is not an artifact of a listed stream; validated with `modulemd-validator`. Result: 18 modular RPMs,
  all artifacts of the two streams; `modules.yaml` sha256 `6b0eb335…cff012c`. Shell + awk, because aero's fapolicyd
  refuses untrusted Python files (a first Python version was denied; no fapolicyd change was made).
- **`make-repodata.sh`** (now called by `sign-repo.sh` instead of `createrepo_c`): `createrepo_c`, then
  `modifyrepo_c --mdtype=modules` with the stage's `modules.yaml`; exactly one `modules` record (createrepo_c would
  otherwise also pick the file up by itself); refuses modular RPMs without `modules.yaml`. `repomd.xml` is signed
  after this, so the modules record is covered by the repo signature.
- **`sign-repo.sh`** copies `stage/modules.yaml` into its work dir. **`verify-repo.sh`** now fails a repo that has
  modular RPMs but no `modules` record. **`push.sh`** also copies `MODULES*.txt`. Tools pushed to
  `aero:/data/chp-release/tools/`.
- **Tests:** `test_sign_repo.sh` section 9 (7 cases) + section 6 adjusted. The non-signing cases were run on aero
  (section 6 assemble ×2, stage-modules ×3, make-repodata ×2, verify missing-modules ×1): **8/8 PASS**. The full
  `test_sign_repo.sh` (throwaway gpg keys, including the new "signed repo carries the modules metadata" case) was
  **not** run: it signs, which is outside this step. Run it before step 2.

## Dry-run on iso5-srv (ISO 0.6.0 install, documents not enabled)

`chpadmin` has **no sudo** on this install (`sudo: a password is required`; the lab adapter is not present). So dnf ran
as uid 0 of a **private user + mount namespace** (`unshare -rm`, `dry-run.sh`): the host's root-owned files are
read-only to it, and dnf's writable state (`/etc/dnf/modules.d`, `/var/lib/dnf`, `/var/cache/dnf`, log) was on tmpfs
mounts that exist only inside the namespace. The repo was a temp copy of the stage with repodata built by
`make-repodata.sh` (exactly sign-repo's path, unsigned), at `/var/tmp/s012/repo`, used alone
(`--repofrompath=s012,… --repo=s012 --nogpgcheck`), the same as `documents.py`'s `--enablerepo=chp` with every other
repo disabled. Full output: `dry.log`.

| # | Command | Result |
|---|---|---|
| 1 | `module list` | php **8.3** (common [d]), postgresql **16** (server [d]); no other streams |
| 2 | `module enable php:8.3 postgresql:16 --assumeno` | resolves: "Enabling module streams: php 8.3, postgresql 16" |
| 3 | same with `-y` (namespace tmpfs only) | Complete; `php.module`/`postgresql.module` `state=enabled` (in the tmpfs) |
| 4 | `install --assumeno nextcloud-chp chp-documents` | **Install 33, Upgrade 1** (chp-site 0.14.0-1, required by chp-documents), 232 MB, no conflict, nothing missing |
| 5 | `upgrade --assumeno` | **Upgrade 3**: chp-base 0.1.0-10, chp-identity-server 0.1.2-3, chp-site 0.14.0-1; nothing else (the new Rocky packages are not pulled onto a host that does not ask for them) |
| 6 | install of all 5 of ours together `--assumeno` | Install 33, Upgrade 3 |
| 7 | control: no stream enabled, `install php-fpm` | "All matches were filtered out by modular filtering" → the php RPMs are hidden until the stream is enabled (fails closed) |
| 8 | `rpm -U --test` of the 36 packages against a copy of srv's rpm database (`rpmtest.log`) | rc 0: no file conflicts, no unmet dependencies |

Afterwards (`after.log`): `/etc/dnf/modules.d` still empty, `/var/lib/rpm/rpmdb.sqlite` and
`/var/lib/dnf/history.sqlite` timestamps unchanged, chp-site 0.13.0-2 / chp-base 0.1.0-4 / chp-identity-server
0.1.2-2 still installed, httpd and php not installed, `/var/tmp/s012` removed. Aero's scratch installroot removed.

**Not proven here:** signature checks (`--nogpgcheck`; step 2 signs, `verify-repo` checks), the real transaction
(scriptlets, SELinux contexts, fapolicyd): Task 9 step 3 on the reset lab.

## For step 2 (owner)

- Sign: `sign-repo.sh /data/chp-release/0.12.0/stage /data/chp-release/0.12.0/repo <fpr> /data/chp-release/tools`
  through `sign-session.sh` as before. The new `make-repodata.sh` adds the modules record before repomd.xml is signed.
  Expect `REPO OK: 61 packages` (verify-repo also checks the modules record).
- Run `test_sign_repo.sh` on aero first (its new case 9 signs with a throwaway key).
- ISO note: the repo grows from 622 MB (0.11.0 stage) to 854 MB.
