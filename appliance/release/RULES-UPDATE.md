# Monthly YARA rules update (security bundle part 2)

The appliance never downloads rules. Once a month, the project builds, tests and signs a new `chp-yara-rules` and
publishes it as a small update folder (`0.3.0-rules-<YYYY-MM>/`). Steps:

1. **Pin the new upstream commit** in `lab/inputs/fetch-signature-base.sh`:
   - `SIG_COMMIT`: `git ls-remote https://github.com/Neo23x0/signature-base HEAD`;
   - `SIG_DATE`: that commit's date as YYYY.MM.DD (it becomes the package version);
   - `SIG_SHA256`: run the script once with the old value; it prints the new tarball's sha256. Put it in and run it
     again until it says `OK signature-base <commit>`.
2. **Copy the tarball** to aero `/data/lab-inputs/`.
3. **Build:** `bash appliance/rpm/chp-yara-rules/build-rpm.sh`. Read its line `compiled N rule files, skipped M`, and
   any new `SKIPPED.txt` reasons.
4. **Test on the lab:** install the new package on iso5-cli2 (from the built RPM) and run
   `bash lab/security/prove-y1.sh full`. A clean appliance must give no matches other than the test file. For any new
   false alarm, add its rule file to `appliance/rpm/chp-yara-rules/exclude.txt` with the reason, and rebuild.
5. **Assemble and sign** a repo with only `chp-yara-rules` changed (`assemble-repo.sh`, then `sign-session.sh` with
   `sign-repo.sh`; the owner says "go").
6. **Release:** write a short `UPDATE-0.3.0-rules-<YYYY-MM>.md.in` (the commit, the date, the compile and skip counts,
   and the AIDE entries to expect: `/usr/share/chp-yara-rules/*` only), then
   `V=0.3.0-rules-<YYYY-MM> REPO_V=<repo> NOTE=UPDATE-0.3.0-rules-<YYYY-MM>.md.in bash appliance/release/release-repo.sh`.
7. **Sites apply it** like any update: unpack the repo, `dnf --refresh --enablerepo=chp upgrade chp-yara-rules`, and
   accept the AIDE alert. No restart is needed: the next scan uses the new rules.
