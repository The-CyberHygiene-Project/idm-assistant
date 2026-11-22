#!/bin/zsh
# Sign repo 0.14.1 (ISO 0.7.0 Plan 3, Task 13e). Touch the YubiKey when it blinks.
cd ~/idm-assistant || exit 1
# refuse unless the stage is exactly the one staged in Task 13e: 72 RPMs + modules.yaml whose sha256 list
# (stage-0.14.1-logs/stage-sha256.txt) hashes to 789e1455...; it holds chp-templates 1.4.0-3 and chp-onlyoffice 0.1.0-7
d=$(ssh aero 'cd /data/chp-release/0.14.1/stage && ls chp-templates-1.4.0-3.chp.el9.noarch.rpm chp-onlyoffice-0.1.0-7.chp.el9.noarch.rpm >/dev/null && [ $(ls *.rpm | wc -l) = 72 ] && sha256sum * | sha256sum | cut -c1-64' 2>/dev/null)
[[ $d == 789e1455769640acfb58ae07e142f1065b5e48e8b8c5bc585963b50558009b8a ]] || { echo "STOP: stage is not the staged 0.14.1 (got '$d') - not signing"; exit 1; }
ssh aero '[ ! -e /data/chp-release/0.14.1/repo ]' 2>/dev/null || { echo "STOP: /data/chp-release/0.14.1/repo already exists - not signing"; exit 1; }
gpgconf --kill all
bash appliance/release/sign-session.sh "bash /data/chp-release/tools/sign-repo.sh /data/chp-release/0.14.1/stage /data/chp-release/0.14.1/repo 2DE0D71BF37D8F5E4201A590521276F43C908F8E /data/chp-release/tools"; echo "sign EXIT=$?"
