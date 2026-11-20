#!/usr/bin/env bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# CHP_TEMPLATES_RELEASE=<folder> build-rpm.sh (RUNS ON THE MAC): build chp-templates' noarch RPM on aero from the SIGNED
# release (the folder holding chp-templates-$V.tar.gz, SHA256SUMS and SHA256SUMS.asc). The signature and the pinned
# sha256 are checked BEFORE anything is copied to aero.
# LAB CANDIDATE (explicit opt-in, ISO 0.7.0 Plan 3 Task 11b, owner decision 2026-11-20 option A):
# CHP_TEMPLATES_TAG=<local chp-templates git repo> builds instead from `git archive` of the LOCAL tag templates-$V, and
# refuses unless that archive's sha256 is the pin below. No signature provenance: the pin is the only input check (the
# RPM is then signed into the repo by the owner's key). For a pre-release lab candidate only; the signed release
# (CHP_TEMPLATES_RELEASE) follows as a new Release. Setting both is refused.
set -Eeuo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
V=1.4.0
TAR=chp-templates-$V.tar.gz
SHA=73964274430484e387a23e2cb95bee1747007841ecbd04c7f8c2f245dfc2c34f   # templates-1.4.0 = git archive of the local tag at 0a18aca (re-pin if the tag moves before the owner signs)
FPR=2DE0D71BF37D8F5E4201A590521276F43C908F8E
t=""; w=""; trap 'rm -rf "$t" "$w"' EXIT
if [[ -n ${CHP_TEMPLATES_TAG:-} ]]; then
  [[ -z ${CHP_TEMPLATES_RELEASE:-} ]] || { echo "refusing: set CHP_TEMPLATES_TAG or CHP_TEMPLATES_RELEASE, not both"; exit 1; }
  G=$CHP_TEMPLATES_TAG
  echo "################################################################################"
  echo "## LAB CANDIDATE BUILD: chp-templates $V from the UNSIGNED local tag templates-$V in $G"
  echo "## NO SIGNATURE PROVENANCE: the sha256 pin is the only input check. Not a release."
  echo "################################################################################"
  git -C "$G" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "refusing: $G is not a git working tree"; exit 1; }
  c=$(git -C "$G" rev-parse -q --verify "refs/tags/templates-$V^{commit}" 2>/dev/null) || { echo "refusing: tag templates-$V not found in $G"; exit 1; }
  t=$(mktemp -d); REL=$t
  git -C "$G" archive --format=tar.gz --prefix="chp-templates-$V/" -o "$REL/$TAR" "templates-$V"
  got=$(shasum -a 256 "$REL/$TAR" | cut -d' ' -f1)
  [[ $got == "$SHA" ]] || { echo "refusing: git archive of templates-$V ($c) is $got, not the pinned $SHA"; exit 1; }
  echo "lab candidate input: templates-$V = commit $c, archive sha256 $got (= pin)"
else
REL=${CHP_TEMPLATES_RELEASE:?set CHP_TEMPLATES_RELEASE to the signed release folder (or CHP_TEMPLATES_TAG for a lab candidate)}
gpg --verify "$REL/SHA256SUMS.asc" "$REL/SHA256SUMS" 2>&1 | grep -q "Good signature" || { echo "refusing: bad signature"; exit 1; }
gpg --verify --status-fd 1 "$REL/SHA256SUMS.asc" "$REL/SHA256SUMS" 2>/dev/null | grep -q "VALIDSIG $FPR" || { echo "refusing: not signed by $FPR"; exit 1; }
(cd "$REL" && shasum -a 256 -c SHA256SUMS) >/dev/null || { echo "refusing: checksum"; exit 1; }
[[ $(shasum -a 256 "$REL/$TAR" | cut -d' ' -f1) == "$SHA" ]] || { echo "refusing: $TAR is not the pinned release"; exit 1; }
fi
# The renderer as a zipapp (like chp-site.pyz): aero's fapolicyd blocks reading raw .py files, and rpmbuild reads all.
w=$(mktemp -d)
tar -xzf "$REL/$TAR" -C "$w"; src="$w/chp-templates-$V"
mkdir "$w/z"; cp "$src/render/chpfill.py" "$w/z/chpfill.py"
printf 'import sys\nimport chpfill\nsys.exit(chpfill.main())\n' > "$w/z/__main__.py"
python3 -m zipapp "$w/z" -o "$src/chpfill.pyz"
rm -rf "$src/render" "$src/tests" "$src/tools"
COPYFILE_DISABLE=1 tar --no-mac-metadata -C "$w" -czf "$w/chp-templates-$V-rpm.tar.gz" "chp-templates-$V"   # no ._* entries
ssh aero 'rm -rf /tmp/chpt && mkdir -p /tmp/chpt/SOURCES /tmp/chpt/SPECS /data/chp-release/built'
scp -q "$w/chp-templates-$V-rpm.tar.gz" aero:/tmp/chpt/SOURCES/
scp -q "$here/chp-templates.spec" aero:/tmp/chpt/SPECS/
ssh aero 'rpmbuild -bb --define "_topdir /tmp/chpt" /tmp/chpt/SPECS/chp-templates.spec >/tmp/chpt/build.log 2>&1 || { tail -20 /tmp/chpt/build.log; exit 1; }
          if rpm -qlp /tmp/chpt/RPMS/noarch/chp-templates-*.rpm | grep -q "/\._"; then echo "refusing: macOS ._ files in the RPM"; exit 1; fi
          cp /tmp/chpt/RPMS/noarch/chp-templates-*.rpm /data/chp-release/built/ && rpm -qlp /data/chp-release/built/chp-templates-*.rpm | head -12 && rm -rf /tmp/chpt'
