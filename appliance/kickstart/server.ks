# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# CHP Lab Installer, server kickstart. Site values come from the OEMDRV stick through `chp-site pre` (%pre below);
# the secrets (LUKS passphrase, root console password) exist only in /tmp/chp (installer RAM) and on the stick.
text
cdrom
poweroff
lang en_US.UTF-8
keyboard --vckeymap=us --xlayouts='us'
%include /tmp/chp/misc.ks
%include /tmp/chp/net.ks
firewall --enabled --service=ssh
selinux --enforcing
%include /tmp/chp/users.ks
bootloader --append="fips=1"
zerombr
%include /tmp/chp/disk.ks
%include /tmp/chp/repo.ks

%addon com_redhat_kdump --disable
%end

%addon com_redhat_oscap
    content-type = scap-security-guide
    profile = xccdf_org.ssgproject.content_profile_cui
%end

%packages
@^graphical-server-environment
audit
chrony
crypto-policies
firewalld
fapolicyd
openscap-scanner
scap-security-guide
openssh-server
sudo
tar
rsync
clevis
clevis-luks
clevis-dracut
clevis-systemd
tpm2-tools
mokutil
chp-site
%end

%pre --interpreter=/usr/bin/bash --erroronfail --log=/tmp/chp-pre.log
# Validate the site stick BEFORE any disk is touched. Messages go to the console so the person installing sees them.
set -uo pipefail
mkdir -p /mnt/oemdrv /tmp/chp
if ! mount -o rw LABEL=OEMDRV /mnt/oemdrv; then
  echo "CHP: no site stick found (a USB volume labelled OEMDRV). Nothing was changed." | tee /dev/console
  exit 1
fi
repo=file:///run/install/repo/chp
for a in $(cat /proc/cmdline); do case $a in chp.repo=*) repo=${a#chp.repo=} ;; esac; done
pyz=/run/install/repo/chp/chp-site.pyz
if [ -f /chp-site.pyz ]; then pyz=/chp-site.pyz; fi
python3 "$pyz" pre --role server --stick /mnt/oemdrv --out /tmp/chp --repo-url "$repo" 2>&1 | tee /dev/console
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then echo "CHP: install stopped before any disk was touched." | tee /dev/console; fi
exit "$rc"
%end

%post --nochroot --log=/mnt/sysimage/root/chp-post-nochroot.log
# Non-secret site files to /etc/chp (0644). The escrow directory is NEVER copied to the host.
install -d -m 0755 /mnt/sysimage/etc/chp
for f in site.conf hosts client.conf; do
  if [ -f "/mnt/oemdrv/$f" ]; then install -m 0644 "/mnt/oemdrv/$f" "/mnt/sysimage/etc/chp/$f"; fi
done
sync; umount /mnt/oemdrv || true
echo "CHP: install finished. Remove the site stick and keep it OFFLINE: it holds this host's recovery secrets." > /dev/console
%end

%post --log=/root/chp-post.log
# Trust our signing key (the chp-site RPM ships it) and keep vendor online repos off (offline appliance).
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-cyberhygiene
dnf config-manager --set-disabled baseos appstream extras >/dev/null 2>&1 || true
# dc2 tailoring: dc2 UNSELECTS sysctl_user_max_user_namespaces; the CUI files are also inside the initramfs.
grep -rlE 'user\.max_user_namespaces' /etc/sysctl.d /etc/sysctl.conf 2>/dev/null | xargs -r sed -i '/user\.max_user_namespaces/d'
rm -f /etc/sysctl.d/user_max_user_namespaces.conf
dracut -f --regenerate-all
%end
