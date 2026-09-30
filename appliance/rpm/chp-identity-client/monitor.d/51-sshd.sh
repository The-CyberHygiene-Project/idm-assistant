#!/bin/bash
# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
# 51-sshd: the effective sshd settings still match the CHP drop-ins (row 35), and the user CA key is the pinned one.
M=/var/lib/chp/firstboot
if [ ! -e "$M/client.done" ]; then echo "OK sshd (not enrolled yet)"; exit 0; fi
t=$(sshd -T -C user=chp-monitor-probe,host=x,addr=127.0.0.2 2>/dev/null)
b=$(sshd -T -C user=chpadmin,host=x,addr=127.0.0.2 2>/dev/null)
am=$(awk '$1=="authenticationmethods"{print $2}' <<< "$t"); ca=$(awk '$1=="trustedusercakeys"{print $2}' <<< "$t")
bm=$(awk '$1=="authenticationmethods"{print $2}' <<< "$b")
if [ -f /etc/chp/client.conf ]; then want=$(chp-site get SSH_CA_FPR 2>/dev/null); else want=$(ssh-keygen -lf /etc/ssh-ca/user_ca.pub 2>/dev/null | awk '{print $2}'); fi
have=$(ssh-keygen -lf /etc/ssh/chp_user_ca.pub 2>/dev/null | awk '{print $2}')
if [ "$am" != "publickey,keyboard-interactive:pam" ]; then echo "ALERT sshd drift: authenticationmethods is '$am'"
elif [ "$ca" != "/etc/ssh/chp_user_ca.pub" ]; then echo "ALERT sshd drift: trustedusercakeys is '$ca'"
elif [ "$bm" != "publickey" ]; then echo "ALERT sshd drift: chpadmin authenticationmethods is '$bm'"
elif [ -z "$want" ] || [ "$have" != "$want" ]; then echo "ALERT sshd drift: user CA key $have is not the pinned $want"
else echo "OK sshd CHP settings and pinned user CA"; fi
