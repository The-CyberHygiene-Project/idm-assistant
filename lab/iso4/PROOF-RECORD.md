# ISO Plan 4a proof: record

## Task 5: sshd `Match` placement on OpenSSH 9.9 (aero, 2026-09-30)

`lab/iso4/sshd-match-check.sh` builds a Rocky-like tree in a temp dir: a main file with `Include d/*.conf` followed by `X11Forwarding no` and
`MaxAuthTries 3` (as the CUI main file has lines after its Include), plus the two shipped drop-ins (`10-chp.conf`, `99-chp-exceptions.conf`
with `Match User chpadmin,diag,chpcache`). It then asks `sshd -T -C user=…`. aero's sshd was not touched.

```
OpenSSH_9.9p1, OpenSSL 3.5.5 27 Jan 2026
alice: maxauthtries=3 x11forwarding=no authenticationmethods=publickey,keyboard-interactive:pam
chpadmin: maxauthtries=3 x11forwarding=no authenticationmethods=publickey
diag: maxauthtries=3 x11forwarding=no authenticationmethods=publickey
```

**Result: PASS.**
- A `Match` in an included file ends at that file's end.
- The main-file lines after the `Include` apply to every user.
- The key-only exception applies only to the named accounts.
- `MaxAuthTries` is the sentinel (sshd's default is 6; a leak would show 6 for `alice`). `X11Forwarding` defaults to `no`, so it proves nothing here.
