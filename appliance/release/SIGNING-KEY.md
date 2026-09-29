# Release signing key

The one key that signs CyberHygiene Project Lab Installer packages (RPMs), repository metadata (`repomd.xml`) and
release checksums.

| Item | Value |
|---|---|
| Fingerprint | `2DE0D71BF37D8F5E4201A590521276F43C908F8E` |
| User ID | The CyberHygiene Project Release Signing (Lab Installer packages) |
| Algorithm | RSA 3072 (primary = signing key; card also holds RSA 3072 encryption and authentication subkeys, unused) |
| Digest used for signatures | SHA-256 |
| Created | 2026-09-29 |
| Expires | 2028-09-28 |
| Public key | `RPM-GPG-KEY-cyberhygiene` (pinned in `trusted-keys.txt`) |

## Custody

- Generated **on-card** on a **dedicated YubiKey 5 NFC**, which is used for nothing but release signing and is held by
  the System Owner. The secret key cannot be exported, and **no backup copy exists**.
- PIN and Admin PIN were changed from the factory defaults before first use. They are never written down in this repository
  or typed on a command line: every PIN is entered in a pinentry dialog.
- **Touch policy: On** (`UIF Sign=on`). Every signature needs a physical touch within about 15 seconds of the key blinking.
  Expect **two touches per RPM** (rpm 4.16 adds a header signature and a header+payload signature) and one each for
  `repomd.xml` and `SHA256SUMS`.
- The key is only ever used from the Mac. Hosts that sign (aero) reach it through a forwarded gpg-agent socket that
  exists only for one command (`sign-session.sh`).

## Expiry

Before 2028-09-28, extend the key on-card with `gpg --quick-set-expire 2DE0D71BF37D8F5E4201A590521276F43C908F8E 2y`,
then re-export `RPM-GPG-KEY-cyberhygiene` and commit it. Sites re-import the public key; the fingerprint does not change.

## Loss or compromise

1. Generate a new key on a new dedicated token (`keygen.exp`, Plan 1 Task 1).
2. Replace the `cyberhygiene` line in `trusted-keys.txt` and the public key file.
3. Rebuild and re-sign the repository and the ISO.
4. Tell every site to remove the old key and pin the new fingerprint.

**Revocation certificate:** gpg wrote one at key creation, on the Mac:
`~/.gnupg/openpgp-revocs.d/2DE0D71BF37D8F5E4201A590521276F43C908F8E.rev`. Anyone holding it can revoke the key, so it
is kept **offline** (a copy on offline media held with the token's PINs) and is **never** committed or put on a network
share. To revoke: remove the `:` guard before `-----BEGIN PGP PUBLIC KEY BLOCK-----` in a copy, `gpg --import` it,
re-export the public key and distribute it with the new key.
