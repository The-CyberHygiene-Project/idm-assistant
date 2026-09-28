"""RFC 6238 TOTP for lab enrolment scripts (Kanidm 1.11 issues HMAC-SHA256 TOTP). Stdlib only."""
import base64
import hashlib
import hmac
import struct
import sys
import time


def totp(secret_b32, t=None, digits=6, step=30, algorithm="sha1"):
    s = secret_b32.strip().upper()
    key = base64.b32decode(s + "=" * (-len(s) % 8))
    counter = int((time.time() if t is None else t) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm)).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


if __name__ == "__main__":
    # "-" = read the secret from stdin, so it never shows in `ps` / /proc/*/cmdline.
    sec = sys.stdin.readline().strip() if sys.argv[1] == "-" else sys.argv[1]
    # TOTP_OFFSET (seconds) = the target host's clock minus ours, e.g. a VM reverted to a snapshot.
    now = time.time() + int(__import__("os").environ.get("TOTP_OFFSET", "0"))
    print(totp(sec, t=now, algorithm=sys.argv[2] if len(sys.argv) > 2 else "sha1"))
