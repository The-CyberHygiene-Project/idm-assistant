"""RFC 6238 TOTP (HMAC-SHA1) for lab enrolment scripts. Stdlib only; lab secrets never leave ~/idm-lab-secrets."""
import base64
import hashlib
import hmac
import struct
import sys
import time


def totp(secret_b32, t=None, digits=6, step=30):
    s = secret_b32.strip().upper()
    key = base64.b32decode(s + "=" * (-len(s) % 8))
    counter = int((time.time() if t is None else t) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


if __name__ == "__main__":
    print(totp(sys.argv[1]))
