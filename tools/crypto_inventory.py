"""Which crypto implementations does a Rust build pull in? (ADR 0001 Q2, static half.)"""
import re
import sys

FAMILIES = [
    ("aws-lc-fips", re.compile(r"^aws-lc-fips-sys$")),
    ("aws-lc", re.compile(r"^aws-lc-(sys|rs)$")),
    ("ring", re.compile(r"^ring$")),
    ("openssl", re.compile(r"^openssl(-sys)?$")),
    ("rustcrypto", re.compile(r"^(argon2|sha1|sha2|sha3|hmac|hkdf|pbkdf2|aes|aes-gcm|chacha20poly1305|p256|p384|p521|ecdsa|ed25519-dalek|rsa|blake2|md-5|des|ctr|cbc)$")),
    ("other-crypto", re.compile(r"^(boring|boring-sys|mbedtls|nettle|libsodium-sys|tss-esapi)$")),
]


def inventory(lock_text):
    out = []
    for block in lock_text.split("[[package]]"):
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        ver = re.search(r'^version = "([^"]+)"', block, re.M)
        if not name:
            continue
        for fam, rx in FAMILIES:
            if rx.match(name.group(1)):
                out.append({"name": name.group(1), "version": ver.group(1) if ver else "?", "family": fam})
                break
    return sorted(out, key=lambda i: (i["family"], i["name"]))


def main():
    items = inventory(open(sys.argv[1]).read())
    print("| family | crate | version |\n|---|---|---|")
    for i in items:
        print(f"| {i['family']} | {i['name']} | {i['version']} |")
    fams = {i["family"] for i in items}
    print(f"\nOpenSSL present: {'yes' if 'openssl' in fams else 'NO'} · "
          f"AWS-LC FIPS module present: {'yes' if 'aws-lc-fips' in fams else 'NO'}")


if __name__ == "__main__":
    main()
