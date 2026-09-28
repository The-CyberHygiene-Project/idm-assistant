from tools.crypto_inventory import inventory

LOCK = '''
[[package]]
name = "aws-lc-sys"
version = "0.44.0"

[[package]]
name = "ring"
version = "0.17.14"

[[package]]
name = "argon2"
version = "0.5.3"

[[package]]
name = "serde"
version = "1.0.228"

[[package]]
name = "aws-lc-fips-sys"
version = "0.13.0"
'''


def test_classifies_crypto_crates_and_ignores_others():
    got = {i["name"]: i["family"] for i in inventory(LOCK)}
    assert got == {"aws-lc-sys": "aws-lc", "ring": "ring", "argon2": "rustcrypto",
                   "aws-lc-fips-sys": "aws-lc-fips"}


def test_no_openssl_is_reported_as_absent():
    assert all(i["family"] != "openssl" for i in inventory(LOCK))
