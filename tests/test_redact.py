import subprocess
from pathlib import Path

SED = Path(__file__).resolve().parents[1] / "collector" / "redact.sed"
SECRETS = [  # every secret shape the lab can produce (all fake)
    "use-reset-token pkc2r-5s5we-23ghh-hfg78",
    "token=eyJhbGciOiJFUzI1NiJ9abcdefghijk.eyJzdWIiOiJ1bml4ZC1jbGllbnQyIn0abc.sig",
    "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256",
    "Secret: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    'password=Zx9_fake-FAKE-fake-123',
    '"password": "Zx9_fake-FAKE-fake-123"',
    "Authorization: Bearer abcdef0123456789abcdef",
    "TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    'new_password: "xjgG4abcdEFGH12345"',
    "authorization: bearer abcdef0123456789abcdef",
    "Bearer abcdef0123456789abcdefXYZ",
    "IDM_ADMIN_PASSWORD=Zx9fakeFAKE123",
    "PASSWORD=Zx9fakeFAKE124",
    "password: Zx9fakeFAKE125",
    "secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
    "use-reset-token Pkc2r-5s5We-23ghh-hfg78",
]
KEYBLOCK = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----"
BENIGN = ["kanidmd.service active", "-----BEGIN CERTIFICATE-----", "notAfter=Sep 29 15:07:43 2026 GMT",
          "Protocol  : TLSv1.3"]


def redact(text):
    return subprocess.run(["sed", "-E", "-f", str(SED)], input=text, capture_output=True, text=True, check=True).stdout


def test_every_secret_shape_is_redacted():
    out = redact("\n".join(SECRETS) + "\n")
    for s in SECRETS:
        secret_part = s.split()[-1].split("=")[-1].strip('"')
        assert secret_part not in out, s
    assert out.count("[REDACTED]") >= len(SECRETS)


def test_private_key_block_is_redacted_entirely():
    out = redact(KEYBLOCK + "\n")
    assert "b3BlbnNzaC1rZXktdjEAAAAA" not in out and "AAAABG5vbmUAAAAEbm9uZQ" not in out


def test_benign_lines_survive():
    out = redact("\n".join(BENIGN) + "\n")
    for b in BENIGN:
        assert b in out


def test_otpauth_secret_value_itself_is_gone():
    out = redact("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256\n"
                 "Secret: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
    assert "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" not in out
