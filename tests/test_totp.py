import base64
from lab.tools.totp import totp

SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_rfc6238_sha1_vectors():
    for t, want in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                    (1234567890, "89005924"), (2000000000, "69279037")]:
        assert totp(SECRET, t=t, digits=8) == want


def test_default_is_six_digits_and_accepts_lowercase_unpadded_secret():
    assert totp(SECRET.lower().rstrip("="), t=59) == "287082"


def test_rfc6238_sha256_vectors():
    seed = base64.b32encode(b"12345678901234567890123456789012").decode()
    for t, want in [(59, "46119246"), (1111111109, "68084774"), (1111111111, "67062674"),
                    (1234567890, "91819424"), (2000000000, "90698825")]:
        assert totp(seed, t=t, digits=8, algorithm="sha256") == want


def test_cli_reads_the_secret_from_stdin_so_it_never_appears_in_process_args():
    import subprocess, sys
    from pathlib import Path
    cli = Path(__file__).resolve().parents[1] / "lab" / "tools" / "totp.py"
    r = subprocess.run([sys.executable, str(cli), "-", "sha256"], input=SECRET + "\n", capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == totp(SECRET, algorithm="sha256")
