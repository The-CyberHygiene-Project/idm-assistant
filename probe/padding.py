"""Deterministic filler: realistic operations text that grows the prompt without
changing the task (MFR F-6 measures reliability against prompt volume)."""
CHARS_PER_TOKEN = 4

_LINES = [
    "Sep 26 {h:02d}:{m:02d}:{s:02d} srv1 kanidmd[812]: INFO request completed path=/v1/auth status=200 duration_ms={d}",
    "Sep 26 {h:02d}:{m:02d}:{s:02d} client2 kanidm_unixd[655]: DEBUG cache hit for account uid={u} ttl=300",
    "Sep 26 {h:02d}:{m:02d}:{s:02d} srv1 step-ca[901]: INFO certificate renewed serial={u}{d} not_after=2026-10-26",
    "Sep 26 {h:02d}:{m:02d}:{s:02d} srv1 named[733]: client @0x7f{d} 192.168.100.{u}#53 query: idm.kanidm.lab.test IN A",
    "Runbook note {u}: the unixd cache keeps resolved accounts for 300 seconds; posix passwords are separate from primary credentials.",
    "Inventory {u}: host client{u} enrolled {d} days ago, trust anchor step-ca root, sshd TrustedUserCAKeys present.",
]


def padding(target_tokens: int) -> str:
    target_chars = target_tokens * CHARS_PER_TOKEN
    out, i = [], 0
    size = 0
    while size < target_chars:
        line = _LINES[i % len(_LINES)].format(
            h=(i // 3600) % 24, m=(i // 60) % 60, s=i % 60, d=100 + i % 900, u=10 + i % 90)
        out.append(line)
        size += len(line) + 1
        i += 1
    text = "\n".join(out)
    return text[:target_chars] if target_tokens else ""
