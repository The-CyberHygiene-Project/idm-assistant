# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Status thresholds for the daily review (review spec §7). Pure functions: each returns a state and a plain-English
detail. Certificates are judged against their own lifetime: the Kanidm TLS certificate lasts 24 hours, the CAs 10 years."""
H, DAY = 3600, 86400
OK, ATTENTION, STALE = "OK", "ATTENTION", "STALE"
_ORDER = {OK: 0, ATTENTION: 1, STALE: 2}
LONG_LIVED = 90 * DAY


def _span(seconds):
    seconds = max(0, seconds)
    if seconds < 2 * DAY:
        return f"{int(seconds // H)} h"
    return f"{int(seconds // DAY)} days"


def cert_state(not_before, not_after, now):
    """(state, immediate, detail). Lifetime under 90 days (renewed automatically): ATTENTION below half the lifetime
    left, immediate below a quarter. 90 days or more: ATTENTION at <= 30 days left, immediate at <= 7 days."""
    life, left = not_after - not_before, not_after - now
    if left <= 0:
        return ATTENTION, True, f"expired {_span(-left)} ago"
    if life < LONG_LIVED:
        detail = f"{_span(left)} left of {_span(life)}"
        if left < life / 4:
            return ATTENTION, True, detail
        return (ATTENTION if left < life / 2 else OK), False, detail
    detail = f"{int(left // DAY)} days left"
    if left <= 7 * DAY:
        return ATTENTION, True, detail
    return (ATTENTION if left <= 30 * DAY else OK), False, detail


def key_state(expires, now):
    """A pinned signing key: ATTENTION within 90 days of expiry (as check-key-expiry.sh); None = never expires."""
    if expires is None:
        return OK, "does not expire"
    left = expires - now
    if left <= 0:
        return ATTENTION, f"expired {_span(-left)} ago"
    return (ATTENTION if left <= 90 * DAY else OK), f"{int(left // DAY)} days left"


def fresh_state(last, schedule_s, now):
    """A scan or feeder: STALE when it has never run, or ran more than twice its schedule ago."""
    if last is None:
        return STALE, "never ran"
    age = now - last
    return (STALE if age > 2 * schedule_s else OK), f"last {_span(age)} ago"


def worst(states):
    return max(states, key=_ORDER.__getitem__, default=OK)
