"""The operator's decision form for a repair, built by code from the runbook and what the collector found on the host.
No model writes any of it. Organized, not longer: one short line per field."""
import textwrap


def _w(text, indent="   "):
    return textwrap.fill(" ".join(str(text).split()), 72, initial_indent=indent, subsequent_indent=indent)


def render(host, rb, findings, repair_id):
    seen = [e for f in findings if f.id.split("(")[0] == rb.finding for e in f.evidence]
    bar = "=" * 72
    lines = ["", bar, f" DECISION on {host}: repair {repair_id}", bar,
             " PROBLEM DETECTED", _w(rb.user_sees), _w("Why it matters: " + rb.means), "",
             f" LIKELY CAUSE  (found by the diagnostic tool: {rb.finding})", _w(rb.evidence)]
    if seen:
        lines.append(_w("Found on this host: " + "; ".join(seen)))
    lines += ["", " PROPOSED ACTION", _w(rb.repair), "",
              " POTENTIAL DOWNSIDE", _w("If it is wrong: " + rb.if_wrong), _w("Undo: " + rb.rollback), ""]
    if rb.decisions:
        lines += [_w(f"Follows ISSO decision {rb.decisions}."), ""]
    lines += [" SAY NO IF", _w(rb.say_no_if), "",
              f" If unsure, type no: nothing on {host} changes.", "-" * 72,
              " CHOICE: Type yes to apply, or no to skip, then press Enter"]
    return "\n".join(lines)
