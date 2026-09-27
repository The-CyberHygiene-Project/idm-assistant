CATS = ["valid", "invalid_call", "prose_json", "prose", "error"]


def to_markdown(points, meta):
    lines = ["# Tool-calling probe results", ""]
    lines += [f"- {k}: {v}" for k, v in meta.items()] + [""]
    lines.append("| model | pad tokens | n | valid % | " + " | ".join(CATS) + " | prompt tok | s/call | note |")
    lines.append("|---|---:|---:|---:|" + "---:|" * len(CATS) + "---:|---:|---|")
    for p in points:
        c = p["counts"]
        pct = f"{round(100 * c.get('valid', 0) / p['n'])}%" if p["n"] else "-"
        note = f"ABORTED: {p['reason']}" if p["aborted"] else ""
        lines.append(f"| {p['model']} | {p['pad_tokens']} | {p['n']} | {pct} | "
                     + " | ".join(str(c.get(k, 0)) for k in CATS)
                     + f" | {p['prompt_tokens_mean']} | {p['seconds_mean']} | {note} |")
    return "\n".join(lines) + "\n"
