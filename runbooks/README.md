# Runbook format

Approved by the ISSO on 2026-10-03. One short page per finding id (`<FINDING_ID>.md`). The header fills the operator's
decision form **by code** (`engine/form.py`); no model writes any line of it. The body is the short text the model
reads. `tests/test_runbook_shape.py` enforces the format for every page.

## Layout

```
default_repair: <repair id from engine/repairs.py, or none>
decisions: <ISSO decision / requirement row numbers this page depends on, or empty>
user_sees: <PROBLEM DETECTED: what the person notices>
means: <why it matters: who loses what>
evidence: <LIKELY CAUSE: what the diagnostic tool found, in plain words>
repair: <PROPOSED ACTION; for none: "No automatic repair." + what a person does instead>
if_wrong: <POTENTIAL DOWNSIDE: what happens if this is the wrong call>
rollback: <Undo: how it is undone, or "Cannot be undone" and why>
say_no_if: <SAY NO IF: the one situation where the right answer is no>
---
<the model's text: a few sentences, technical terms allowed>
```

## How each field reaches the form

| Field | Form line |
| --- | --- |
| `user_sees` + `means` | PROBLEM DETECTED, then "Why it matters" |
| `evidence` | LIKELY CAUSE, followed by "Found on this host:" with what the collector actually found |
| `repair` | PROPOSED ACTION |
| `if_wrong` + `rollback` | POTENTIAL DOWNSIDE: "If it is wrong", then "Undo" |
| `decisions` | "Follows ISSO decision N." |
| `say_no_if` | SAY NO IF |

The form ends with "If unsure, type no: nothing on <host> changes" and a choice typed as a whole word plus Enter.

## Rules

1. **Plain words.** Write for a person who is not a Linux identity specialist. Every line must be something they can act on.
2. **Written from the repair's code, not from memory.** Read the repair's `precheck`, `backup`, `apply` and `undo` before
   writing `repair`, `if_wrong` and `rollback`. Claim nothing the code does not do.
3. **Say when a repair cannot be undone, and why** (for example: "the old time was wrong").
4. **No-repair pages** (`default_repair: none`) say what a person does instead, and when not to.
5. **Follow the ISSO decisions.** A page whose advice depends on one names it in `decisions`, and its text must agree
   with it (`tests/test_isso_decisions.py`).
6. **Use the live values.** Numbers that come from a host's configuration (limits, intervals) must match what the
   collector reads there; the live evidence line on the form shows the actual values.
7. **Every new repair ships with two tests:** a case where the right answer is no repair (the model must decline or the
   code must refuse), and a case where the evidence carries an injected instruction that must be ignored.
8. **Wording is reviewed by the ISSO before it is published.**
