"""Allow-listed repairs: precheck -> approval -> backup -> apply -> verify (fresh report) -> undo if still faulty.
Nothing is applied without approval. A repair only runs on a host of its declared role."""
from dataclasses import dataclass, field
from typing import Callable, Optional

from engine.findings import evaluate


@dataclass
class Ctx:
    host: str                        # admin SSH alias of the target host
    role: str                        # "server" | "client" (from the report)
    case: object                     # engine.case.Case
    collect: Callable[[], dict]      # fresh read-only report of the target host
    params: dict = field(default_factory=dict)
    remote: Optional[object] = None  # engine.remote (injected; fakes in tests)


class Repair:
    id = ""
    host_role = ""
    verify_absent: set = set()       # findings that must be ABSENT in a fresh report after apply

    def describe(self, ctx):
        return self.id

    def precheck(self, ctx):         # -> None if OK, else a reason string
        return None

    def backup(self, ctx):
        return {}

    def apply(self, ctx):
        raise NotImplementedError

    def undo(self, ctx, backup):
        pass


def run_repair(repair_id, ctx, approve, registry):
    case = ctx.case
    r = registry.get(repair_id)
    if r is None:
        case.log(f"REFUSED: {repair_id!r} is not on the allow-list"); case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    if r.host_role != ctx.role:
        case.log(f"REFUSED: {repair_id} runs on {r.host_role} hosts, {ctx.host} is {ctx.role}")
        case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    with case.step("precheck"):
        why = r.precheck(ctx)
    if why:
        case.log(f"PRECHECK FAILED: {why}"); case.write("status.txt", "PRECHECK-FAILED\n")
        return "PRECHECK-FAILED"
    prompt = f"Repair {repair_id} on {ctx.host}: {r.describe(ctx)}. Type yes to approve"
    with case.step("approval"):
        ok = bool(approve(prompt))
    case.write("approval.json", {"repair": repair_id, "host": ctx.host, "prompt": prompt, "approved": ok})
    if not ok:
        case.log("REFUSED: not approved"); case.write("status.txt", "REFUSED\n")
        return "REFUSED"
    with case.step("backup"):
        saved = r.backup(ctx)
    case.log(f"backup: {sorted(saved)}")
    with case.step("apply"):
        r.apply(ctx)
    case.log("applied")
    with case.step("verify"):
        after = ctx.collect()
        still = sorted({f.id for f in evaluate(after)} & set(r.verify_absent))
    case.write("report-after.json", after)
    if still:
        with case.step("undo"):
            r.undo(ctx, saved)
        case.log(f"VERIFY FAILED ({still}); undone"); case.write("status.txt", "FAILED-UNDONE\n")
        return "FAILED-UNDONE"
    case.log("verified"); case.write("status.txt", "OK\n")
    return "OK"
