"""The probe's five diagnostic tools. Each call is scored against ITS OWN schema
(MFR-2026-08-20 correction #2: a single hard-coded field misreported 16% for 83-100%)."""
import json

import jsonschema


def _tool(name, description, properties, required):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": required, "additionalProperties": False}}}


TOOLS = [
    _tool("get_service_status", "Show whether a systemd unit is active and its recent state.",
          {"unit": {"type": "string"}}, ["unit"]),
    _tool("read_log", "Read the last N journal lines for a systemd unit.",
          {"unit": {"type": "string"}, "lines": {"type": "integer", "minimum": 1}}, ["unit", "lines"]),
    _tool("check_certificate", "Show the TLS certificate chain and expiry for host:port.",
          {"host": {"type": "string"}, "port": {"type": "integer"}}, ["host", "port"]),
    _tool("check_time_sync", "Show clock offset and NTP synchronisation state.", {}, []),
    _tool("list_failed_logins", "List recent failed login attempts for a user.",
          {"user": {"type": "string"}}, ["user"]),
]
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}
_SCHEMAS = {t["function"]["name"]: t["function"]["parameters"] for t in TOOLS}


def validate_call(name: str, arguments: str) -> tuple[bool, str]:
    if name not in _SCHEMAS:
        return False, f"unknown tool {name!r}"
    if arguments is not None and not isinstance(arguments, str):
        return False, f"arguments must be a JSON string, got {type(arguments).__name__}"
    try:
        args = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError as e:
        return False, f"arguments are not valid JSON: {e.msg}"
    try:
        jsonschema.validate(args, _SCHEMAS[name])
    except jsonschema.ValidationError as e:
        return False, f"schema: {e.message}"
    return True, "ok"
