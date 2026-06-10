from __future__ import annotations

from typing import Any, Dict, List


class TaskArgumentError(ValueError):
    """Raised when a queued read-only task does not match its catalog schema."""




READONLY_TASK_CATALOG: List[Dict[str, Any]] = [
    {
        "task_type": "inventory",
        "title": "Host inventory",
        "description": "Return basic host, OS, IP, and agent runtime inventory.",
        "platforms": ["windows", "linux"],
        "args_schema": {},
    },
    {
        "task_type": "process_list",
        "title": "Process list",
        "description": "Return a bounded snapshot of running processes.",
        "platforms": ["windows", "linux"],
        "args_schema": {},
    },
    {
        "task_type": "network_connections",
        "title": "Network connections",
        "description": "Return a bounded read-only network/interface or connection snapshot.",
        "platforms": ["windows", "linux"],
        "args_schema": {},
    },
    {
        "task_type": "service_list",
        "title": "Services",
        "description": "Return installed services or service definitions where supported.",
        "platforms": ["windows", "linux"],
        "args_schema": {},
    },
    {
        "task_type": "scheduled_tasks",
        "title": "Scheduled tasks",
        "description": "Return scheduled tasks / cron-style persistence entries where supported.",
        "platforms": ["windows", "linux"],
        "args_schema": {},
    },
    {
        "task_type": "windows_event_logs",
        "title": "Windows Event Logs",
        "description": "Collect recent events from allowlisted Windows log profiles.",
        "platforms": ["windows"],
        "args_schema": {"profile": {"type": "string", "enum": ["powershell", "auth", "service", "task"], "default": "powershell"}, "max_events": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}},
    },
    {
        "task_type": "file_exists",
        "title": "File exists",
        "description": "Check whether a path exists without reading file contents.",
        "platforms": ["windows", "linux"],
        "args_schema": {"path": {"type": "string", "required": True}},
    },
    {
        "task_type": "file_hash",
        "title": "File SHA256",
        "description": "Hash a specific file path for evidence and IOC comparison.",
        "platforms": ["windows", "linux"],
        "args_schema": {"path": {"type": "string", "required": True}},
    },
]


def validate_task_args(task_type: str, args: Dict[str, Any]) -> None:
    """Validate analyst-supplied task args against the read-only task catalog.

    This intentionally supports only the tiny schema vocabulary V1 uses today.
    The server must reject unsafe/unknown profiles before work reaches endpoints.
    """
    entry = next((item for item in READONLY_TASK_CATALOG if item["task_type"] == task_type), None)
    if not entry:
        raise TaskArgumentError("task_not_readonly_allowlisted")
    schema = entry.get("args_schema") or {}
    args = args or {}
    for name, spec in schema.items():
        if spec.get("required") and (name not in args or args.get(name) in (None, "")):
            raise TaskArgumentError(f"task_arg_{name}_required")
        if name not in args:
            continue
        value = args[name]
        if spec.get("type") == "string" and not isinstance(value, str):
            raise TaskArgumentError(f"task_arg_{name}_invalid")
        if spec.get("type") == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise TaskArgumentError(f"task_arg_{name}_invalid")
            if "minimum" in spec and value < spec["minimum"]:
                raise TaskArgumentError(f"task_arg_{name}_invalid")
            if "maximum" in spec and value > spec["maximum"]:
                raise TaskArgumentError(f"task_arg_{name}_invalid")
        if "enum" in spec and value not in spec["enum"]:
            raise TaskArgumentError(f"task_arg_{name}_invalid")
