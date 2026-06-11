from __future__ import annotations

from typing import Any, Dict, List


class TaskArgumentError(ValueError):
    """Raised when a queued task does not match its catalog schema."""


READONLY_TASK_CATALOG: List[Dict[str, Any]] = [
    {
        "task_type": "inventory",
        "title": "Host inventory",
        "description": "Return basic host, OS, IP, and agent runtime inventory.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "process_list",
        "title": "Process list",
        "description": "Return a bounded snapshot of running processes.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "network_connections",
        "title": "Network connections",
        "description": "Return a bounded read-only network/interface or connection snapshot.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "service_list",
        "title": "Services",
        "description": "Return installed services or service definitions where supported.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "scheduled_tasks",
        "title": "Scheduled tasks",
        "description": "Return scheduled tasks / cron-style persistence entries where supported.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "windows_event_logs",
        "title": "Windows Event Logs",
        "description": "Collect recent events from allowlisted Windows log profiles.",
        "platforms": ["windows"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"profile": {"type": "string", "enum": ["powershell", "auth", "service", "task"], "default": "powershell"}, "max_events": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}},
    },
    {
        "task_type": "file_exists",
        "title": "File exists",
        "description": "Check whether a path exists without reading file contents.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"path": {"type": "string", "required": True}},
    },
    {
        "task_type": "file_hash",
        "title": "File SHA256",
        "description": "Hash a specific file path for evidence and IOC comparison.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"path": {"type": "string", "required": True}},
    },
    {
        "task_type": "agent_identity",
        "title": "Agent execution identity",
        "description": "Return the account/security context the endpoint agent is running as (used to confirm LocalSystem/root deployment).",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "list_directory",
        "title": "List directory",
        "description": "List bounded directory entries for triage and evidence discovery.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"path": {"type": "string", "required": True}, "max_entries": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}},
    },
    {
        "task_type": "read_file_chunk",
        "title": "Read file chunk",
        "description": "Read a bounded byte range from a file for analyst inspection.",
        "platforms": ["windows", "linux"],
        "risk": "medium",
        "destructive": False,
        "args_schema": {"path": {"type": "string", "required": True}, "offset": {"type": "integer", "minimum": 0, "maximum": 104857600, "default": 0}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 65536, "default": 4096}},
    },
    {
        "task_type": "copy_file",
        "title": "Copy file",
        "description": "Copy a file on the endpoint to another local path for evidence preservation.",
        "platforms": ["windows", "linux"],
        "risk": "medium",
        "destructive": False,
        "args_schema": {"source_path": {"type": "string", "required": True}, "destination_path": {"type": "string", "required": True}},
    },
    {
        "task_type": "listening_ports",
        "title": "Listening ports",
        "description": "Return listening TCP ports and owning PID where available.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "registry_query",
        "title": "Registry query",
        "description": "Read a Windows registry key using reg.exe query; unsupported on non-Windows platforms.",
        "platforms": ["windows"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"key": {"type": "string", "required": True}, "recursive": {"type": "boolean", "default": False}},
    },
    {
        "task_type": "autoruns_collect",
        "title": "Autoruns collection",
        "description": "Collect common persistence locations such as Run keys, services, scheduled tasks, startup folders, systemd and cron.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {},
    },
    {
        "task_type": "process_tree",
        "title": "Process tree",
        "description": "Return bounded parent/child process context for a PID.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"pid": {"type": "integer", "minimum": 1, "maximum": 2147483647, "required": True}},
    },
    {
        "task_type": "process_detail",
        "title": "Process detail",
        "description": "Return details for a specific process ID, including command line and executable hash when available.",
        "platforms": ["windows", "linux"],
        "risk": "low",
        "destructive": False,
        "args_schema": {"pid": {"type": "integer", "minimum": 1, "maximum": 2147483647, "required": True}},
    },
    {
        "task_type": "collect_file",
        "title": "Collect file evidence",
        "description": "Upload a bounded file from the endpoint to server raw evidence storage.",
        "platforms": ["windows", "linux"],
        "risk": "medium",
        "destructive": False,
        "args_schema": {"path": {"type": "string", "required": True}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 10485760, "default": 10485760}},
    },
    {
        "task_type": "quarantine_file",
        "title": "Quarantine file",
        "description": "Move a file into an analyst-specified quarantine directory on the endpoint.",
        "platforms": ["windows", "linux"],
        "risk": "high",
        "destructive": True,
        "requires_explicit_dispatch": True,
        "args_schema": {"source_path": {"type": "string", "required": True}, "quarantine_dir": {"type": "string", "required": True}},
    },
    {
        "task_type": "delete_file",
        "title": "Delete file",
        "description": "Delete a specific file. Requires confirm_sha256 to reduce accidental destructive actions.",
        "platforms": ["windows", "linux"],
        "risk": "high",
        "destructive": True,
        "requires_explicit_dispatch": True,
        "args_schema": {"path": {"type": "string", "required": True}, "confirm_sha256": {"type": "string", "required": True}},
    },
    {
        "task_type": "kill_process",
        "title": "Kill process",
        "description": "Terminate a process by PID.",
        "platforms": ["windows", "linux"],
        "risk": "high",
        "destructive": True,
        "requires_explicit_dispatch": True,
        "args_schema": {"pid": {"type": "integer", "minimum": 1, "maximum": 2147483647, "required": True}},
    },
    {
        "task_type": "service_control",
        "title": "Service control",
        "description": "Query, start, or stop a named service using the platform service manager.",
        "platforms": ["windows", "linux"],
        "risk": "high",
        "destructive": True,
        "requires_explicit_dispatch": True,
        "args_schema": {"service_name": {"type": "string", "required": True}, "action": {"type": "string", "enum": ["status", "start", "stop"], "required": True}},
    },
]


def validate_task_args(task_type: str, args: Dict[str, Any]) -> None:
    """Validate analyst-supplied task args against the endpoint task catalog.

    This intentionally supports only the tiny schema vocabulary V1 uses today.
    The server must reject unsafe/unknown task shapes before work reaches endpoints.
    """
    entry = next((item for item in READONLY_TASK_CATALOG if item["task_type"] == task_type), None)
    if not entry:
        raise TaskArgumentError("task_not_allowlisted")
    schema = entry.get("args_schema") or {}
    args = args or {}
    for name in args:
        if name not in schema:
            raise TaskArgumentError(f"task_arg_{name}_unknown")
    for name, spec in schema.items():
        if spec.get("required") and (name not in args or args.get(name) in (None, "")):
            raise TaskArgumentError(f"task_arg_{name}_required")
        if name not in args:
            continue
        value = args[name]
        if spec.get("type") == "string" and not isinstance(value, str):
            raise TaskArgumentError(f"task_arg_{name}_invalid")
        if spec.get("type") == "boolean":
            if not isinstance(value, bool):
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
