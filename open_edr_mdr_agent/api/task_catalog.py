from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping


class TaskArgumentError(ValueError):
    """Raised when a queued task does not match its catalog schema."""


@dataclass(frozen=True)
class ArgumentSpec:
    """Tiny schema vocabulary supported by endpoint task arguments."""

    type: str
    required: bool = False
    enum: tuple[Any, ...] | None = None
    minimum: int | None = None
    maximum: int | None = None
    default: Any = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ArgumentSpec":
        return cls(
            type=str(data.get("type", "string")),
            required=bool(data.get("required", False)),
            enum=tuple(data["enum"]) if "enum" in data else None,
            minimum=data.get("minimum"),
            maximum=data.get("maximum"),
            default=data.get("default"),
        )

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type}
        if self.enum is not None:
            out["enum"] = list(self.enum)
        if self.minimum is not None:
            out["minimum"] = self.minimum
        if self.maximum is not None:
            out["maximum"] = self.maximum
        if self.default is not None:
            out["default"] = self.default
        if self.required:
            out["required"] = True
        return out

    def validate(self, name: str, value: Any) -> None:
        if self.type == "string" and not isinstance(value, str):
            raise TaskArgumentError(f"task_arg_{name}_invalid")
        if self.type == "boolean" and not isinstance(value, bool):
            raise TaskArgumentError(f"task_arg_{name}_invalid")
        if self.type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise TaskArgumentError(f"task_arg_{name}_invalid")
            if self.minimum is not None and value < self.minimum:
                raise TaskArgumentError(f"task_arg_{name}_invalid")
            if self.maximum is not None and value > self.maximum:
                raise TaskArgumentError(f"task_arg_{name}_invalid")
        if self.enum is not None and value not in self.enum:
            raise TaskArgumentError(f"task_arg_{name}_invalid")


@dataclass(frozen=True)
class TaskDefinition:
    task_type: str
    title: str
    description: str
    platforms: tuple[str, ...]
    risk: str
    destructive: bool
    args_schema: Mapping[str, ArgumentSpec] = field(default_factory=dict)
    requires_explicit_dispatch: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskDefinition":
        return cls(
            task_type=str(data["task_type"]),
            title=str(data["title"]),
            description=str(data["description"]),
            platforms=tuple(data.get("platforms", ())),
            risk=str(data.get("risk", "low")),
            destructive=bool(data.get("destructive", False)),
            requires_explicit_dispatch=bool(data.get("requires_explicit_dispatch", False)),
            args_schema={name: ArgumentSpec.from_dict(spec) for name, spec in (data.get("args_schema") or {}).items()},
        )

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "task_type": self.task_type,
            "title": self.title,
            "description": self.description,
            "platforms": list(self.platforms),
            "risk": self.risk,
            "destructive": self.destructive,
            "args_schema": {name: spec.as_dict() for name, spec in self.args_schema.items()},
        }
        if self.requires_explicit_dispatch:
            out["requires_explicit_dispatch"] = True
        return out

    def validate_args(self, args: Mapping[str, Any] | None) -> None:
        args = args or {}
        for name in args:
            if name not in self.args_schema:
                raise TaskArgumentError(f"task_arg_{name}_unknown")
        for name, spec in self.args_schema.items():
            if spec.required and (name not in args or args.get(name) in (None, "")):
                raise TaskArgumentError(f"task_arg_{name}_required")
            if name in args:
                spec.validate(name, args[name])


_TASK_CATALOG_SOURCE = [
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

TASK_CATALOG: tuple[TaskDefinition, ...] = tuple(TaskDefinition.from_dict(item) for item in _TASK_CATALOG_SOURCE)
TASK_CATALOG_BY_TYPE: dict[str, TaskDefinition] = {item.task_type: item for item in TASK_CATALOG}
READONLY_TASK_CATALOG: list[dict[str, Any]] = [item.as_dict() for item in TASK_CATALOG]


def get_task_definition(task_type: str) -> TaskDefinition | None:
    return TASK_CATALOG_BY_TYPE.get(task_type)


def validate_task_args(task_type: str, args: Dict[str, Any]) -> None:
    """Validate analyst-supplied task args against the endpoint task catalog.

    This intentionally supports only the tiny schema vocabulary V1 uses today.
    The server must reject unsafe/unknown task shapes before work reaches endpoints.
    """
    entry = get_task_definition(task_type)
    if not entry:
        raise TaskArgumentError("task_not_allowlisted")
    entry.validate_args(args)
