from __future__ import annotations

from typing import Any, Dict, List


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
