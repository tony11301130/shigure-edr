from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

REQUIRED_AUTOMATED_GATES = {
    "python_tests",
    "go_tests",
    "m0_smoke",
    "golden_dataset_replay",
    "detection_replay",
    "mdr_workspace_loop",
    "safe_response_evidence",
}

REQUIRED_LAB_GATES = {
    "windows_service_runtime",
    "windows_etw_process",
    "windows_event_log_subscription",
    "storage_load_retention",
}

REQUIRED_LOAD_SCENARIOS = {
    "alert_queue",
    "endpoint_timeline",
    "process_graph",
    "indicator_hunt",
    "case_evidence",
}

RELEASE_BLOCKERS = {
    "silent_graph_uncertainty",
    "destructive_task_exposure",
    "unaudited_evidence",
    "missing_workflow_steps",
    "missing_windows_runtime_validation",
    "unbounded_spool",
    "production_dev_token_shortcuts",
}

REQUIRED_DOCUMENTS = {
    "docs/RELEASE_VALIDATION.md",
    "docs/WINDOWS_RELEASE_LAB.md",
    "docs/WINDOWS_ETW_PROCESS_LAB.md",
    "docs/WINDOWS_EVENT_LOG_SUBSCRIPTION_LAB.md",
    "docs/LOAD_TESTING.md",
}


def load_release_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def validate_release_report(report: Mapping[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []

    _validate_gate_map(failures, "automated", report.get("automated_gates"), REQUIRED_AUTOMATED_GATES)
    _validate_gate_map(failures, "lab", report.get("lab_gates"), REQUIRED_LAB_GATES)
    _validate_load_scenarios(failures, report.get("load_scenarios"))
    _validate_known_gap_review(failures, warnings, report.get("known_gap_review"))
    _validate_docs(failures, report.get("documents"))

    return {
        "status": "failed" if failures else "passed",
        "failures": failures,
        "warnings": warnings,
        "required": {
            "automated_gates": sorted(REQUIRED_AUTOMATED_GATES),
            "lab_gates": sorted(REQUIRED_LAB_GATES),
            "load_scenarios": sorted(REQUIRED_LOAD_SCENARIOS),
            "release_blockers": sorted(RELEASE_BLOCKERS),
            "documents": sorted(REQUIRED_DOCUMENTS),
        },
    }


def _validate_gate_map(failures: list[str], gate_group: str, raw_gates: Any, required: set[str]) -> None:
    if not isinstance(raw_gates, Mapping):
        failures.append(f"missing_{gate_group}_gates")
        return
    for gate_id in sorted(required):
        gate = raw_gates.get(gate_id)
        if not isinstance(gate, Mapping):
            failures.append(f"missing_gate:{gate_id}")
            continue
        status = str(gate.get("status") or "").lower()
        if status != "passed":
            failures.append(f"gate_not_passed:{gate_id}:{status or 'missing'}")
        if not str(gate.get("evidence") or "").strip():
            failures.append(f"gate_missing_evidence:{gate_id}")


def _validate_load_scenarios(failures: list[str], raw_scenarios: Any) -> None:
    if not isinstance(raw_scenarios, list):
        failures.append("missing_load_scenarios")
        return
    scenarios = {str(item.get("id")): item for item in raw_scenarios if isinstance(item, Mapping) and item.get("id")}
    for scenario_id in sorted(REQUIRED_LOAD_SCENARIOS):
        scenario = scenarios.get(scenario_id)
        if not isinstance(scenario, Mapping):
            failures.append(f"missing_load_scenario:{scenario_id}")
            continue
        targets = scenario.get("metric_targets")
        if not isinstance(targets, list) or not targets:
            failures.append(f"load_scenario_missing_metric:{scenario_id}")


def _validate_known_gap_review(failures: list[str], warnings: list[str], raw_review: Any) -> None:
    if not isinstance(raw_review, Mapping):
        failures.append("missing_known_gap_review")
        return
    status = str(raw_review.get("status") or "").lower()
    if status != "passed":
        failures.append(f"known_gap_review_not_passed:{status or 'missing'}")
    if not str(raw_review.get("evidence") or "").strip():
        failures.append("known_gap_review_missing_evidence")
    blockers = raw_review.get("blockers")
    if not isinstance(blockers, Mapping):
        failures.append("missing_release_blocker_review")
        return
    for blocker_id in sorted(RELEASE_BLOCKERS):
        if blocker_id not in blockers:
            warnings.append(f"release_blocker_not_reviewed:{blocker_id}")
            continue
        if bool(blockers[blocker_id]):
            failures.append(f"release_blocker:{blocker_id}")


def _validate_docs(failures: list[str], raw_docs: Any) -> None:
    if not isinstance(raw_docs, list):
        failures.append("missing_release_documents")
        return
    docs = {str(item) for item in raw_docs}
    for doc in sorted(REQUIRED_DOCUMENTS):
        if doc not in docs:
            failures.append(f"missing_doc:{doc}")
