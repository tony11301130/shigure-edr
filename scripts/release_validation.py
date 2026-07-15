#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from open_edr_mdr_agent.api.release_validation import load_release_report, validate_release_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Shigure commercial MVP release gate report.")
    parser.add_argument("--report", required=True, help="Path to a JSON release report with automated, lab, load, and blocker evidence.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable validation output.")
    args = parser.parse_args()

    result = validate_release_report(load_release_report(args.report))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"release_validation_status={result['status']}")
        for failure in result["failures"]:
            print(f"failure={failure}")
        for warning in result["warnings"]:
            print(f"warning={warning}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
