#!/usr/bin/env python3
"""
wan_fault_to_alerts.py

Runs Project 4's deterministic diagnose() function (imported directly from
baseline_diagnostic.py, no re-implementation) against a baseline and a fault
evidence bundle, then converts each plain-text finding into the shared alert
schema used across all Project 5 signal sources:

    event_id, timestamp, source, device, rule_or_signature, severity, description

Usage:
    python3 wan_fault_to_alerts.py --baseline <path> --fault <path>
"""

import argparse
import importlib.util
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# baseline_diagnostic.py is vendored from the Project 4 repo. Set PROJECT4_DIR
# to use a different checkout instead.
PROJECT4_DIR = Path(os.environ.get("PROJECT4_DIR", Path(__file__).resolve().parent / "vendor"))
OUTPUT_FILE = Path("alerts_wan_fault.json")

# Category -> (severity, rule label) mapping, based on the prefix
# diagnose() puts at the start of every finding string.
CATEGORY_MAP = [
    ("INTERFACE DOWN", "high", "WAN Fault: Interface Down"),
    ("HSRP STATE CHANGE", "critical", "WAN Fault: HSRP Failover"),
    ("OSPF ADJACENCY CHANGE", "high", "WAN Fault: OSPF Adjacency Lost"),
    ("OSPF AREA MISMATCH", "medium", "WAN Fault: OSPF Area Mismatch"),
    ("REACHABILITY REGRESSION", "critical", "WAN Fault: Reachability Regression"),
    ("ACL DENY HITS", "critical", "WAN Fault: ACL Deny Hits"),
]


def load_diagnose_function():
    """Import diagnose() directly from Project 4's baseline_diagnostic.py
    rather than re-implementing or re-parsing its printed output."""
    module_path = PROJECT4_DIR / "baseline_diagnostic.py"
    spec = importlib.util.spec_from_file_location("baseline_diagnostic", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.diagnose


def classify(finding: str):
    for prefix, severity, rule in CATEGORY_MAP:
        if finding.startswith(prefix):
            return severity, rule
    return "medium", "WAN Fault: Unclassified Finding"


def extract_device(finding: str) -> str:
    """Best-effort device extraction from a finding string. Most findings
    start with 'CATEGORY: <device> ...'; area-mismatch findings can name
    multiple devices, so all of them are captured comma-separated."""
    if finding.startswith("OSPF AREA MISMATCH"):
        after_colon = finding.split(":", 1)[-1].strip()
        devices = [entry.strip().split()[0] for entry in after_colon.split(",") if entry.strip()]
        return ", ".join(devices)

    after_colon = finding.split(":", 1)[-1].strip()
    return after_colon.split()[0] if after_colon else "unknown"


def build_alert(finding: str) -> dict:
    severity, rule = classify(finding)
    device = extract_device(finding)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "wan_fault",
        "device": device,
        "rule_or_signature": rule,
        "severity": severity,
        "description": finding,
    }


def main():
    parser = argparse.ArgumentParser(description="Convert WAN-fault diagnostic findings into the shared alert schema")
    parser.add_argument("--baseline", required=True, help="Path to baseline evidence bundle JSON")
    parser.add_argument("--fault", required=True, help="Path to fault evidence bundle JSON")
    args = parser.parse_args()

    diagnose = load_diagnose_function()

    with open(args.baseline) as f:
        baseline = json.load(f)
    with open(args.fault) as f:
        fault = json.load(f)

    findings = diagnose(baseline, fault)
    alerts = [build_alert(f) for f in findings]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"[OK] Wrote {len(alerts)} wan_fault events to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
