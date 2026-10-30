#!/usr/bin/env python3
"""
anomaly_to_alerts.py

Reads anomaly-detector's threshold results (anomaly_results_threshold.json)
and converts each finding into the shared alert schema used across all
Project 5 signal sources:

    event_id, timestamp, source, device, rule_or_signature, severity, description

Severity is derived from how far the observed value exceeds its own
threshold (value / threshold), since the threshold detector only ever
emits entries that already cleared the 10x-median bar — the question is
how far past it they went, not whether they're anomalies at all.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Input defaults to the bundled sample; point INPUT_FILE at your own
# anomaly-detector output (see README) to run against fresh data.
INPUT_FILE = Path(__file__).resolve().parent / "sample_data" / "anomaly_results_threshold.json"
OUTPUT_FILE = Path("alerts_anomaly.json")


def severity_for_ratio(ratio: float) -> str:
    if ratio >= 10:
        return "critical"
    if ratio >= 5:
        return "high"
    if ratio >= 2:
        return "medium"
    return "low"


def normalize_timestamp(raw: str) -> str:
    """Convert 'YYYY-MM-DD HH:MM:SS.ffffff+00:00' style timestamps into
    the same ISO-8601-with-offset style used by the other two adapters."""
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        # Fall back to the raw string rather than dropping the event
        return raw


def build_alert(finding: dict) -> dict:
    value = finding["value"]
    threshold = finding["threshold"]
    ratio = value / threshold if threshold else float("inf")

    metric = finding["metric"]
    device = finding["device"]

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": normalize_timestamp(finding["timestamp"]),
        "source": "anomaly",
        "device": device,
        "rule_or_signature": f"SNMP Threshold Anomaly ({metric})",
        "severity": severity_for_ratio(ratio),
        "description": (
            f"{device}: {metric} = {value:.0f} "
            f"(baseline median {finding['device_median']:.0f}, "
            f"threshold {threshold:.0f}, "
            f"{ratio:.1f}x threshold)"
        ),
    }


def main():
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    with open(INPUT_FILE) as f:
        findings = json.load(f)

    alerts = [build_alert(f) for f in findings]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"[OK] Wrote {len(alerts)} anomaly events to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
