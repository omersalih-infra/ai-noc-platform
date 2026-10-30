#!/usr/bin/env python3
"""
correlate_deterministic.py

Deterministic (non-LLM) alert correlator for Project 5. Merges alerts from
all four signal sources (compliance, anomaly, intrusion, wan_fault) and
groups them into incidents using two simple, auditable rules:

  1. TIME WINDOW: alerts must occur within WINDOW_MINUTES of each other.
  2. TOPOLOGY ADJACENCY: alerts must involve the same device, or devices
     that are directly adjacent in the network topology (see ADJACENCY).

This is the ground-truth baseline the LLM correlator (correlate_llm.py) is
compared against, following the same AI-vs-deterministic pattern used by
every prior project in this portfolio (threshold detector vs. Isolation
Forest, compliance rule engine vs. LLM report, etc.).

Usage:
    python3 correlate_deterministic.py --input alerts_compliance.json alerts_intrusion.json alerts_anomaly.json alerts_wan_fault.json --output incidents_deterministic.json
    python3 correlate_deterministic.py --input *.json --window 5
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

WINDOW_MINUTES_DEFAULT = 5

# Undirected topology adjacency. A device is always considered adjacent to
# itself; this only needs to list *other* devices each one is directly
# connected to.
ADJACENCY = {
    "R-A1": {"R-A2", "R-B1"},
    "R-A2": {"R-A1", "R-B2"},
    "R-B1": {"R-A1", "R-B2", "DMZ-Web"},
    "R-B2": {"R-A2", "R-B1", "DMZ-Web"},
    "DMZ-Web": {"R-B1", "R-B2"},
}


def parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def devices_related(dev_a: str, dev_b: str) -> bool:
    """True if dev_a and dev_b are the same device, or directly adjacent.
    Handles multi-device fields (e.g. wan_fault's 'R-A1, R-A2' from an
    area-mismatch finding) by splitting on comma and checking all pairs."""
    devs_a = [d.strip() for d in dev_a.split(",")]
    devs_b = [d.strip() for d in dev_b.split(",")]
    for a in devs_a:
        for b in devs_b:
            if a == b:
                return True
            if b in ADJACENCY.get(a, set()):
                return True
    return False


def load_alerts(paths: list) -> list:
    alerts = []
    for path in paths:
        with open(path) as f:
            data = json.load(f)
        alerts.extend(data)
    return alerts


def correlate(alerts: list, window_minutes: int) -> list:
    """Union-find style grouping: two alerts merge into the same incident
    if they're within the time window AND devices are related."""
    n = len(alerts)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    timestamps = [parse_timestamp(a["timestamp"]) for a in alerts]

    for i in range(n):
        for j in range(i + 1, n):
            delta = abs((timestamps[i] - timestamps[j]).total_seconds())
            if delta <= window_minutes * 60 and devices_related(alerts[i]["device"], alerts[j]["device"]):
                union(i, j)

    groups = {}
    for i in range(n):
        root = find(i)
        groups.setdefault(root, []).append(alerts[i])

    incidents = []
    for idx, (root, members) in enumerate(sorted(groups.items(), key=lambda kv: min(
            parse_timestamp(a["timestamp"]) for a in kv[1])), start=1):
        members_sorted = sorted(members, key=lambda a: a["timestamp"])
        sources = sorted(set(a["source"] for a in members_sorted))
        devices = sorted(set(a["device"] for a in members_sorted))
        severities = [a["severity"] for a in members_sorted]
        highest_severity = max(severities, key=lambda s: ["low", "medium", "high", "critical"].index(s))

        incidents.append({
            "incident_id": f"INC-{idx:03d}",
            "alert_count": len(members_sorted),
            "sources_involved": sources,
            "devices_involved": devices,
            "highest_severity": highest_severity,
            "time_span": {
                "start": members_sorted[0]["timestamp"],
                "end": members_sorted[-1]["timestamp"],
            },
            "alerts": members_sorted,
        })

    return incidents


def main():
    parser = argparse.ArgumentParser(description="Deterministic time-window + topology-adjacency alert correlator")
    parser.add_argument("--input", nargs="+", required=True, help="One or more alerts_*.json files to merge and correlate")
    parser.add_argument("--output", default="incidents_deterministic.json", help="Output file for grouped incidents")
    parser.add_argument("--window", type=int, default=WINDOW_MINUTES_DEFAULT, help="Time window in minutes (default: 5)")
    args = parser.parse_args()

    alerts = load_alerts(args.input)
    incidents = correlate(alerts, args.window)

    with open(args.output, "w") as f:
        json.dump(incidents, f, indent=2)

    print(f"[+] Loaded {len(alerts)} alerts from {len(args.input)} file(s)")
    print(f"[+] Grouped into {len(incidents)} incident(s) (window={args.window}min)")
    for inc in incidents:
        print(f"    {inc['incident_id']}: {inc['alert_count']} alert(s), "
              f"sources={inc['sources_involved']}, devices={inc['devices_involved']}, "
              f"severity={inc['highest_severity']}")
    print(f"[+] Written to {args.output}")


if __name__ == "__main__":
    main()
