#!/usr/bin/env python3
"""
correlate_llm.py

LLM-based alert correlator for Project 5, using a local Ollama instance
(qwen2.5:7b) instead of the hand-written rules in correlate_deterministic.py.
This is the AI side of the AI-vs-deterministic comparison the whole
correlation layer is built to test.

Design choice: the LLM is only ever asked to decide *which alerts belong
together* (a list of event_id groups, plus its reasoning for each group).
All derived fields (alert_count, sources_involved, devices_involved,
highest_severity, time_span) are then computed in Python from the original
alert data -- the same way correlate_deterministic.py computes them. This
keeps the comparison focused on the actual grouping *judgment*, not on
formatting differences between the two scripts.

Supports two prompt modes:
  --topology-hint       Include the topology/adjacency description in the
                         prompt, so the LLM has the same structural
                         information the deterministic correlator uses.
  (default, no flag)    Give the LLM only the raw alerts -- no topology
                         info -- to see whether it infers relationships
                         itself from IPs/device names/descriptions alone.
                         This is the more interesting condition for
                         scenario 4 (the multi-hop pivot with the
                         source-IP clue).

Usage:
    python3 correlate_llm.py --input scenarios/scenario_1_true_incident.json --output scenarios/incidents_1_llm.json
    python3 correlate_llm.py --input scenarios/scenario_4_pivot.json --output scenarios/incidents_4_llm.json --topology-hint
"""

import argparse
import json
import re
import sys
from datetime import datetime

import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:7b"

TOPOLOGY_DESCRIPTION = """
Network topology (for reference):
- R-A1 and R-A2 are a redundant router pair at Site A (enterprise core), directly connected to each other.
- R-B1 and R-B2 are a redundant router pair at Site B (perimeter/DMZ), directly connected to each other.
- R-A1 has a WAN link directly to R-B1.
- R-A2 has a WAN link directly to R-B2.
- R-B1 and R-B2 both sit directly in front of DMZ-Web (a DMZ web server behind a firewall).
- R-A1's own IP address is 10.10.1.2. R-A2's own IP address is 10.10.1.3.
- A network event on one device can cause a related, closely-timed effect on a directly connected device.
"""

SYSTEM_PROMPT_BASE = """You are a NOC (Network Operations Center) alert correlation assistant.
You will be given a list of alerts from four different monitoring systems:
compliance audits, SNMP-based anomaly detection, an intrusion detection system (Suricata),
and a WAN-fault diagnostic tool.

Your job is to group these alerts into INCIDENTS: alerts that represent the same underlying
real-world network event or a closely related chain of events, based on timing and any
relationship between the devices or IP addresses involved. Alerts that are unrelated,
meaning different times, different unrelated devices, or routine unrelated findings, should
NOT be grouped together, even if there are only a few alerts total.

Respond with ONLY a JSON array, no other text, no markdown code fences. Each element of the
array must be an object with exactly these two fields:
  "event_ids": a list of the event_id strings that belong to this one incident
  "reasoning": a short one or two sentence explanation of why these alerts were grouped together

Every event_id from the input must appear in exactly one group. An alert with no related
alerts should be its own group of one.
"""


def build_prompt(alerts: list, topology_hint: bool) -> str:
    system = SYSTEM_PROMPT_BASE
    if topology_hint:
        system += "\n" + TOPOLOGY_DESCRIPTION

    alerts_json = json.dumps(alerts, indent=2)
    user = f"Here are the alerts to correlate:\n\n{alerts_json}"
    return system, user


def call_ollama(system: str, user: str) -> str:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0},
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=600)
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def extract_json_array(text: str):
    """The model is asked for JSON-only, but strip markdown fences and grab
    the outermost [...] block defensively in case it adds anything else."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text)
    text = re.sub(r"```$", "", text)
    text = text.strip()

    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError("No JSON array found in model output:\n" + text)
    return json.loads(text[start:end + 1])


def severity_rank(sev: str) -> int:
    return ["low", "medium", "high", "critical"].index(sev)


def build_incident(group: dict, alerts_by_id: dict, idx: int) -> dict:
    members = [alerts_by_id[eid] for eid in group["event_ids"] if eid in alerts_by_id]
    members_sorted = sorted(members, key=lambda a: a["timestamp"])

    sources = sorted(set(a["source"] for a in members_sorted))
    devices = sorted(set(a["device"] for a in members_sorted))
    highest_severity = max((a["severity"] for a in members_sorted), key=severity_rank)

    return {
        "incident_id": f"LLM-INC-{idx:03d}",
        "alert_count": len(members_sorted),
        "sources_involved": sources,
        "devices_involved": devices,
        "highest_severity": highest_severity,
        "time_span": {
            "start": members_sorted[0]["timestamp"] if members_sorted else None,
            "end": members_sorted[-1]["timestamp"] if members_sorted else None,
        },
        "llm_reasoning": group.get("reasoning", ""),
        "alerts": members_sorted,
    }


def main():
    parser = argparse.ArgumentParser(description="LLM-based alert correlator (Ollama qwen2.5:7b)")
    parser.add_argument("--input", nargs="+", required=True, help="One or more alerts_*.json files to merge and correlate")
    parser.add_argument("--output", default="incidents_llm.json", help="Output file for grouped incidents")
    parser.add_argument("--topology-hint", action="store_true", help="Include topology/adjacency description in the prompt")
    args = parser.parse_args()

    alerts = []
    for path in args.input:
        with open(path) as f:
            alerts.extend(json.load(f))
    alerts_by_id = {a["event_id"]: a for a in alerts}

    system, user = build_prompt(alerts, args.topology_hint)

    print(f"[+] Sending {len(alerts)} alerts to {MODEL} (topology_hint={args.topology_hint}) ...")
    raw_response = call_ollama(system, user)

    try:
        groups = extract_json_array(raw_response)
    except ValueError as e:
        print(f"[ERROR] Could not parse model output as JSON: {e}")
        sys.exit(1)

    incidents = [build_incident(g, alerts_by_id, idx) for idx, g in enumerate(groups, start=1)]

    with open(args.output, "w") as f:
        json.dump(incidents, f, indent=2)

    print(f"[+] Grouped into {len(incidents)} incident(s)")
    for inc in incidents:
        print(f"    {inc['incident_id']}: {inc['alert_count']} alert(s), "
              f"sources={inc['sources_involved']}, devices={inc['devices_involved']}, "
              f"severity={inc['highest_severity']}")
        if inc["llm_reasoning"]:
            print(f"        reasoning: {inc['llm_reasoning']}")
    print(f"[+] Written to {args.output}")


if __name__ == "__main__":
    main()
