import json
import uuid
from datetime import datetime, timezone

SEVERITY_MAP = {
    "No default SNMP community": "high",
    "Password encryption enabled": "medium",
    "SSH-only remote access": "high",
    "NTP configured": "low",
    "Syslog host configured": "medium",
    "Adequate logging level": "low",
    "HTTP server disabled": "medium",
    "Login banner configured": "low",
    "Strong local authentication": "high",
    "Domain name configured": "low",
}

def convert(audit_file, out_file):
    with open(audit_file) as f:
        results = json.load(f)
    events = []
    now = datetime.now(timezone.utc).isoformat()
    for device_result in results:
        device = device_result["device"]
        for finding in device_result["findings"]:
            if finding["status"] == "FAIL":
                events.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": now,
                    "source": "compliance",
                    "device": device,
                    "rule_or_signature": finding["rule"],
                    "severity": SEVERITY_MAP.get(finding["rule"], "low"),
                    "description": finding.get("evidence", finding["rule"]),
                })
    with open(out_file, "w") as f:
        json.dump(events, f, indent=2)
    print(f"[OK] Wrote {len(events)} compliance events to {out_file}")

if __name__ == "__main__":
    import sys
    audit_file = sys.argv[1] if len(sys.argv) > 1 else "sample_data/audit_results.json"
    convert(audit_file, "alerts_compliance.json")
