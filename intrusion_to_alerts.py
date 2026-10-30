import json
import uuid

SEVERITY_MAP = {
    1: "high",
    2: "medium",
    3: "low",
}

def convert(eve_file, out_file):
    events = []
    with open(eve_file) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("event_type") != "alert":
                continue
            alert = entry["alert"]
            events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": entry["timestamp"],
                "source": "intrusion",
                "device": "DMZ-Web",
                "rule_or_signature": alert["signature"],
                "severity": SEVERITY_MAP.get(alert.get("severity"), "low"),
                "description": f"{entry.get('src_ip')} -> {entry.get('dest_ip')}:{entry.get('dest_port')} ({alert.get('category')})",
            })
    with open(out_file, "w") as f:
        json.dump(events, f, indent=2)
    print(f"[OK] Wrote {len(events)} intrusion events to {out_file}")

if __name__ == "__main__":
    import sys
    eve_file = sys.argv[1] if len(sys.argv) > 1 else "eve.json"
    convert(eve_file, "alerts_intrusion.json")
