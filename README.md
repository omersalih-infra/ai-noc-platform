# AI-Assisted NOC Platform: Alert Correlation, Deterministic Rules vs. a Local LLM

A dual-site AI-assisted Network Operations Center (NOC) platform built on a GNS3 lab. It ingests alerts from four independent signal sources and correlates them into incidents, then asks one question:

> Does a locally hosted LLM (`qwen2.5:7b` via Ollama) add real correlation value beyond a small set of deterministic time-window and topology-adjacency rules?

This is Project 5 of a portfolio of AI-assisted networking projects. It reuses the earlier projects as its signal sources.

## Signal sources

| Source | Origin | Adapter |
|---|---|---|
| Compliance | [network-compliance-auditor](https://github.com/omersalih-infra/network-compliance-auditor) (Project 1) | `compliance_to_alerts.py` |
| Anomaly (SNMP) | [network-anomaly-detector](https://github.com/omersalih-infra/network-anomaly-detector) (Project 2) | `anomaly_to_alerts.py` |
| Intrusion (Suricata) | [network-intrusion-detector](https://github.com/omersalih-infra/network-intrusion-detector) (Project 3) | `intrusion_to_alerts.py` |
| WAN fault | Project 4 (WAN Troubleshooting Copilot), `baseline_diagnostic.py` vendored in `vendor/` | `wan_fault_to_alerts.py` |

Every adapter emits the same alert schema:

```
event_id, timestamp, source, device, rule_or_signature, severity, description
```

## Lab topology

- **Site A (enterprise core):** R-A1 / R-A2 in an HSRP pair with OSPF area 0, an L3 core switch, VLAN 20 (IT) and VLAN 30 (Finance) distribution switches. Compliance and anomaly signals come from here.
- **Site B (perimeter / DMZ):** R-B1 / R-B2 in an HSRP pair, a FortiGate firewall, an edge router, and a DMZ web server running nginx + Suricata. The intrusion signal comes from here.
- **WAN:** two inter-site links (R-A1 to R-B1, R-A2 to R-B2). The WAN-fault signal is the only one that touches all four routers.

The full diagram and build narrative are in the report (`docs/Project5_Correlation_Report.docx`).

## Correlators

**`correlate_deterministic.py`** groups alerts using two auditable rules: the alerts occur within a time window (default 5 minutes), and they involve the same device or directly adjacent devices.

**`correlate_llm.py`** asks the local LLM only for grouping decisions (lists of `event_id`s plus short reasoning). All derived fields (sources, devices, highest severity, time span) are computed in Python from the original alerts, so the comparison measures grouping judgment only. Two prompt modes:

- default: raw alerts only, no topology information
- `--topology-hint`: adds a plain-English description of device adjacency

## Evaluation: six synthetic incident scenarios

| # | Scenario | Expected incidents | Deterministic | LLM (no hint) | LLM (topology hint) |
|---|---|---|---|---|---|
| 1 | True multi-signal incident | 1 | 1 | 3 | 2 |
| 2 | Coincidental unrelated events | 2 | 2 | n/a | 2 |
| 3 | Noisy / false-alarm mix | 5 | 5 | n/a | 3 |
| 4 | Multi-hop pivot attack | 2 (single-hop limit) | 2 | 2 | 2 |
| 5 | Compliance-only audit | 1 | 1 | n/a | 2 |
| 6 | Full four-source overlap | 2 | 2 | n/a | 3 |

Findings, in short:

- The deterministic correlator behaved exactly as designed in all six scenarios, including its known limitation: it cannot reason across more than one topology hop.
- The LLM reliably merged **single-hop** adjacency when given the topology hint (scenarios 1 and 6), but **never chained a second hop**, even when the full path was described.
- On scenario 4, built to test whether an LLM can close the multi-hop gap by matching an IP address in an alert to a router's address, it failed in both prompt conditions, even when handed the exact fact it needed.
- Time-weighting was inconsistent. It correctly kept distant events apart in scenario 2, but over-merged similarly distant events in scenario 3, once contradicting its own stated reasoning.
- One point in the LLM's favor: in scenario 5 it split a `PASS` finding from `FAIL` findings. That is a semantic distinction the rule engine cannot perceive.

This is a narrow, honest negative result for LLM-added value on this task with a 7B local model. It is a result about this model and these prompts, not about LLM correlation in general.

## Repository layout

```
correlate_deterministic.py   rule-based correlator
correlate_llm.py             Ollama / qwen2.5:7b correlator
compliance_to_alerts.py      signal adapters
anomaly_to_alerts.py
intrusion_to_alerts.py
wan_fault_to_alerts.py
vendor/baseline_diagnostic.py   WAN-fault rules, vendored from Project 4
scenarios/                   6 scenario inputs + saved deterministic/LLM results
sample_data/                 outputs of Projects 1 and 2 used by the adapters
sample_output/               example alert files and deterministic incidents
docs/                        full project report (Word)
```

## Running it

Requirements: Python 3.9+, and for the LLM correlator a local Ollama instance with the model pulled.

```bash
pip install -r requirements.txt
ollama pull qwen2.5:7b
```

Deterministic correlation of a scenario (no LLM needed):

```bash
python3 correlate_deterministic.py --input scenarios/scenario_1_true_incident.json --output incidents_1.json
```

LLM correlation, with and without the topology hint:

```bash
python3 correlate_llm.py --input scenarios/scenario_1_true_incident.json --output incidents_1_llm.json
python3 correlate_llm.py --input scenarios/scenario_1_true_incident.json --output incidents_1_llm_topo.json --topology-hint
```

Generate alert files from the signal sources:

```bash
python3 compliance_to_alerts.py                 # reads sample_data/audit_results.json
python3 anomaly_to_alerts.py                    # reads sample_data/anomaly_results_threshold.json
python3 intrusion_to_alerts.py path/to/eve.json # Suricata eve.json from your own sensor
python3 wan_fault_to_alerts.py --baseline baseline.json --fault fault.json
```

The WAN-fault evidence bundles (`baseline.json`, `fault.json`) are produced by the Project 4 collector and are not included here.

### Note on LLM run time

`qwen2.5:7b` ran slowly on the CPU-only lab VM (a trivial prompt took over a minute). `correlate_llm.py` therefore uses a 600-second HTTP timeout, and each scenario run takes a few minutes. That is expected, not a hang.

## Notes on the data

- The lab uses private `10.x.x.x` addressing inside an isolated GNS3 environment. Example attacker addresses in scenario files use RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`).
- No credentials, raw device configurations, or Suricata logs are included. The signal-source results in `sample_data/` contain only structured pass/fail findings.
- The correlator expects `qwen2.5:7b` at `http://localhost:11434`. Edit `OLLAMA_URL` and `MODEL` at the top of `correlate_llm.py` to change that.

## License

MIT, see `LICENSE`.
