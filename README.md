# ICS/OT AI Threat Detection System

A local, air-gapped AI threat detection system for Industrial Control System (ICS) 
and Operational Technology (OT) environments. Designed for Conpot honeypot log 
analysis, SCADA security monitoring, and SOC analyst assistance.

**Resume project status:** High-level | ICS/OT + AI + MITRE ATT&CK for ICS

---

## What It Does

- **Layer 1 — Anomaly Detection** (Isolation Forest): Detects novel/unknown attack 
  patterns by learning what normal ICS traffic looks like. No labeled data required.

- **Layer 2 — Threat Classification** (Random Forest + Rule Engine): Classifies 
  threats into categories: `reconnaissance`, `exploit_attempt`, `active_attack`, 
  `lateral_movement`. Rule engine encodes expert ICS security knowledge that ML 
  alone cannot capture.

- **MITRE ATT&CK for ICS Mapping**: Every alert is automatically mapped to relevant 
  MITRE ATT&CK for ICS techniques (T0840, T0855, T0888, etc.)

- **Protocol Support**: Modbus/TCP, IEC 60870-5-104, Siemens S7comm, SNMP, 
  Guardian AST (automatic tank gauges)

---

## Attack Patterns Detected

Based on real-world ICS threat intelligence:

| Attack | Source | Techniques Detected |
|--------|--------|---------------------|
| Guardian AST I91300 system dump | Shodan-exposed ATGs | T0888, T0840, T0861 |
| Siemens S7-300 CPU enumeration | Stuxnet-style recon | T0888, T0846, T0861 |
| IEC 104 control commands | Industroyer/Crashoverride | T0855, T0856 |
| Modbus write from external IP | Generic ICS attacks | T0855, T0801 |
| SNMP default community string | Device fingerprinting | T0888, T0841 |

---

## Quick Start

```bash
# 1. Install dependencies (Python 3.9+)
pip install -r requirements.txt

# 2. Run demo with synthetic attack data
python main.py --mode demo

# 3. Train on your own Conpot logs
python main.py --mode train --logs data/your_conpot_logs.json

# 4. Detect threats in new logs
python main.py --mode detect --logs data/new_logs.json
```

---

## Conpot Log Format

Your Conpot honeypot logs should be in JSON format. Export them with:

```bash
# From your Conpot honeypot directory
python -c "
import sqlite3, json
conn = sqlite3.connect('conpot.db')
rows = conn.execute('SELECT * FROM events').fetchall()
# Convert to JSON and save
"
```

Or configure Conpot to output JSON logs directly in `conpot.cfg`:
```ini
[loggers]
output_plugins = jsonlog
```

---

## Output

Results are printed to terminal with severity color-coding and saved to 
`output/threat_report.json` in SIEM-ready format.

```
[CRITICAL] 2025-03-01T10:14:00
  Source IP  : 45.33.32.156
  Protocol   : GUARDIAN
  Event      : guardian_ast_get_system_info
  Category   : reconnaissance
  Anomaly    : -0.4231
  MITRE ICS  : T0888, T0840, T0861
```

---

## Architecture

```
Conpot Logs (JSON)
      │
      ▼
 log_parser.py          ← Protocol-aware feature extraction
      │                    (Modbus, IEC104, S7comm, SNMP, AST)
      ▼
 detector.py            ← Layer 1: Isolation Forest anomaly detection
      │                    Layer 2: Random Forest + rule engine classifier
      ▼
 mitre_mapper.py        ← Maps events to MITRE ATT&CK for ICS techniques
      │
      ▼
 reporter.py            ← Terminal output + JSON report generation
```

---

## Why Local?

- **No data exfiltration**: ICS/OT log data never leaves your network
- **Air-gap compatible**: Works in fully isolated OT environments
- **Compliance friendly**: Meets NERC CIP, NIST 800-82, IEC 62443 data 
  handling requirements
- **No cloud dependency**: Runs on any machine with Python 3.9+

---

## Extending the Model

**Add new attack signatures** in `mitre_mapper.py` under `MAPPING_RULES`.

**Add new protocol support** in `log_parser.py` with a new `_parse_X()` method.

**Retrain on your own data** after collecting 2+ weeks of Conpot honeypot logs 
for a model tuned to your environment's baseline traffic.

---

## Certifications This Project Supports

- CompTIA CySA+ (CS0-003): Detection engineering, log analysis
- GICSP: ICS/OT security fundamentals  
- MITRE ATT&CK for ICS framework proficiency

---

*Built as a resume project for ICS/OT cybersecurity career development.*
*Threat patterns sourced from CISA ICS-CERT, MITRE ATT&CK for ICS,*
*Dragos threat intelligence, and documented Conpot honeypot research.*
