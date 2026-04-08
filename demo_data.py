"""
demo_data.py
============
Generates synthetic ICS/OT log data for demo mode.
Patterns are based on real attack behaviors documented in:
  - The YouTube video (Guardian AST, Conpot, S7-300 attacks)
  - CISA ICS-CERT advisories
  - MITRE ATT&CK for ICS case studies (Stuxnet, Industroyer, Triton)
  - Shodan-exposed ICS device attack patterns
"""

import random
from datetime import datetime, timedelta


def _ts(offset_hours=0, offset_minutes=0):
    """Generate a realistic timestamp."""
    base = datetime(2025, 3, 1, 9, 0, 0)
    delta = timedelta(
        hours=offset_hours + random.uniform(0, 0.5),
        minutes=offset_minutes
    )
    return (base + delta).isoformat()


def generate_demo_logs() -> list:
    """
    Returns a mixed list of normal baseline ICS traffic and attack traffic.
    Simulates two weeks of Conpot honeypot data compressed for demo purposes.
    """
    logs = []

    # ── Normal baseline traffic ──────────────────────────────────────────────
    # Internal engineering workstation doing routine Modbus reads
    for i in range(80):
        logs.append({
            "timestamp": _ts(offset_hours=i * 0.5),
            "remote_host": f"192.168.1.{random.randint(10, 30)}",
            "remote_port": random.randint(49152, 65535),
            "local_port": 502,
            "protocol": "modbus",
            "session_duration": round(random.uniform(0.1, 2.0), 3),
            "is_attack": False,
            "request": {
                "function_code": random.choice([1, 3, 4]),  # Read only
                "address": random.randint(0, 99),
                "count": random.randint(1, 10),
                "unit_id": 1,
            }
        })

    # Internal SNMP polling (network management, normal)
    for i in range(30):
        logs.append({
            "timestamp": _ts(offset_hours=i),
            "remote_host": "192.168.1.5",
            "remote_port": random.randint(49152, 65535),
            "local_port": 161,
            "protocol": "snmp",
            "session_duration": round(random.uniform(0.05, 0.3), 3),
            "is_attack": False,
            "request": {
                "operation": "get",
                "oid": "1.3.6.1.2.1.1.1",
                "community": "internal_ro",  # Non-default community string
                "version": 2,
            }
        })

    # Normal S7comm reads from engineering workstation
    for i in range(25):
        logs.append({
            "timestamp": _ts(offset_hours=i * 2),
            "remote_host": "192.168.1.15",
            "remote_port": random.randint(49152, 65535),
            "local_port": 102,
            "protocol": "s7comm",
            "session_duration": round(random.uniform(0.2, 1.5), 3),
            "is_attack": False,
            "request": {
                "pdu_type": 1,             # Job request (normal)
                "function": "read_var",
                "db_number": random.randint(1, 10),
            }
        })

    # ── Attack traffic — Guardian AST (from the YouTube video) ───────────────
    # Attacker discovered AST on Shodan, begins enumeration
    logs.append({
        "timestamp": _ts(offset_hours=24, offset_minutes=13),
        "remote_host": "45.33.32.156",     # Simulated external Shodan scanner IP
        "remote_port": 54321,
        "local_port": 10001,
        "protocol": "guardian",
        "session_duration": 0.8,
        "is_attack": True,
        "request": {"command": "I20100"},  # Get in-tank inventory
    })

    logs.append({
        "timestamp": _ts(offset_hours=24, offset_minutes=14),
        "remote_host": "45.33.32.156",
        "remote_port": 54322,
        "local_port": 10001,
        "protocol": "guardian",
        "session_duration": 0.4,
        "is_attack": True,
        "request": {"command": "I91300"},  # FULL SYSTEM DUMP — highest risk
    })

    logs.append({
        "timestamp": _ts(offset_hours=24, offset_minutes=18),
        "remote_host": "45.33.32.156",
        "remote_port": 54323,
        "local_port": 10001,
        "protocol": "guardian",
        "session_duration": 0.3,
        "is_attack": True,
        "request": {"command": "I20300"},  # Get alarm history
    })

    # ── Attack traffic — Siemens S7-300 fingerprinting (from the video) ──────
    # Attacker enumerates S7 PLC using IEC 104 / S7comm probing
    logs.append({
        "timestamp": _ts(offset_hours=36, offset_minutes=22),
        "remote_host": "198.51.100.42",
        "remote_port": 40001,
        "local_port": 102,
        "protocol": "s7comm",
        "session_duration": 2.1,
        "is_attack": True,
        "request": {
            "pdu_type": 7,              # Userdata — CPU info extraction
            "function": "cpu_services",
            "db_number": 0,
        }
    })

    logs.append({
        "timestamp": _ts(offset_hours=36, offset_minutes=25),
        "remote_host": "198.51.100.42",
        "remote_port": 40002,
        "local_port": 102,
        "protocol": "s7comm",
        "session_duration": 1.4,
        "is_attack": True,
        "request": {
            "pdu_type": 7,
            "function": "read_szl",     # Read system status list — full PLC info
            "db_number": 0,
        }
    })

    # ── Attack traffic — IEC 104 attacks (Industroyer pattern) ───────────────
    logs.append({
        "timestamp": _ts(offset_hours=48, offset_minutes=5),
        "remote_host": "203.0.113.99",
        "remote_port": 35000,
        "local_port": 2404,
        "protocol": "iec104",
        "session_duration": 0.6,
        "is_attack": True,
        "request": {
            "type_id": 100,    # C_IC_NA_1 — General interrogation (recon)
            "cot": 6,
            "ca": 1,
            "ioa": 0,
        }
    })

    logs.append({
        "timestamp": _ts(offset_hours=48, offset_minutes=8),
        "remote_host": "203.0.113.99",
        "remote_port": 35001,
        "local_port": 2404,
        "protocol": "iec104",
        "session_duration": 0.3,
        "is_attack": True,
        "request": {
            "type_id": 45,     # C_SC_NA_1 — Single command (ACTIVE ATTACK)
            "cot": 6,
            "ca": 1,
            "ioa": 2001,       # Target information object
        }
    })

    # ── Attack traffic — Modbus write from external IP ────────────────────────
    logs.append({
        "timestamp": _ts(offset_hours=60, offset_minutes=33),
        "remote_host": "91.108.4.200",
        "remote_port": 51200,
        "local_port": 502,
        "protocol": "modbus",
        "session_duration": 1.2,
        "is_attack": True,
        "request": {
            "function_code": 6,     # Write single register
            "address": 40001,
            "count": 1,
            "unit_id": 1,
        }
    })

    logs.append({
        "timestamp": _ts(offset_hours=60, offset_minutes=35),
        "remote_host": "91.108.4.200",
        "remote_port": 51201,
        "local_port": 502,
        "protocol": "modbus",
        "session_duration": 0.9,
        "is_attack": True,
        "request": {
            "function_code": 16,    # Write multiple registers
            "address": 40001,
            "count": 10,
            "unit_id": 1,
        }
    })

    # ── Attack traffic — SNMP with default community string ───────────────────
    for i in range(5):
        logs.append({
            "timestamp": _ts(offset_hours=72 + i * 0.1),
            "remote_host": "185.220.101.55",
            "remote_port": random.randint(40000, 60000),
            "local_port": 161,
            "protocol": "snmp",
            "session_duration": round(random.uniform(0.1, 0.5), 3),
            "is_attack": True,
            "request": {
                "operation": "get",
                "oid": "1.3.6.1.2.1.1",    # System OID tree — fingerprinting
                "community": "public",       # Default community string
                "version": 1,
            }
        })

    random.shuffle(logs)
    print(f"    Generated {len(logs)} log entries "
          f"({sum(1 for l in logs if l.get('is_attack'))} attacks, "
          f"{sum(1 for l in logs if not l.get('is_attack'))} baseline)")
    return logs
