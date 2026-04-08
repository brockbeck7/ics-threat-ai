"""
log_parser.py
=============
Parses Conpot honeypot logs and raw ICS protocol logs into
a normalized feature format the ML models can consume.

Supports:
  - Conpot JSON log format
  - Modbus/TCP events
  - IEC 60870-5-104 (IEC 104)
  - Siemens S7comm (S7-300/400 PLCs)
  - SNMP reconnaissance events
  - Guardian AST (automatic tank gauge) commands
"""

import re
from datetime import datetime


# Known malicious / suspicious Modbus function codes
MODBUS_SUSPICIOUS_FC = {
    0x01: "read_coils",
    0x02: "read_discrete_inputs",
    0x03: "read_holding_registers",
    0x04: "read_input_registers",
    0x05: "write_single_coil",
    0x06: "write_single_register",
    0x0F: "write_multiple_coils",
    0x10: "write_multiple_registers",
    0x17: "read_write_multiple_registers",  # Often used in recon
}

# Guardian AST commands seen in wild (from the video's research)
GUARDIAN_AST_COMMANDS = {
    "I20100": "get_in_tank_inventory",
    "I20200": "get_delivery_report",
    "I20300": "get_alarm_history",
    "I91300": "get_system_info",       # Highly suspicious - full system dump
    "I20400": "get_tank_thresholds",
    "S60200": "set_tank_label",        # Write command - critical
}

# S7comm PDU types for Siemens S7-300 fingerprinting
S7_SUSPICIOUS_PDUS = {
    0x01: "job_request",
    0x02: "ack",
    0x03: "ack_data",
    0x07: "userdata",           # Used for CPU info extraction
}

# IEC 104 ASDU type IDs
IEC104_SUSPICIOUS_TYPES = {
    100: "interrogation_command",   # C_IC_NA_1 - full data poll (recon)
    103: "clock_sync",              # C_CS_NA_1 - sometimes used pre-attack
    45:  "single_command",          # C_SC_NA_1 - control command (critical)
    46:  "double_command",          # C_DC_NA_1 - control command (critical)
}


class ConpotLogParser:
    """
    Parses Conpot honeypot JSON logs into normalized feature vectors
    suitable for the anomaly detector and classifier.
    """

    def parse_batch(self, raw_logs: list) -> list:
        """Parse a list of raw log entries."""
        parsed = []
        for entry in raw_logs:
            result = self.parse_entry(entry)
            if result:
                parsed.append(result)
        return parsed

    def parse_entry(self, entry: dict) -> dict:
        """Normalize a single log entry into feature dict."""
        protocol = entry.get("protocol", "unknown").lower()

        base = {
            "timestamp": entry.get("timestamp", datetime.utcnow().isoformat()),
            "src_ip": entry.get("remote_host", entry.get("src_ip", "0.0.0.0")),
            "src_port": int(entry.get("remote_port", entry.get("src_port", 0))),
            "dst_port": int(entry.get("local_port", entry.get("dst_port", 0))),
            "protocol": protocol,
            "session_duration": float(entry.get("session_duration", 0.0)),
            "data_length": len(str(entry.get("data_type", ""))),
            "is_attack": entry.get("is_attack", False),  # for labeled data
        }

        # Protocol-specific feature extraction
        if protocol == "modbus":
            base.update(self._parse_modbus(entry))
        elif protocol in ("iec104", "iec-104", "iec60870"):
            base.update(self._parse_iec104(entry))
        elif protocol in ("s7comm", "s7", "siemens"):
            base.update(self._parse_s7comm(entry))
        elif protocol == "snmp":
            base.update(self._parse_snmp(entry))
        elif protocol in ("guardian", "ast", "tank_gauge"):
            base.update(self._parse_guardian(entry))
        else:
            base.update(self._parse_generic(entry))

        # Derived features used by ML models
        base["is_write_operation"] = base.get("operation_type", "") in (
            "write", "command", "set", "control"
        )
        base["is_recon_indicator"] = base.get("event_type", "") in (
            "fingerprint", "scan", "enumerate", "interrogation", "sysinfo"
        )
        base["hour_of_day"] = self._extract_hour(base["timestamp"])
        base["is_after_hours"] = base["hour_of_day"] not in range(6, 20)
        base["ip_is_external"] = not self._is_rfc1918(base["src_ip"])

        return base

    def _parse_modbus(self, entry: dict) -> dict:
        raw = entry.get("request", {})
        fc = int(raw.get("function_code", 0))
        return {
            "event_type": "modbus_request",
            "function_code": fc,
            "function_name": MODBUS_SUSPICIOUS_FC.get(fc, f"fc_{fc}"),
            "register_address": int(raw.get("address", 0)),
            "register_count": int(raw.get("count", 0)),
            "operation_type": "write" if fc in (5, 6, 15, 16, 23) else "read",
            "unit_id": int(raw.get("unit_id", 1)),
        }

    def _parse_iec104(self, entry: dict) -> dict:
        raw = entry.get("request", {})
        asdu_type = int(raw.get("type_id", 0))
        return {
            "event_type": IEC104_SUSPICIOUS_TYPES.get(asdu_type, "iec104_data"),
            "asdu_type_id": asdu_type,
            "cause_of_transmission": int(raw.get("cot", 0)),
            "common_address": int(raw.get("ca", 0)),
            "information_object_address": int(raw.get("ioa", 0)),
            "operation_type": "control" if asdu_type in (45, 46, 47, 48) else "read",
        }

    def _parse_s7comm(self, entry: dict) -> dict:
        raw = entry.get("request", {})
        pdu_type = int(raw.get("pdu_type", 0))
        return {
            "event_type": "s7_" + S7_SUSPICIOUS_PDUS.get(pdu_type, "unknown"),
            "pdu_type": pdu_type,
            "function": raw.get("function", ""),
            "data_block": raw.get("db_number", 0),
            "operation_type": "read" if "read" in str(raw.get("function", "")).lower() else "write",
            # Userdata PDU type 7 used for CPU info dump — high risk
            "is_fingerprint": pdu_type == 7,
        }

    def _parse_snmp(self, entry: dict) -> dict:
        raw = entry.get("request", {})
        return {
            "event_type": "snmp_" + raw.get("operation", "get"),
            "oid": raw.get("oid", ""),
            "community_string": raw.get("community", "public"),
            "version": raw.get("version", 2),
            "operation_type": "read",
            # Querying system OID tree is fingerprinting
            "is_fingerprint": raw.get("oid", "").startswith("1.3.6.1.2.1.1"),
            "used_default_community": raw.get("community", "") in ("public", "private"),
        }

    def _parse_guardian(self, entry: dict) -> dict:
        raw = entry.get("request", {})
        cmd = raw.get("command", "")
        cmd_info = GUARDIAN_AST_COMMANDS.get(cmd, "unknown_command")
        return {
            "event_type": "guardian_ast_" + cmd_info,
            "command_code": cmd,
            "command_name": cmd_info,
            "operation_type": "set" if cmd.startswith("S") else "read",
            # System info dump I91300 is most suspicious
            "is_high_risk_command": cmd == "I91300",
        }

    def _parse_generic(self, entry: dict) -> dict:
        return {
            "event_type": entry.get("event_type", "generic"),
            "operation_type": "unknown",
            "is_fingerprint": False,
        }

    def _extract_hour(self, timestamp: str) -> int:
        try:
            return datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            ).hour
        except Exception:
            return 12

    def _is_rfc1918(self, ip: str) -> bool:
        """Check if IP is a private/internal address."""
        try:
            parts = list(map(int, ip.split(".")))
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
        except Exception:
            pass
        return False
