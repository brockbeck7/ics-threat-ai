"""
mitre_mapper.py
===============
Maps detected ICS threat events to MITRE ATT&CK for ICS techniques.
Reference: https://attack.mitre.org/matrices/ics/

Covers techniques observed in:
- Stuxnet (T0856, T0843, T0834)
- Industroyer/Crashoverride (T0855, T0831)
- Triton/TRISIS (T0857, T0800)
- Generic ICS reconnaissance (T0840, T0846, T0888)
- Guardian AST attacks (T0840, T0888)
"""

from typing import List, Dict


# Full MITRE ATT&CK for ICS technique reference
MITRE_ICS_TECHNIQUES = {
    "T0800": {
        "name": "Activate Firmware Update Mode",
        "tactic": "Inhibit Response Function",
        "description": "Adversaries may activate firmware update mode to enable further exploitation.",
    },
    "T0801": {
        "name": "Monitor Process State",
        "tactic": "Collection",
        "description": "Adversaries may gather information about the current state of a industrial process.",
    },
    "T0802": {
        "name": "Automated Collection",
        "tactic": "Collection",
        "description": "Adversaries may use automated techniques for collecting internal data.",
    },
    "T0830": {
        "name": "Adversary-in-the-Middle",
        "tactic": "Collection, Credential Access",
        "description": "Adversaries with privileged position intercept and alter ICS communications.",
    },
    "T0840": {
        "name": "Network Connection Enumeration",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate communication between devices to map the ICS environment.",
    },
    "T0841": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may scan for open ports or services on ICS devices.",
    },
    "T0842": {
        "name": "Network Sniffing",
        "tactic": "Discovery, Collection",
        "description": "Adversaries may passively sniff ICS protocol traffic.",
    },
    "T0843": {
        "name": "Program Download",
        "tactic": "Lateral Movement",
        "description": "Adversaries may transfer a new or modified program to a controller.",
    },
    "T0845": {
        "name": "Program Upload",
        "tactic": "Collection",
        "description": "Adversaries may attempt to upload a program from a PLC or controller.",
    },
    "T0846": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate remote systems on the ICS network.",
    },
    "T0847": {
        "name": "Replication Through Removable Media",
        "tactic": "Lateral Movement, Initial Access",
        "description": "Adversaries may move onto systems using removable media (Stuxnet initial vector).",
    },
    "T0855": {
        "name": "Unauthorized Command Message",
        "tactic": "Impair Process Control",
        "description": "Adversaries may send unauthorized commands to field controllers (Industroyer TTP).",
    },
    "T0856": {
        "name": "Spoof Reporting Message",
        "tactic": "Impair Process Control",
        "description": "Adversaries may spoof reporting messages to mislead operators about system state.",
    },
    "T0857": {
        "name": "System Firmware",
        "tactic": "Persistence, Inhibit Response Function",
        "description": "Adversaries may modify system firmware to persist in ICS devices (Triton/TRISIS).",
    },
    "T0858": {
        "name": "Change Credential",
        "tactic": "Persistence",
        "description": "Adversaries may modify credentials to maintain access to ICS devices.",
    },
    "T0861": {
        "name": "Point & Tag Identification",
        "tactic": "Discovery, Collection",
        "description": "Adversaries may identify control system tags and I/O points for targeting.",
    },
    "T0862": {
        "name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may manipulate hardware or software before delivery.",
    },
    "T0885": {
        "name": "Commonly Used Port",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate over commonly used ICS ports (Modbus:502, IEC104:2404).",
    },
    "T0886": {
        "name": "Remote Services",
        "tactic": "Initial Access, Lateral Movement",
        "description": "Adversaries may leverage remote services for initial access to ICS.",
    },
    "T0888": {
        "name": "Remote System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may gather information about remote ICS systems — seen in Guardian AST attacks.",
    },
}


# Mapping rules: (protocol, event_type, classification) → [technique_ids]
MAPPING_RULES = [

    # Guardian AST reconnaissance (from the YouTube video)
    {
        "match": {"protocol": "guardian", "event_type_contains": "get_system_info"},
        "techniques": ["T0888", "T0840", "T0861"],
        "notes": "Guardian AST I91300 command — full system info dump. Seen on Shodan-exposed ATGs.",
    },
    {
        "match": {"protocol": "guardian", "operation_type": "set"},
        "techniques": ["T0855", "T0856"],
        "notes": "Guardian AST write command — attempt to alter tank gauge thresholds.",
    },

    # Siemens S7-300 fingerprinting (from the video)
    {
        "match": {"protocol": "s7comm", "is_fingerprint": True},
        "techniques": ["T0888", "T0846", "T0861"],
        "notes": "S7comm userdata PDU — CPU/firmware enumeration. Pre-exploitation recon step.",
    },
    {
        "match": {"protocol": "s7comm", "operation_type": "write"},
        "techniques": ["T0843", "T0855"],
        "notes": "S7comm write operation — possible program modification (Stuxnet pattern T0843).",
    },

    # Modbus attacks
    {
        "match": {"protocol": "modbus", "operation_type": "read", "ip_is_external": True},
        "techniques": ["T0801", "T0840", "T0885"],
        "notes": "Modbus read from external IP — process state collection recon.",
    },
    {
        "match": {"protocol": "modbus", "operation_type": "write"},
        "techniques": ["T0855", "T0801"],
        "notes": "Modbus write command — unauthorized coil/register modification.",
    },

    # IEC 104 attacks (Industroyer used IEC 104 module)
    {
        "match": {"protocol": "iec104", "asdu_type_id_in": [45, 46, 47, 48]},
        "techniques": ["T0855", "T0856"],
        "notes": "IEC 104 control command — direct device control. Industroyer/Crashoverride TTP.",
    },
    {
        "match": {"protocol": "iec104", "asdu_type_id": 100},
        "techniques": ["T0801", "T0861", "T0840"],
        "notes": "IEC 104 general interrogation — full data poll for process state mapping.",
    },

    # SNMP reconnaissance
    {
        "match": {"protocol": "snmp", "used_default_community": True},
        "techniques": ["T0888", "T0841", "T0846"],
        "notes": "SNMP with default community string — device fingerprinting / discovery.",
    },

    # Generic classification-based mappings
    {
        "match": {"classification": "reconnaissance"},
        "techniques": ["T0840", "T0846"],
        "notes": "General network reconnaissance activity.",
    },
    {
        "match": {"classification": "exploit_attempt"},
        "techniques": ["T0855", "T0885"],
        "notes": "Exploit attempt against ICS device.",
    },
    {
        "match": {"classification": "active_attack"},
        "techniques": ["T0855", "T0856", "T0801"],
        "notes": "Active attack — direct device interaction detected.",
    },
    {
        "match": {"classification": "lateral_movement"},
        "techniques": ["T0843", "T0886"],
        "notes": "Lateral movement within ICS network.",
    },
]


class MitreICSMapper:
    """Maps parsed ICS events + classification to MITRE ATT&CK for ICS techniques."""

    def map(self, entry: dict, classification: str) -> List[Dict]:
        """
        Returns a list of matched MITRE ATT&CK for ICS techniques with context.
        """
        matched_ids = set()
        matched_notes = []

        entry_with_class = dict(entry)
        entry_with_class["classification"] = classification

        for rule in MAPPING_RULES:
            if self._matches(entry_with_class, rule["match"]):
                for tid in rule["techniques"]:
                    matched_ids.add(tid)
                matched_notes.append(rule.get("notes", ""))

        results = []
        for tid in sorted(matched_ids):
            technique = MITRE_ICS_TECHNIQUES.get(tid, {})
            results.append({
                "technique_id": tid,
                "technique_name": technique.get("name", "Unknown"),
                "tactic": technique.get("tactic", "Unknown"),
                "description": technique.get("description", ""),
                "navigator_url": f"https://attack.mitre.org/techniques/{tid}/",
            })

        return results

    def _matches(self, entry: dict, rule_match: dict) -> bool:
        """Check if an entry matches a rule's match conditions."""
        for key, val in rule_match.items():
            if key == "event_type_contains":
                if val not in entry.get("event_type", ""):
                    return False
            elif key == "asdu_type_id_in":
                if entry.get("asdu_type_id", -1) not in val:
                    return False
            elif key == "classification":
                if entry.get("classification") != val:
                    return False
            else:
                if entry.get(key) != val:
                    return False
        return True
