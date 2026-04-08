"""
reporter.py
===========
Formats and outputs threat detection results.
Prints a color-coded terminal summary and saves a structured JSON report
suitable for feeding into a SIEM or sharing with a SOC team.
"""

import json
import os
from datetime import datetime
from collections import Counter


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # Red
    "HIGH":     "\033[93m",   # Yellow
    "MEDIUM":   "\033[94m",   # Blue
    "LOW":      "\033[92m",   # Green
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "CYAN":     "\033[96m",
}


class AlertReporter:

    def print_summary(self, alerts: list):
        C = SEVERITY_COLORS
        total = len(alerts)

        print(f"\n{C['BOLD']}{'='*60}{C['RESET']}")
        print(f"{C['BOLD']}  THREAT DETECTION RESULTS{C['RESET']}")
        print(f"{C['BOLD']}{'='*60}{C['RESET']}")
        print(f"  Alerts Generated : {C['BOLD']}{total}{C['RESET']}")
        print(f"  Scan Time        : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

        if not alerts:
            print(f"\n  {C['RESET']}No threats detected.")
            return

        # Severity breakdown
        sev_counts = Counter(a["severity"] for a in alerts)
        print(f"\n  {C['BOLD']}Severity Breakdown:{C['RESET']}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_counts.get(sev, 0)
            color = C.get(sev, "")
            bar = "█" * min(count, 40)
            print(f"    {color}{sev:<10}{C['RESET']} {count:>4}  {color}{bar}{C['RESET']}")

        # Classification breakdown
        cls_counts = Counter(a["classification"] for a in alerts)
        print(f"\n  {C['BOLD']}Classification Breakdown:{C['RESET']}")
        for cls, cnt in cls_counts.most_common():
            print(f"    {C['CYAN']}{cls:<22}{C['RESET']} {cnt}")

        # MITRE techniques seen
        all_techniques = []
        for alert in alerts:
            for t in alert.get("mitre_techniques", []):
                all_techniques.append(t["technique_id"] + " " + t["technique_name"])
        tech_counts = Counter(all_techniques)

        if tech_counts:
            print(f"\n  {C['BOLD']}Top MITRE ATT&CK for ICS Techniques:{C['RESET']}")
            for tech, cnt in tech_counts.most_common(8):
                print(f"    {C['CYAN']}{tech:<45}{C['RESET']} {cnt}x")

        # Top source IPs
        ip_counts = Counter(a["source_ip"] for a in alerts)
        print(f"\n  {C['BOLD']}Top Source IPs:{C['RESET']}")
        for ip, cnt in ip_counts.most_common(5):
            print(f"    {ip:<20} {cnt} events")

        # Print individual alerts (CRITICAL and HIGH only to avoid noise)
        high_alerts = [a for a in alerts if a["severity"] in ("CRITICAL", "HIGH")]
        if high_alerts:
            print(f"\n{C['BOLD']}{'='*60}{C['RESET']}")
            print(f"{C['BOLD']}  HIGH/CRITICAL ALERTS{C['RESET']}")
            print(f"{C['BOLD']}{'='*60}{C['RESET']}")
            for alert in high_alerts[:20]:   # Cap at 20 to avoid terminal flood
                self._print_alert(alert)

        print(f"\n{C['BOLD']}{'='*60}{C['RESET']}\n")

    def _print_alert(self, alert: dict):
        C = SEVERITY_COLORS
        sev = alert.get("severity", "LOW")
        color = C.get(sev, "")

        print(f"\n  {color}[{sev}]{C['RESET']} {alert.get('timestamp', 'N/A')}")
        print(f"    Source IP  : {alert.get('source_ip', 'N/A')}")
        print(f"    Protocol   : {alert.get('protocol', 'N/A').upper()}")
        print(f"    Event      : {alert.get('event', 'N/A')}")
        print(f"    Category   : {C['CYAN']}{alert.get('classification', 'N/A')}{C['RESET']}")
        print(f"    Anomaly    : {alert.get('anomaly_score', 'N/A')}")

        techniques = alert.get("mitre_techniques", [])
        if techniques:
            ids = ", ".join(t["technique_id"] for t in techniques)
            print(f"    MITRE ICS  : {C['CYAN']}{ids}{C['RESET']}")

    def save_report(self, alerts: list, output_path: str):
        """Save full report as structured JSON."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        report = {
            "report_generated": datetime.utcnow().isoformat() + "Z",
            "total_alerts": len(alerts),
            "severity_summary": dict(Counter(a["severity"] for a in alerts)),
            "classification_summary": dict(Counter(a["classification"] for a in alerts)),
            "mitre_techniques_observed": self._summarize_techniques(alerts),
            "alerts": alerts,
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"  [+] Full report saved: {output_path}")

    def _summarize_techniques(self, alerts: list) -> list:
        counts = Counter()
        details = {}
        for alert in alerts:
            for t in alert.get("mitre_techniques", []):
                tid = t["technique_id"]
                counts[tid] += 1
                details[tid] = t
        result = []
        for tid, cnt in counts.most_common():
            entry = dict(details[tid])
            entry["occurrences"] = cnt
            result.append(entry)
        return result
