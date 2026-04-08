"""
ICS/OT Threat Detection AI
===========================
Author: Built for your cybersecurity internship + resume project
Purpose: Detects anomalies and known attack patterns in ICS/OT logs
         (Conpot honeypot, SCADA, Modbus, IEC 104, S7comm)
Maps findings to MITRE ATT&CK for ICS

Usage:
    python main.py --mode train --logs data/sample_logs.json
    python main.py --mode detect --logs data/live_logs.json
    python main.py --mode demo   (runs with built-in synthetic data)
"""

import argparse
import json
import os
from datetime import datetime

from log_parser import ConpotLogParser
from detector import ICSAnomalyDetector, ICSClassifier
from mitre_mapper import MitreICSMapper
from reporter import AlertReporter


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║          ICS/OT AI THREAT DETECTION SYSTEM              ║
║          MITRE ATT&CK for ICS  |  Conpot-Ready          ║
╚══════════════════════════════════════════════════════════╝
    """)


def run_demo():
    """Run a full demo using synthetic ICS log data."""
    print("[DEMO MODE] Generating synthetic Conpot/ICS log data...\n")

    from demo_data import generate_demo_logs
    logs = generate_demo_logs()

    parser = ConpotLogParser()
    parsed = parser.parse_batch(logs)
    print(f"[+] Parsed {len(parsed)} log entries\n")

    print("[*] Training anomaly detection model on baseline traffic...")
    detector = ICSAnomalyDetector(contamination=0.1)
    baseline = [e for e in parsed if not e.get("is_attack")]
    detector.train(baseline)
    print(f"[+] Model trained on {len(baseline)} baseline samples\n")

    print("[*] Running classifier on all events...")
    classifier = ICSClassifier()
    classifier.train(parsed)

    print("[*] Running detection pipeline...\n")
    mapper = MitreICSMapper()
    reporter = AlertReporter()

    alerts = []
    for entry in parsed:
        anomaly_score = detector.score(entry)
        classification = classifier.predict(entry)
        if anomaly_score < -0.1 or classification != "benign":
            techniques = mapper.map(entry, classification)
            alert = {
                "timestamp": entry.get("timestamp"),
                "source_ip": entry.get("src_ip"),
                "protocol": entry.get("protocol"),
                "event": entry.get("event_type"),
                "anomaly_score": round(anomaly_score, 4),
                "classification": classification,
                "mitre_techniques": techniques,
                "severity": _severity(anomaly_score, classification),
            }
            alerts.append(alert)

    reporter.print_summary(alerts)
    reporter.save_report(alerts, "output/threat_report.json")
    return alerts


def run_train(log_path):
    """Train the model on real Conpot log data."""
    print(f"[*] Loading logs from: {log_path}")
    with open(log_path) as f:
        raw_logs = json.load(f)

    parser = ConpotLogParser()
    parsed = parser.parse_batch(raw_logs)
    print(f"[+] Parsed {len(parsed)} entries\n")

    detector = ICSAnomalyDetector(contamination=0.05)
    detector.train(parsed)
    detector.save("models/anomaly_model.pkl")
    print("[+] Anomaly model saved to models/anomaly_model.pkl\n")

    classifier = ICSClassifier()
    classifier.train(parsed)
    classifier.save("models/classifier_model.pkl")
    print("[+] Classifier saved to models/classifier_model.pkl")


def run_detect(log_path):
    """Run detection on new logs using saved models."""
    detector = ICSAnomalyDetector()
    detector.load("models/anomaly_model.pkl")

    classifier = ICSClassifier()
    classifier.load("models/classifier_model.pkl")

    with open(log_path) as f:
        raw_logs = json.load(f)

    parser = ConpotLogParser()
    parsed = parser.parse_batch(raw_logs)

    mapper = MitreICSMapper()
    reporter = AlertReporter()
    alerts = []

    for entry in parsed:
        score = detector.score(entry)
        classification = classifier.predict(entry)
        if score < -0.1 or classification != "benign":
            techniques = mapper.map(entry, classification)
            alerts.append({
                "timestamp": entry.get("timestamp"),
                "source_ip": entry.get("src_ip"),
                "protocol": entry.get("protocol"),
                "event": entry.get("event_type"),
                "anomaly_score": round(score, 4),
                "classification": classification,
                "mitre_techniques": techniques,
                "severity": _severity(score, classification),
            })

    reporter.print_summary(alerts)
    reporter.save_report(alerts, "output/threat_report.json")
    return alerts


def _severity(score, classification):
    if classification in ["exploit_attempt", "active_attack"]:
        return "CRITICAL"
    elif classification == "reconnaissance":
        return "HIGH"
    elif score < -0.3:
        return "MEDIUM"
    return "LOW"


if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="ICS/OT AI Threat Detection System")
    parser.add_argument("--mode", choices=["train", "detect", "demo"],
                        default="demo", help="Operation mode")
    parser.add_argument("--logs", type=str, help="Path to log file (JSON)")
    args = parser.parse_args()

    os.makedirs("models", exist_ok=True)
    os.makedirs("output", exist_ok=True)

    if args.mode == "demo":
        run_demo()
    elif args.mode == "train":
        if not args.logs:
            print("[!] --logs required for train mode")
        else:
            run_train(args.logs)
    elif args.mode == "detect":
        if not args.logs:
            print("[!] --logs required for detect mode")
        else:
            run_detect(args.logs)
