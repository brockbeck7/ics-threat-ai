"""
detector.py
===========
Two-layer detection system:

Layer 1 — ICSAnomalyDetector
    Unsupervised Isolation Forest trained on baseline normal ICS traffic.
    Flags statistical anomalies without needing labeled attack data.
    Best for: zero-day / novel attack patterns.

Layer 2 — ICSClassifier
    Rule-augmented Random Forest classifier trained on labeled events.
    Categorizes threats into: benign, reconnaissance, exploit_attempt,
    active_attack, lateral_movement.
    Best for: known ICS attack patterns (Stuxnet-style, Industroyer TTPs).
"""

import pickle
import numpy as np
from typing import List, Dict, Optional


# ─── Feature extraction helpers ──────────────────────────────────────────────

FEATURE_KEYS = [
    "src_port",
    "dst_port",
    "session_duration",
    "data_length",
    "function_code",
    "register_address",
    "register_count",
    "asdu_type_id",
    "pdu_type",
    "hour_of_day",
    "is_write_operation",
    "is_recon_indicator",
    "is_after_hours",
    "ip_is_external",
    "is_fingerprint",
    "used_default_community",
    "is_high_risk_command",
    "unit_id",
]

PROTOCOL_MAP = {
    "modbus": 0,
    "iec104": 1,
    "iec-104": 1,
    "s7comm": 2,
    "s7": 2,
    "snmp": 3,
    "guardian": 4,
    "ast": 4,
    "unknown": 5,
}

LABEL_MAP = {
    "benign": 0,
    "reconnaissance": 1,
    "exploit_attempt": 2,
    "active_attack": 3,
    "lateral_movement": 4,
}
LABEL_MAP_INV = {v: k for k, v in LABEL_MAP.items()}


def _to_feature_vector(entry: dict) -> np.ndarray:
    """Convert a parsed log entry dict into a numeric feature vector."""
    vec = []
    for key in FEATURE_KEYS:
        val = entry.get(key, 0)
        if isinstance(val, bool):
            val = int(val)
        elif not isinstance(val, (int, float)):
            val = 0
        vec.append(float(val))

    # Protocol as numeric feature
    protocol_code = PROTOCOL_MAP.get(entry.get("protocol", "unknown"), 5)
    vec.append(float(protocol_code))

    return np.array(vec, dtype=np.float32)


def _batch_features(entries: List[dict]) -> np.ndarray:
    return np.vstack([_to_feature_vector(e) for e in entries])


# ─── Layer 1: Anomaly Detector ────────────────────────────────────────────────

class ICSAnomalyDetector:
    """
    Isolation Forest anomaly detector.
    Trained exclusively on normal/baseline ICS traffic.
    Assigns anomaly scores: more negative = more anomalous.
    Threshold of -0.1 is a reasonable starting point; tune based on
    your environment's false positive tolerance.
    """

    def __init__(self, contamination: float = 0.05):
        """
        contamination: expected fraction of anomalies in training data.
        For a clean baseline use 0.01–0.05.
        For honeypot data (lots of attacks) use 0.10–0.20.
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            self._IsolationForest = IsolationForest
            self._StandardScaler = StandardScaler
        except ImportError:
            raise ImportError(
                "scikit-learn not installed. Run: pip install scikit-learn"
            )

        self.contamination = contamination
        self.model = None
        self.scaler = None
        self._trained = False

    def train(self, entries: List[dict]):
        """Train on a list of baseline (normal traffic) parsed log entries."""
        if not entries:
            raise ValueError("Cannot train on empty dataset.")

        X = _batch_features(entries)
        self.scaler = self._StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = self._IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self._trained = True
        print(f"    [Anomaly Detector] Trained on {len(entries)} samples.")

    def score(self, entry: dict) -> float:
        """
        Return anomaly score for a single entry.
        Scores range roughly from -0.5 (very anomalous) to 0.5 (normal).
        Values below -0.1 should be investigated.
        """
        if not self._trained:
            # Fallback rule-based scoring if model not trained
            return self._rule_based_score(entry)

        x = _to_feature_vector(entry).reshape(1, -1)
        x_scaled = self.scaler.transform(x)
        return float(self.model.score_samples(x_scaled)[0])

    def _rule_based_score(self, entry: dict) -> float:
        """Fallback heuristic scoring when model isn't trained."""
        score = 0.0
        if entry.get("ip_is_external"):
            score -= 0.15
        if entry.get("is_after_hours"):
            score -= 0.10
        if entry.get("is_write_operation"):
            score -= 0.20
        if entry.get("is_high_risk_command"):
            score -= 0.40
        if entry.get("is_fingerprint"):
            score -= 0.25
        if entry.get("used_default_community"):
            score -= 0.10
        fc = entry.get("function_code", 0)
        if fc in (5, 6, 15, 16):   # Write function codes
            score -= 0.15
        return score

    def save(self, path: str):
        with open(path, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)
        print(f"    [Anomaly Detector] Saved to {path}")

    def load(self, path: str):
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self._trained = True


# ─── Layer 2: Threat Classifier ───────────────────────────────────────────────

class ICSClassifier:
    """
    Random Forest classifier for known ICS threat categories.
    Uses a combination of ML classification and explicit ICS security rules.
    The rules encode expert knowledge about ICS attack patterns from
    MITRE ATT&CK for ICS, the Dragos threat library, and the honeypot
    research in the YouTube video (Guardian AST, Conpot, S7-300).
    """

    def __init__(self):
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import LabelEncoder
            self._RFC = RandomForestClassifier
            self._LE = LabelEncoder
        except ImportError:
            raise ImportError(
                "scikit-learn not installed. Run: pip install scikit-learn"
            )

        self.model = None
        self.label_encoder = None
        self._trained = False

    def train(self, entries: List[dict]):
        """
        Train classifier. Expects entries to have an 'is_attack' boolean
        or an 'attack_type' string. If neither exists, uses rule-based
        labeling to bootstrap training labels from feature heuristics.
        """
        if not entries:
            raise ValueError("Cannot train on empty dataset.")

        labeled = self._auto_label(entries)
        X = _batch_features(labeled)
        y_raw = [e["_label"] for e in labeled]

        self.label_encoder = self._LE()
        y = self.label_encoder.fit_transform(y_raw)

        self.model = self._RFC(
            n_estimators=300,
            max_depth=12,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )
        self.model.fit(X, y)
        self._trained = True
        from collections import Counter
        dist = Counter(y_raw)
        print(f"    [Classifier] Trained. Label distribution: {dict(dist)}")

    def predict(self, entry: dict) -> str:
        """Classify a single entry. Returns threat category string."""
        # Rule-based layer runs first — explicit ICS knowledge takes priority
        rule_result = self._apply_rules(entry)
        if rule_result != "benign":
            return rule_result

        # ML layer for statistical classification
        if self._trained and self.model is not None:
            x = _to_feature_vector(entry).reshape(1, -1)
            pred = self.model.predict(x)[0]
            return self.label_encoder.inverse_transform([pred])[0]

        return "benign"

    def _apply_rules(self, entry: dict) -> str:
        """
        Hard-coded ICS security rules based on known attack patterns.
        These encode expert knowledge and cannot be fooled by adversarial ML.
        """
        protocol = entry.get("protocol", "")
        event_type = entry.get("event_type", "")
        fc = entry.get("function_code", -1)

        # Guardian AST full system dump — seen in Shodan-exposed ATG attacks
        if event_type == "guardian_ast_get_system_info":
            return "reconnaissance"

        # Guardian AST write command — attempt to alter tank thresholds
        if protocol in ("guardian", "ast") and entry.get("operation_type") == "set":
            return "exploit_attempt"

        # S7comm userdata PDU — used for Siemens CPU enumeration (Stuxnet-style)
        if event_type == "s7_userdata" and entry.get("is_fingerprint"):
            return "reconnaissance"

        # Modbus write commands from external IPs
        if (protocol == "modbus"
                and fc in (5, 6, 15, 16, 23)
                and entry.get("ip_is_external")):
            return "exploit_attempt"

        # IEC 104 control commands (C_SC_NA_1, C_DC_NA_1)
        asdu = entry.get("asdu_type_id", -1)
        if asdu in (45, 46, 47, 48):
            return "active_attack"

        # IEC 104 full interrogation from external IP — recon
        if asdu == 100 and entry.get("ip_is_external"):
            return "reconnaissance"

        # SNMP with default community string from external IP
        if (protocol == "snmp"
                and entry.get("used_default_community")
                and entry.get("ip_is_external")):
            return "reconnaissance"

        # After-hours write operations — high suspicion
        if (entry.get("is_after_hours")
                and entry.get("is_write_operation")
                and entry.get("ip_is_external")):
            return "exploit_attempt"

        return "benign"

    def _auto_label(self, entries: List[dict]) -> List[dict]:
        """Bootstrap labels from entry metadata + rule engine."""
        labeled = []
        for entry in entries:
            e = dict(entry)
            if "attack_type" in e:
                e["_label"] = e["attack_type"]
            elif e.get("is_attack"):
                e["_label"] = self._apply_rules(e)
                if e["_label"] == "benign":
                    e["_label"] = "reconnaissance"  # Default for flagged traffic
            else:
                e["_label"] = "benign"
            labeled.append(e)
        return labeled

    def save(self, path: str):
        with open(path, "wb") as f:
            pickle.dump({
                "model": self.model,
                "label_encoder": self.label_encoder
            }, f)
        print(f"    [Classifier] Saved to {path}")

    def load(self, path: str):
        with open(path, "rb") as f:
            data = pickle.load(f)
        self.model = data["model"]
        self.label_encoder = data["label_encoder"]
        self._trained = True
