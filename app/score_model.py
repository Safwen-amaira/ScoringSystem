from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import ScoringRequest


DATA_DIR = Path(os.getenv("HANICAR_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
TRAINING_DIR = DATA_DIR / "training"
TRAINING_CSV = TRAINING_DIR / "hbrain_banking_incidents.csv"
DATASET_VERSION = "hbrain-banking-v3"
MIN_TRAINING_ROWS = 480

FEATURE_FIELDS = [
    "rule_level",
    "authentication_failures",
    "malware_signal",
    "privilege_signal",
    "web_signal",
    "known_bad_indicator",
    "misp_threat_level",
    "misp_attribute_count",
    "cortex_malicious",
    "cortex_suspicious",
    "artifacts_flagged",
    "contains_cve",
    "cve_count",
    "payment_keywords",
    "identity_keywords",
    "external_exposure",
    "workflow_critical",
    "banking_asset",
    "ai_confidence",
    "lateral_movement_signal",
    "exfiltration_signal",
    "customer_impact",
    "endpoint_criticality",
    "source_diversity",
    "intel_confidence",
    "alert_volume",
]

CSV_FIELDS = ["dataset_version", "scenario_name", *FEATURE_FIELDS, "target_score", "target_decision"]


@dataclass(frozen=True)
class ScenarioTemplate:
    name: str
    band: str
    base_score: int
    values: dict[str, float]


SCENARIOS: list[ScenarioTemplate] = [
    ScenarioTemplate("normal_login_banking_user", "low", 16, {"rule_level": 2, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 4, "misp_attribute_count": 0, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 0, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 1, "external_exposure": 0, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.56, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 2, "source_diversity": 1, "intel_confidence": 0.18, "alert_volume": 1}),
    ScenarioTemplate("scheduled_backup_window", "low", 14, {"rule_level": 1, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 4, "misp_attribute_count": 0, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 0, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 0, "external_exposure": 0, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.52, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 2, "source_diversity": 1, "intel_confidence": 0.1, "alert_volume": 1}),
    ScenarioTemplate("vpn_reconnect_after_timeout", "low", 22, {"rule_level": 3, "authentication_failures": 1, "malware_signal": 0, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 4, "misp_attribute_count": 1, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 1, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 1, "external_exposure": 1, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.61, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 2, "source_diversity": 1, "intel_confidence": 0.22, "alert_volume": 2}),
    ScenarioTemplate("internal_branch_traffic_baseline", "low", 19, {"rule_level": 2, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 4, "misp_attribute_count": 0, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 0, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 0, "external_exposure": 0, "workflow_critical": 0, "banking_asset": 0, "ai_confidence": 0.53, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 1, "source_diversity": 1, "intel_confidence": 0.14, "alert_volume": 1}),
    ScenarioTemplate("cron_job_false_alarm", "low", 24, {"rule_level": 3, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 4, "misp_attribute_count": 0, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 1, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 0, "external_exposure": 0, "workflow_critical": 0, "banking_asset": 0, "ai_confidence": 0.59, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 1, "source_diversity": 1, "intel_confidence": 0.2, "alert_volume": 2}),
    ScenarioTemplate("suspicious_attachment_sandboxed", "medium", 54, {"rule_level": 9, "authentication_failures": 0, "malware_signal": 1, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 1, "misp_threat_level": 2, "misp_attribute_count": 11, "cortex_malicious": 0, "cortex_suspicious": 1, "artifacts_flagged": 7, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 1, "external_exposure": 1, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.84, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 1, "endpoint_criticality": 3, "source_diversity": 3, "intel_confidence": 0.88, "alert_volume": 5}),
    ScenarioTemplate("vulnerability_recon_low_confidence", "medium", 46, {"rule_level": 7, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 1, "known_bad_indicator": 0, "misp_threat_level": 3, "misp_attribute_count": 6, "cortex_malicious": 0, "cortex_suspicious": 1, "artifacts_flagged": 2, "contains_cve": 1, "cve_count": 1, "payment_keywords": 1, "identity_keywords": 0, "external_exposure": 1, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.7, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 3, "source_diversity": 2, "intel_confidence": 0.45, "alert_volume": 4}),
    ScenarioTemplate("wazuh_high_rule_false_positive", "medium", 44, {"rule_level": 12, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 4, "misp_attribute_count": 0, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 0, "contains_cve": 0, "cve_count": 0, "payment_keywords": 0, "identity_keywords": 0, "external_exposure": 0, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.64, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 0, "endpoint_criticality": 2, "source_diversity": 1, "intel_confidence": 0.08, "alert_volume": 6}),
    ScenarioTemplate("cortex_safe_but_misp_malicious", "medium", 58, {"rule_level": 6, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 0, "web_signal": 1, "known_bad_indicator": 1, "misp_threat_level": 1, "misp_attribute_count": 14, "cortex_malicious": 0, "cortex_suspicious": 0, "artifacts_flagged": 1, "contains_cve": 1, "cve_count": 1, "payment_keywords": 1, "identity_keywords": 1, "external_exposure": 1, "workflow_critical": 0, "banking_asset": 1, "ai_confidence": 0.79, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 1, "endpoint_criticality": 4, "source_diversity": 2, "intel_confidence": 0.91, "alert_volume": 3}),
    ScenarioTemplate("partial_lateral_movement_only", "high", 72, {"rule_level": 8, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 1, "web_signal": 0, "known_bad_indicator": 0, "misp_threat_level": 3, "misp_attribute_count": 3, "cortex_malicious": 0, "cortex_suspicious": 1, "artifacts_flagged": 4, "contains_cve": 0, "cve_count": 0, "payment_keywords": 1, "identity_keywords": 1, "external_exposure": 0, "workflow_critical": 1, "banking_asset": 1, "ai_confidence": 0.82, "lateral_movement_signal": 1, "exfiltration_signal": 0, "customer_impact": 1, "endpoint_criticality": 4, "source_diversity": 2, "intel_confidence": 0.52, "alert_volume": 6}),
    ScenarioTemplate("card_portal_account_takeover", "high", 76, {"rule_level": 11, "authentication_failures": 1, "malware_signal": 0, "privilege_signal": 0, "web_signal": 1, "known_bad_indicator": 1, "misp_threat_level": 2, "misp_attribute_count": 14, "cortex_malicious": 0, "cortex_suspicious": 1, "artifacts_flagged": 4, "contains_cve": 0, "cve_count": 0, "payment_keywords": 1, "identity_keywords": 1, "external_exposure": 1, "workflow_critical": 1, "banking_asset": 1, "ai_confidence": 0.86, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 1, "endpoint_criticality": 4, "source_diversity": 3, "intel_confidence": 0.85, "alert_volume": 9}),
    ScenarioTemplate("lateral_movement_after_vpn_compromise", "high", 79, {"rule_level": 13, "authentication_failures": 1, "malware_signal": 0, "privilege_signal": 1, "web_signal": 0, "known_bad_indicator": 1, "misp_threat_level": 2, "misp_attribute_count": 16, "cortex_malicious": 0, "cortex_suspicious": 1, "artifacts_flagged": 8, "contains_cve": 1, "cve_count": 1, "payment_keywords": 1, "identity_keywords": 1, "external_exposure": 1, "workflow_critical": 1, "banking_asset": 1, "ai_confidence": 0.91, "lateral_movement_signal": 1, "exfiltration_signal": 0, "customer_impact": 1, "endpoint_criticality": 5, "source_diversity": 3, "intel_confidence": 0.86, "alert_volume": 10}),
    ScenarioTemplate("edge_exploit_known_cve", "critical", 91, {"rule_level": 15, "authentication_failures": 0, "malware_signal": 0, "privilege_signal": 1, "web_signal": 1, "known_bad_indicator": 1, "misp_threat_level": 1, "misp_attribute_count": 26, "cortex_malicious": 1, "cortex_suspicious": 0, "artifacts_flagged": 9, "contains_cve": 1, "cve_count": 2, "payment_keywords": 1, "identity_keywords": 1, "external_exposure": 1, "workflow_critical": 1, "banking_asset": 1, "ai_confidence": 0.96, "lateral_movement_signal": 0, "exfiltration_signal": 0, "customer_impact": 1, "endpoint_criticality": 5, "source_diversity": 3, "intel_confidence": 0.97, "alert_volume": 11}),
    ScenarioTemplate("ransomware_staging", "critical", 95, {"rule_level": 16, "authentication_failures": 0, "malware_signal": 1, "privilege_signal": 1, "web_signal": 0, "known_bad_indicator": 1, "misp_threat_level": 1, "misp_attribute_count": 33, "cortex_malicious": 1, "cortex_suspicious": 0, "artifacts_flagged": 12, "contains_cve": 1, "cve_count": 1, "payment_keywords": 1, "identity_keywords": 1, "external_exposure": 0, "workflow_critical": 1, "banking_asset": 1, "ai_confidence": 0.98, "lateral_movement_signal": 1, "exfiltration_signal": 1, "customer_impact": 1, "endpoint_criticality": 5, "source_diversity": 3, "intel_confidence": 0.99, "alert_volume": 14}),
]


def ensure_training_dataset(min_rows: int = MIN_TRAINING_ROWS) -> Path:
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)
    if TRAINING_CSV.exists():
        with TRAINING_CSV.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames or []
            rows = list(reader)
        if fieldnames == CSV_FIELDS and len(rows) >= min_rows and all(row.get("dataset_version") == DATASET_VERSION for row in rows[:5]):
            return TRAINING_CSV

    rows = _build_dataset_rows(min_rows)
    with TRAINING_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return TRAINING_CSV


def _build_dataset_rows(min_rows: int) -> list[dict[str, Any]]:
    targets = {"low": int(min_rows * 0.4), "medium": int(min_rows * 0.3), "high": int(min_rows * 0.2), "critical": min_rows - int(min_rows * 0.4) - int(min_rows * 0.3) - int(min_rows * 0.2)}
    rows: list[dict[str, Any]] = []
    for band, wanted in targets.items():
        templates = [item for item in SCENARIOS if item.band == band]
        for index in range(wanted):
            template = templates[index % len(templates)]
            row = _variant_row(template, index)
            score = _scenario_score(template, row, index)
            rows.append(
                {
                    "dataset_version": DATASET_VERSION,
                    "scenario_name": template.name,
                    **{field: row[field] for field in FEATURE_FIELDS},
                    "target_score": score,
                    "target_decision": "stop" if score >= 80 else "review" if score >= 50 else "continue",
                }
            )
    return rows


def _variant_row(template: ScenarioTemplate, variant_index: int) -> dict[str, float]:
    row = dict(template.values)
    wave = (variant_index % 5) - 2
    row["rule_level"] = max(0, min(20, row["rule_level"] + (variant_index % 3) - 1))
    row["misp_attribute_count"] = max(0, row["misp_attribute_count"] + (variant_index % 4) - 1)
    row["artifacts_flagged"] = max(0, row["artifacts_flagged"] + (variant_index % 5) - 2)
    row["alert_volume"] = max(1, row["alert_volume"] + wave)
    row["ai_confidence"] = round(max(0.45, min(0.99, row["ai_confidence"] + (wave * 0.015))), 2)
    row["intel_confidence"] = round(max(0.05, min(0.99, row["intel_confidence"] + (wave * 0.02))), 2)
    row["endpoint_criticality"] = max(1, min(5, row["endpoint_criticality"] + (1 if variant_index % 7 == 0 else 0)))
    _inject_messy_signals(row, variant_index)
    return row


def _inject_messy_signals(row: dict[str, float], variant_index: int) -> None:
    if variant_index % 5 == 0:
        row["cortex_malicious"] = 0 if row["cortex_malicious"] else 1
        if row["cortex_malicious"] == 0 and row["cortex_suspicious"] == 0:
            row["cortex_suspicious"] = 1
    if variant_index % 6 == 0:
        row["known_bad_indicator"] = 0 if row["known_bad_indicator"] else 1
        row["misp_threat_level"] = 1 if row["misp_threat_level"] > 2 else 4
    if variant_index % 7 == 0:
        row["lateral_movement_signal"] = 0 if row["lateral_movement_signal"] else 1
    if variant_index % 8 == 0:
        row["web_signal"] = 0 if row["web_signal"] else 1
    if variant_index % 9 == 0:
        row["source_diversity"] = max(1, row["source_diversity"] - 1)
    if variant_index % 10 == 0:
        row["alert_volume"] += 4


def _scenario_score(template: ScenarioTemplate, row: dict[str, float], variant_index: int) -> int:
    score = float(template.base_score)
    score += row["rule_level"] * 0.55
    score += row["misp_attribute_count"] * 0.1
    score += row["artifacts_flagged"] * 0.45
    score += row["source_diversity"] * 2.2
    score += row["customer_impact"] * 6
    score += row["endpoint_criticality"] * 1.3
    score += row["alert_volume"] * 0.2
    score += row["lateral_movement_signal"] * 4
    score += row["exfiltration_signal"] * 5
    score -= variant_index % 4
    if row["cortex_malicious"] and row["banking_asset"]:
        score = max(score, 82 if template.band in {"high", "critical"} else score)
    if row["rule_level"] <= 3 and not any(row[key] for key in ["cortex_malicious", "known_bad_indicator", "lateral_movement_signal", "exfiltration_signal"]):
        score = min(score, 24)
    band_limits = {"low": (0, 30), "medium": (31, 60), "high": (61, 80), "critical": (81, 100)}
    lower, upper = band_limits[template.band]
    return max(lower, min(upper, int(round(score))))


class HBrainScoreModel:
    def __init__(self) -> None:
        self.model_name = "hbrain-banking-hybrid-rf-v3"
        self.pipeline = self._train()

    def _train(self):
        from sklearn.ensemble import RandomForestRegressor
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.impute import SimpleImputer
        from sklearn.pipeline import Pipeline

        dataset_path = ensure_training_dataset()
        features: list[dict[str, float]] = []
        targets: list[float] = []
        with dataset_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                targets.append(float(row["target_score"]))
                features.append({key: float(row[key]) for key in FEATURE_FIELDS})

        return Pipeline(
            [
                ("vectorizer", DictVectorizer(sparse=False)),
                ("imputer", SimpleImputer(strategy="median")),
                ("regressor", RandomForestRegressor(n_estimators=420, max_depth=20, min_samples_split=3, random_state=42, n_jobs=1)),
            ]
        ).fit(features, targets)

    def predict_score(self, feature_map: dict[str, float]) -> int:
        raw = float(self.pipeline.predict([feature_map])[0])
        return max(0, min(100, int(round(raw))))


def extract_feature_map(request: ScoringRequest, ai_features: dict[str, Any] | None = None, cve_count: int = 0) -> dict[str, float]:
    ai_features = ai_features or {}
    combined_text = " ".join(
        filter(
            None,
            [
                request.title,
                request.asset_name,
                request.workflow_id or "",
                request.notes or "",
                request.misp_enrichment.event_info if request.misp_enrichment else "",
                request.cortex_analysis.summary if request.cortex_analysis and request.cortex_analysis.summary else "",
            ],
        )
    ).lower()
    groups = [group.lower() for group in request.wazuh_alert.groups] if request.wazuh_alert else []
    verdict = request.cortex_analysis.verdict.lower() if request.cortex_analysis else "unknown"
    payment_keywords = 1 if any(token in combined_text for token in ["payment", "pci", "swift", "card", "merchant", "issuer"]) else 0
    identity_keywords = 1 if any(token in combined_text for token in ["identity", "customer", "account", "credential", "iban"]) else 0
    lateral_movement_signal = 1 if any(token in combined_text for token in ["lateral", "pivot", "rdp", "smb", "movement"]) else 0
    exfiltration_signal = 1 if any(token in combined_text for token in ["exfil", "upload", "dump", "transfer", "leak"]) else 0
    auth_failures = 1 if "authentication_failed" in groups or any(token in combined_text for token in ["authentication", "login", "password", "credential"]) else 0
    alert_volume = float(ai_features.get("alert_volume", max(1, len(groups) + (request.cortex_analysis.artifacts_flagged if request.cortex_analysis else 0))))
    return {
        "rule_level": float(request.wazuh_alert.rule_level if request.wazuh_alert else 0),
        "authentication_failures": float(auth_failures),
        "malware_signal": float(1 if "malware" in groups or "malware" in combined_text else 0),
        "privilege_signal": float(1 if "privilege" in combined_text or "privilege_escalation" in groups else 0),
        "web_signal": float(1 if "web" in groups or "http" in combined_text or "portal" in combined_text or "edge" in combined_text else 0),
        "known_bad_indicator": float(1 if request.misp_enrichment and request.misp_enrichment.known_bad_indicator else 0),
        "misp_threat_level": float(request.misp_enrichment.threat_level_id if request.misp_enrichment else 4),
        "misp_attribute_count": float(request.misp_enrichment.attribute_count if request.misp_enrichment else 0),
        "cortex_malicious": float(1 if verdict == "malicious" else 0),
        "cortex_suspicious": float(1 if verdict == "suspicious" else 0),
        "artifacts_flagged": float(request.cortex_analysis.artifacts_flagged if request.cortex_analysis else 0),
        "contains_cve": float(1 if cve_count or "cve-" in combined_text else 0),
        "cve_count": float(cve_count),
        "payment_keywords": float(payment_keywords),
        "identity_keywords": float(identity_keywords),
        "external_exposure": float(1 if any(token in combined_text for token in ["external", "public", "internet", "vpn", "dmz", "edge"]) else 0),
        "workflow_critical": float(1 if any(token in combined_text for token in ["critical", "production", "workflow", "playbook", "containment"]) else 0),
        "banking_asset": float(1 if any(token in combined_text for token in ["bank", "payment", "swift", "issuer", "merchant", "atm", "branch"]) else 0),
        "ai_confidence": max(0.0, min(1.0, float(ai_features.get("confidence", 0.72)))),
        "lateral_movement_signal": float(lateral_movement_signal),
        "exfiltration_signal": float(exfiltration_signal),
        "customer_impact": float(1 if payment_keywords or identity_keywords or bool(ai_features.get("customer_impact")) else 0),
        "endpoint_criticality": float(ai_features.get("endpoint_criticality", 5 if payment_keywords else 3)),
        "source_diversity": float(sum(1 for item in [request.wazuh_alert, request.misp_enrichment, request.cortex_analysis] if item)),
        "intel_confidence": max(0.0, min(1.0, float(ai_features.get("confidence", 0.72)))),
        "alert_volume": alert_volume,
    }


@lru_cache(maxsize=1)
def get_score_model() -> HBrainScoreModel:
    return HBrainScoreModel()
