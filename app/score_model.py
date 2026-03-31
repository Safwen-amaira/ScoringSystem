from __future__ import annotations

import csv
import os
import random
from functools import lru_cache
from pathlib import Path
from typing import Any

from sklearn.ensemble import RandomForestRegressor
from sklearn.feature_extraction import DictVectorizer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from .models import ScoringRequest


DATA_DIR = Path(os.getenv("HANICAR_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
TRAINING_DIR = DATA_DIR / "training"
TRAINING_CSV = TRAINING_DIR / "hbrain_banking_incidents.csv"

FIELDS = [
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
    "target_score",
]


def ensure_training_dataset(rows: int = 12000) -> Path:
    TRAINING_DIR.mkdir(parents=True, exist_ok=True)
    if TRAINING_CSV.exists():
        return TRAINING_CSV

    random.seed(42)
    with TRAINING_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for _ in range(rows):
            sample = _generate_sample()
            writer.writerow(sample)
    return TRAINING_CSV


def _generate_sample() -> dict[str, float]:
    rule_level = random.randint(0, 16)
    authentication_failures = random.randint(0, 1)
    malware_signal = random.randint(0, 1)
    privilege_signal = random.randint(0, 1)
    web_signal = random.randint(0, 1)
    known_bad_indicator = random.randint(0, 1)
    misp_threat_level = random.randint(1, 4)
    misp_attribute_count = random.randint(0, 45)
    cortex_state = random.choice(["malicious", "suspicious", "unknown", "safe"])
    cortex_malicious = 1 if cortex_state == "malicious" else 0
    cortex_suspicious = 1 if cortex_state == "suspicious" else 0
    artifacts_flagged = random.randint(0, 12)
    contains_cve = random.randint(0, 1)
    cve_count = random.randint(0, 5 if contains_cve else 1)
    payment_keywords = random.randint(0, 1)
    identity_keywords = random.randint(0, 1)
    external_exposure = random.randint(0, 1)
    workflow_critical = random.randint(0, 1)
    banking_asset = random.randint(0, 1)
    ai_confidence = round(random.uniform(0.45, 0.98), 2)

    target_score = (
        rule_level * 2.4
        + authentication_failures * 4.0
        + malware_signal * 9.5
        + privilege_signal * 7.0
        + web_signal * 6.0
        + known_bad_indicator * 8.5
        + (5 - misp_threat_level) * 4.6
        + min(misp_attribute_count * 0.32, 10)
        + cortex_malicious * 17.0
        + cortex_suspicious * 11.0
        + min(artifacts_flagged * 1.7, 12)
        + contains_cve * 8.0
        + min(cve_count * 2.1, 6)
        + payment_keywords * 8.0
        + identity_keywords * 6.0
        + external_exposure * 6.5
        + workflow_critical * 7.0
        + banking_asset * 5.0
        + ai_confidence * 4.0
        + random.uniform(-4.0, 4.0)
    )
    target_score = max(0, min(100, round(target_score, 1)))

    return {
        "rule_level": rule_level,
        "authentication_failures": authentication_failures,
        "malware_signal": malware_signal,
        "privilege_signal": privilege_signal,
        "web_signal": web_signal,
        "known_bad_indicator": known_bad_indicator,
        "misp_threat_level": misp_threat_level,
        "misp_attribute_count": misp_attribute_count,
        "cortex_malicious": cortex_malicious,
        "cortex_suspicious": cortex_suspicious,
        "artifacts_flagged": artifacts_flagged,
        "contains_cve": contains_cve,
        "cve_count": cve_count,
        "payment_keywords": payment_keywords,
        "identity_keywords": identity_keywords,
        "external_exposure": external_exposure,
        "workflow_critical": workflow_critical,
        "banking_asset": banking_asset,
        "ai_confidence": ai_confidence,
        "target_score": target_score,
    }


class HBrainScoreModel:
    def __init__(self) -> None:
        self.model_name = "hbrain-banking-rf-v1"
        self.pipeline = self._train()

    def _train(self) -> Pipeline:
        dataset_path = ensure_training_dataset()
        features: list[dict[str, float]] = []
        targets: list[float] = []
        with dataset_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                targets.append(float(row["target_score"]))
                features.append({key: float(row[key]) for key in FIELDS if key != "target_score"})

        vectorizer = DictVectorizer(sparse=False)
        regressor = RandomForestRegressor(
            n_estimators=220,
            max_depth=18,
            min_samples_split=4,
            random_state=42,
            n_jobs=1,
        )
        return Pipeline(
            [
                ("vectorizer", vectorizer),
                ("imputer", SimpleImputer(strategy="median")),
                ("regressor", regressor),
            ]
        ).fit(features, targets)

    def predict_score(self, feature_map: dict[str, float]) -> int:
        raw = float(self.pipeline.predict([feature_map])[0])
        return max(0, min(100, int(round(raw))))

    def decision(self, score: int) -> str:
        if score >= 80:
            return "stop"
        if score >= 50:
            return "review"
        return "continue"


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
    verdict = (request.cortex_analysis.verdict.lower() if request.cortex_analysis else "unknown")
    ai_confidence = float(ai_features.get("confidence", 0.72))

    return {
        "rule_level": float(request.wazuh_alert.rule_level if request.wazuh_alert else 0),
        "authentication_failures": float(1 if "authentication_failed" in groups or "auth" in combined_text else 0),
        "malware_signal": float(1 if "malware" in groups or "malware" in combined_text else 0),
        "privilege_signal": float(1 if "privilege" in combined_text or "privilege_escalation" in groups else 0),
        "web_signal": float(1 if "web" in groups or "http" in combined_text or "edge" in combined_text else 0),
        "known_bad_indicator": float(1 if request.misp_enrichment and request.misp_enrichment.known_bad_indicator else 0),
        "misp_threat_level": float(request.misp_enrichment.threat_level_id if request.misp_enrichment else 4),
        "misp_attribute_count": float(request.misp_enrichment.attribute_count if request.misp_enrichment else 0),
        "cortex_malicious": float(1 if verdict == "malicious" else 0),
        "cortex_suspicious": float(1 if verdict == "suspicious" else 0),
        "artifacts_flagged": float(request.cortex_analysis.artifacts_flagged if request.cortex_analysis else 0),
        "contains_cve": float(1 if cve_count or "cve-" in combined_text else 0),
        "cve_count": float(cve_count),
        "payment_keywords": float(1 if any(token in combined_text for token in ["payment", "pci", "card", "swift", "atm", "iban"]) else 0),
        "identity_keywords": float(1 if any(token in combined_text for token in ["identity", "credential", "account", "authentication", "customer"]) else 0),
        "external_exposure": float(1 if any(token in combined_text for token in ["public", "internet", "external", "edge", "vpn"]) else 0),
        "workflow_critical": float(1 if any(token in combined_text for token in ["critical", "playbook", "production", "workflow"]) else 0),
        "banking_asset": float(1 if any(token in combined_text for token in ["bank", "payment", "swift", "core", "issuer", "merchant"]) else 0),
        "ai_confidence": max(0.0, min(1.0, ai_confidence)),
    }


@lru_cache(maxsize=1)
def get_score_model() -> HBrainScoreModel:
    return HBrainScoreModel()
