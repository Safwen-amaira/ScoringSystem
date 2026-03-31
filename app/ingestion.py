from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from .models import (
    CortexAnalysis,
    EvidenceItem,
    IOCItem,
    MISPEnrichment,
    PKIMetric,
    RawIntelligenceRequest,
    ScoringRequest,
    WazuhAlert,
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def normalize_raw_request(payload: RawIntelligenceRequest) -> tuple[ScoringRequest, list[IOCItem], list[PKIMetric]]:
    case_title = payload.title or _extract_case_title(payload) or "Security event"
    asset_name = payload.asset_name or _extract_asset_name(payload) or "unknown-asset"

    wazuh = _parse_wazuh(payload.wazuh_alert)
    misp = _parse_misp(payload.misp_event)
    cortex = _parse_cortex(payload.cortex_analysis)

    scoring_request = ScoringRequest(
        title=case_title,
        asset_name=asset_name,
        analyst_email=payload.analyst_email,
        workflow_id=payload.workflow_id,
        wazuh_alert=wazuh,
        misp_enrichment=misp,
        cortex_analysis=cortex,
        notes=payload.notes,
    )

    iocs = extract_iocs(payload.model_dump())
    pkis = compute_pkis(scoring_request, iocs, payload.model_dump())
    return scoring_request, iocs, pkis


def extract_iocs(data: Any) -> list[IOCItem]:
    seen: set[tuple[str, str]] = set()
    results: list[IOCItem] = []

    for text, source_path in _iter_strings(data):
        matches = [
            ("ip", IP_RE.findall(text)),
            ("url", URL_RE.findall(text)),
            ("email", EMAIL_RE.findall(text)),
            ("sha256", SHA256_RE.findall(text)),
            ("sha1", SHA1_RE.findall(text)),
            ("md5", MD5_RE.findall(text)),
            ("domain", [m for m in DOMAIN_RE.findall(text) if not m.lower().startswith("http")]),
        ]
        for ioc_type, values in matches:
            for value in values:
                key = (ioc_type, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                results.append(IOCItem(type=ioc_type, value=value, source=source_path))
    return results


def compute_pkis(request: ScoringRequest, iocs: list[IOCItem], raw_payload: dict[str, Any] | None = None) -> list[PKIMetric]:
    malicious_signals = 0
    sources_present = 0
    raw_payload = raw_payload or {}

    if request.wazuh_alert:
        sources_present += 1
        if request.wazuh_alert.rule_level >= 10:
            malicious_signals += 1

    if request.misp_enrichment:
        sources_present += 1
        if request.misp_enrichment.known_bad_indicator or request.misp_enrichment.threat_level_id == 1:
            malicious_signals += 1

    if request.cortex_analysis:
        sources_present += 1
        if request.cortex_analysis.verdict.lower() in {"malicious", "suspicious"}:
            malicious_signals += 1

    detection_age_minutes = _event_age_minutes(raw_payload)
    triage_pressure = (malicious_signals * 20) + (len(iocs) * 3) + (10 if detection_age_minutes > 120 else 0)
    source_diversity_index = round((sources_present / 3.0) * 100, 1)
    mttd_minutes = max(1.0, detection_age_minutes)
    mtdr_minutes = round(max(5.0, (triage_pressure / max(1, sources_present)) * 2.2), 1)

    return [
        PKIMetric(name="source_coverage", value=float(sources_present), description="How many telemetry sources contributed to this case."),
        PKIMetric(name="ioc_count", value=float(len(iocs)), description="How many unique IOCs were extracted from the raw payloads."),
        PKIMetric(name="malicious_signal_count", value=float(malicious_signals), description="How many contributing sources indicated suspicious or malicious activity."),
        PKIMetric(name="high_confidence_case", value=float(1 if malicious_signals >= 2 and len(iocs) >= 2 else 0), description="A binary PKI showing whether multiple sources and IOCs support the case."),
        PKIMetric(name="mttd_minutes", value=round(mttd_minutes, 1), description="Approximate mean time to detect from the most recent event timestamp present in the payload."),
        PKIMetric(name="mtdr_minutes", value=mtdr_minutes, description="Estimated mean time to detect and respond based on signal pressure and source diversity."),
        PKIMetric(name="source_diversity_index", value=source_diversity_index, description="Percentage score showing how much of the Wazuh, MISP, and Cortex triad contributed evidence."),
        PKIMetric(name="triage_pressure_index", value=round(min(100.0, triage_pressure), 1), description="Composite triage pressure based on signal count, IOC volume, and event freshness."),
    ]


def _extract_case_title(payload: RawIntelligenceRequest) -> str | None:
    for candidate in [
        _dig(payload.wazuh_alert, "rule", "description"),
        _dig(payload.misp_event, "Event", "info"),
        _dig(payload.cortex_analysis, "summary", "taxonomies"),
        _dig(payload.cortex_analysis, "summary"),
    ]:
        if candidate:
            return str(candidate)
    return None


def _extract_asset_name(payload: RawIntelligenceRequest) -> str | None:
    for candidate in [
        _dig(payload.wazuh_alert, "agent", "name"),
        _dig(payload.wazuh_alert, "agent", "hostname"),
        _dig(payload.wazuh_alert, "agent_name"),
        _dig(payload.cortex_analysis, "observable"),
    ]:
        if candidate:
            return str(candidate)
    return None


def _parse_wazuh(raw: dict[str, Any] | None) -> WazuhAlert | None:
    if not raw:
        return None
    groups = _as_list(_dig(raw, "rule", "groups") or raw.get("groups"))
    return WazuhAlert(
        rule_level=int(_dig(raw, "rule", "level") or raw.get("rule_level") or 0),
        rule_description=str(_dig(raw, "rule", "description") or raw.get("rule_description") or "Wazuh alert"),
        groups=[str(item) for item in groups],
        agent_name=_dig(raw, "agent", "name") or raw.get("agent_name"),
        source_ip=_dig(raw, "data", "srcip") or raw.get("source_ip") or raw.get("srcip"),
    )


def _parse_misp(raw: dict[str, Any] | None) -> MISPEnrichment | None:
    if not raw:
        return None
    event = raw.get("Event", raw)
    attributes = event.get("Attribute", []) if isinstance(event, dict) else []
    tags = [item.get("name", "") for item in _as_list(event.get("Tag", [])) if isinstance(item, dict)]
    threat_level = int(event.get("threat_level_id") or raw.get("threat_level_id") or 4)
    known_bad = any(_attribute_looks_malicious(attr) for attr in attributes if isinstance(attr, dict))
    return MISPEnrichment(
        threat_level_id=threat_level,
        event_info=str(event.get("info") or raw.get("event_info") or "MISP event"),
        tags=[tag for tag in tags if tag],
        attribute_count=len(attributes),
        known_bad_indicator=known_bad,
    )


def _parse_cortex(raw: dict[str, Any] | None) -> CortexAnalysis | None:
    if not raw:
        return None
    taxonomies = []
    raw_taxonomies = _dig(raw, "summary", "taxonomies") or raw.get("taxonomies") or []
    for taxonomy in _as_list(raw_taxonomies):
        if isinstance(taxonomy, dict):
            parts = [taxonomy.get("namespace"), taxonomy.get("predicate"), taxonomy.get("value")]
            taxonomies.append(":".join(str(part) for part in parts if part))
        else:
            taxonomies.append(str(taxonomy))

    verdict = (
        raw.get("verdict")
        or _dig(raw, "summary", "verdict")
        or _dig(raw, "report", "verdict")
        or ("malicious" if any("malicious" in item.lower() for item in taxonomies) else "unknown")
    )

    return CortexAnalysis(
        analyzer_name=str(raw.get("analyzerName") or raw.get("analyzer_name") or "Cortex analyzer"),
        verdict=str(verdict),
        taxonomies=taxonomies,
        artifacts_flagged=int(raw.get("artifacts_flagged") or len(taxonomies)),
        summary=_json_preview(raw.get("summary") or raw.get("full") or raw),
    )


def _attribute_looks_malicious(attribute: dict[str, Any]) -> bool:
    category = str(attribute.get("category", "")).lower()
    comment = str(attribute.get("comment", "")).lower()
    value = str(attribute.get("value", "")).lower()
    return any(token in f"{category} {comment} {value}" for token in ["malware", "ransom", "phish", "c2", "botnet"])


def _iter_strings(data: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(data, str):
        yield data, path
    elif isinstance(data, dict):
        for key, value in data.items():
            yield from _iter_strings(value, f"{path}.{key}")
    elif isinstance(data, list):
        for index, value in enumerate(data):
            yield from _iter_strings(value, f"{path}[{index}]")
    elif data is not None:
        yield str(data), path


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _dig(data: Any, *keys: str) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _json_preview(value: Any) -> str:
    if isinstance(value, str):
        return value[:400]
    return json.dumps(value, ensure_ascii=True)[:400]


def _event_age_minutes(raw_payload: dict[str, Any]) -> float:
    timestamps: list[datetime] = []
    for text, _ in _iter_strings(raw_payload):
        candidate = _parse_timestamp(text)
        if candidate:
            timestamps.append(candidate)
    if not timestamps:
        return 15.0
    latest = max(timestamps)
    age = datetime.now(timezone.utc) - latest.astimezone(timezone.utc)
    return max(1.0, age.total_seconds() / 60.0)


def _parse_timestamp(value: str) -> datetime | None:
    text = value.strip()
    if len(text) < 10:
        return None
    for candidate in [text.replace("Z", "+00:00"), text]:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue
    return None
