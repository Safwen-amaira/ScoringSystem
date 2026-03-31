from __future__ import annotations

import json
from typing import Any
from urllib import error, request


def _fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> Any:
    req = request.Request(url, headers=headers or {}, method="GET")
    with request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_misp_events(base_url: str, api_key: str, limit: int = 20) -> list[dict[str, Any]]:
    if not base_url or not api_key:
        return []
    headers = {"Authorization": api_key, "Accept": "application/json"}
    endpoints = [
        f"{base_url.rstrip('/')}/events/index",
        f"{base_url.rstrip('/')}/events",
    ]
    for endpoint in endpoints:
        try:
            payload = _fetch_json(endpoint, headers=headers)
        except Exception:
            continue
        items = payload if isinstance(payload, list) else payload.get("response", payload.get("Event", payload.get("events", [])))
        normalized: list[dict[str, Any]] = []
        for item in items[:limit]:
            event = item.get("Event", item) if isinstance(item, dict) else {}
            normalized.append(
                {
                    "source_id": str(event.get("id") or event.get("uuid") or "misp-event"),
                    "title": str(event.get("info") or "MISP event"),
                    "severity": _misp_severity(event.get("threat_level_id")),
                    "created_at": str(event.get("date") or event.get("timestamp") or ""),
                    "raw_payload": item,
                }
            )
        if normalized:
            return normalized
    return []


def fetch_cortex_jobs(base_url: str, api_key: str, limit: int = 20) -> list[dict[str, Any]]:
    if not base_url or not api_key:
        return []
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    endpoints = [
        f"{base_url.rstrip('/')}/api/job/_search?range=0-{limit - 1}",
        f"{base_url.rstrip('/')}/api/jobs",
    ]
    for endpoint in endpoints:
        try:
            payload = _fetch_json(endpoint, headers=headers)
        except Exception:
            continue
        items = payload if isinstance(payload, list) else payload.get("data", payload)
        if not isinstance(items, list):
            continue
        normalized: list[dict[str, Any]] = []
        for item in items[:limit]:
            normalized.append(
                {
                    "source_id": str(item.get("id") or item.get("_id") or "cortex-job"),
                    "title": str(item.get("analyzerName") or item.get("analyzer_name") or "Cortex job"),
                    "severity": _cortex_severity(item),
                    "created_at": str(item.get("createdAt") or item.get("startDate") or item.get("created_at") or ""),
                    "raw_payload": item,
                }
            )
        if normalized:
            return normalized
    return []


def fetch_iris_cases(base_url: str, api_key: str, limit: int = 50) -> list[dict[str, Any]]:
    if not base_url or not api_key:
        return []
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    endpoints = [
        f"{base_url.rstrip('/')}/api/v2/cases",
        f"{base_url.rstrip('/')}/cases",
    ]
    for endpoint in endpoints:
        try:
            payload = _fetch_json(endpoint, headers=headers)
        except Exception:
            continue
        items = payload if isinstance(payload, list) else payload.get("items", payload.get("data", []))
        if not isinstance(items, list):
            continue
        normalized: list[dict[str, Any]] = []
        for item in items[:limit]:
            normalized.append(
                {
                    "source_id": str(item.get("id") or item.get("uuid") or item.get("case_id") or "iris-case"),
                    "title": str(item.get("title") or item.get("name") or "IRIS case"),
                    "severity": str(item.get("severity") or item.get("tlp") or "medium").lower(),
                    "created_at": str(item.get("created_at") or item.get("opened_at") or item.get("created") or ""),
                    "raw_payload": item,
                }
            )
        if normalized:
            return normalized
    return []


def _misp_severity(threat_level_id: Any) -> str:
    mapping = {"1": "critical", "2": "high", "3": "medium", "4": "low"}
    return mapping.get(str(threat_level_id or "4"), "medium")


def _cortex_severity(item: dict[str, Any]) -> str:
    blob = json.dumps(item).lower()
    if "malicious" in blob:
        return "critical"
    if "suspicious" in blob:
        return "high"
    if "safe" in blob:
        return "low"
    return "medium"
