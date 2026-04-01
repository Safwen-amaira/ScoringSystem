from __future__ import annotations

import json
import re
from typing import Any
from urllib import error, parse, request


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(data: Any) -> list[str]:
    text = json.dumps(data, ensure_ascii=True)
    found = {match.upper() for match in CVE_RE.findall(text)}
    return sorted(found)


def fetch_cve_by_id(cve_id: str) -> dict[str, Any] | None:
    url = f"https://cve.circl.lu/api/cve/{parse.quote(cve_id)}"
    try:
        with request.urlopen(url, timeout=15) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    if payload.get("dataType") == "CVE_RECORD":
        return _parse_cve_5_entry(payload)

    cvss = payload.get("cvss") or payload.get("cvss3") or 0
    summary = payload.get("summary") or payload.get("description") or "External CVE match"
    return {
        "cve_id": cve_id.upper(),
        "summary": str(summary),
        "cvss": float(cvss or 0),
        "severity": severity_from_cvss(float(cvss or 0)),
        "published": payload.get("Published") or payload.get("published") or "",
        "modified": payload.get("Modified") or payload.get("modified") or "",
        "references": json.dumps(payload.get("references") or payload.get("refmap") or []),
        "raw_payload": json.dumps(payload),
    }


def fetch_recent_cves(limit: int = 3000) -> list[dict[str, Any]]:
    url = "https://cve.circl.lu/api/last"
    try:
        with request.urlopen(url, timeout=60) as response:
            if response.status != 200:
                return []
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError):
        return []

    items: list[dict[str, Any]] = []
    for entry in payload[:limit]:
        if not isinstance(entry, dict):
            continue

        if entry.get("dataType") == "CVE_RECORD":
            parsed = _parse_cve_5_entry(entry)
            if parsed:
                items.append(parsed)
            continue

        cve_id = str(entry.get("id") or entry.get("cve") or "").upper()
        if not cve_id:
            continue
        cvss = float(entry.get("cvss") or entry.get("cvss3") or 0)
        items.append(
            {
                "cve_id": cve_id,
                "summary": str(entry.get("summary") or entry.get("description") or "Recent CVE"),
                "cvss": cvss,
                "severity": severity_from_cvss(cvss),
                "published": entry.get("Published") or entry.get("published") or "",
                "modified": entry.get("Modified") or entry.get("modified") or "",
                "references": json.dumps(entry.get("references") or []),
                "raw_payload": json.dumps(entry),
            }
        )
    return items


def _parse_cve_5_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    metadata = entry.get("cveMetadata") or {}
    cve_id = metadata.get("cveId")
    if not cve_id:
        return None

    containers = entry.get("containers") or {}
    cna = containers.get("cna") or {}
    
    # Prioritize CNA title, then first description
    title = cna.get("title")
    descriptions = cna.get("descriptions") or []
    summary = title or (descriptions[0].get("value") if descriptions else "No description available")
    
    # Attempt to find CVSS in metrics
    cvss = 0.0
    metrics_list = cna.get("metrics") or []
    for metric in metrics_list:
        cvss_data = metric.get("cvssV3_1") or metric.get("cvssV3_0") or metric.get("cvssV2_0")
        if cvss_data and "baseScore" in cvss_data:
            cvss = float(cvss_data["baseScore"])
            break

    return {
        "cve_id": cve_id.upper(),
        "summary": str(summary),
        "cvss": cvss,
        "severity": severity_from_cvss(cvss),
        "published": metadata.get("datePublished") or "",
        "modified": metadata.get("dateUpdated") or "",
        "references": json.dumps(cna.get("references") or []),
        "raw_payload": json.dumps(entry),
    }


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    return "low"
