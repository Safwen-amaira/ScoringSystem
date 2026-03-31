from __future__ import annotations

import json
from typing import Any
from urllib import request


MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def fetch_mitre_bundle() -> list[dict[str, Any]]:
    with request.urlopen(MITRE_ENTERPRISE_URL, timeout=40) as response:
        payload = json.loads(response.read().decode("utf-8"))
    techniques: list[dict[str, Any]] = []
    for obj in payload.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_refs = obj.get("external_references", [])
        external_id = ""
        url = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        tactics = obj.get("kill_chain_phases", [])
        techniques.append(
            {
                "external_id": external_id,
                "name": obj.get("name", "ATT&CK technique"),
                "description": obj.get("description", ""),
                "tactics": [phase.get("phase_name", "") for phase in tactics if phase.get("phase_name")],
                "platforms": obj.get("x_mitre_platforms", []),
                "url": url,
                "detection": obj.get("x_mitre_detection", ""),
            }
        )
    return techniques


def match_techniques(techniques: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    lowered = text.lower()
    matches: list[dict[str, Any]] = []
    keyword_map = {
        "phishing": "T1566",
        "credential": "T1110",
        "privilege escalation": "T1068",
        "command and control": "T1071",
        "malware": "T1204",
        "ransom": "T1486",
        "lateral movement": "T1021",
        "exfiltration": "T1048",
    }
    wanted = {technique_id for keyword, technique_id in keyword_map.items() if keyword in lowered}
    if "cve-" in lowered:
        wanted.add("T1190")
    if "authentication" in lowered:
        wanted.add("T1110")
    if "exploit" in lowered:
        wanted.add("T1190")

    for technique in techniques:
        if technique.get("external_id") in wanted:
            matches.append(technique)
    return matches[:8]
