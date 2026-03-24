from __future__ import annotations

from typing import List, Tuple

from .models import (
    CortexAnalysis,
    EvidenceItem,
    MISPEnrichment,
    RecommendationResponse,
    ScoreBreakdown,
    ScoringRequest,
    WazuhAlert,
)


def _score_wazuh(alert: WazuhAlert | None) -> Tuple[float, ScoreBreakdown | None, List[EvidenceItem]]:
    if not alert:
        return 0.0, None, []

    score = min(alert.rule_level * 4.5, 40)
    if "malware" in [group.lower() for group in alert.groups]:
        score += 10
    if "authentication_failed" in [group.lower() for group in alert.groups]:
        score += 5

    score = min(score, 45)
    rationale = f"Wazuh rule level {alert.rule_level} with groups {', '.join(alert.groups) or 'none'} contributed to urgency."
    evidence = [
        EvidenceItem(
            source="Wazuh",
            title=alert.rule_description,
            severity=str(alert.rule_level),
            value=score,
            details=f"Agent={alert.agent_name or 'unknown'}, source_ip={alert.source_ip or 'n/a'}",
        )
    ]
    return score, ScoreBreakdown(category="Wazuh alert", score=round(score, 1), rationale=rationale), evidence


def _score_misp(misp: MISPEnrichment | None) -> Tuple[float, ScoreBreakdown | None, List[EvidenceItem]]:
    if not misp:
        return 0.0, None, []

    base_map = {1: 30, 2: 22, 3: 12, 4: 5}
    score = float(base_map[misp.threat_level_id])
    score += min(misp.attribute_count, 10)
    if misp.known_bad_indicator:
        score += 10

    score = min(score, 40)
    rationale = (
        f"MISP threat level {misp.threat_level_id} and {misp.attribute_count} attributes "
        f"{'matched known bad indicators' if misp.known_bad_indicator else 'were enriched'}."
    )
    evidence = [
        EvidenceItem(
            source="MISP",
            title=misp.event_info,
            severity=f"threat-level-{misp.threat_level_id}",
            value=score,
            details=f"Tags={', '.join(misp.tags) or 'none'}",
        )
    ]
    return score, ScoreBreakdown(category="MISP enrichment", score=round(score, 1), rationale=rationale), evidence


def _score_cortex(cortex: CortexAnalysis | None) -> Tuple[float, ScoreBreakdown | None, List[EvidenceItem]]:
    if not cortex:
        return 0.0, None, []

    verdict_map = {
        "malicious": 30,
        "suspicious": 18,
        "safe": 0,
        "unknown": 8,
    }
    score = float(verdict_map.get(cortex.verdict.lower(), 8))
    score += min(cortex.artifacts_flagged * 2, 10)
    if any("tlp:red" in item.lower() for item in cortex.taxonomies):
        score += 5

    score = min(score, 35)
    rationale = (
        f"Cortex analyzer {cortex.analyzer_name} returned {cortex.verdict} with "
        f"{cortex.artifacts_flagged} flagged artifacts."
    )
    evidence = [
        EvidenceItem(
            source="Cortex",
            title=f"{cortex.analyzer_name} verdict",
            severity=cortex.verdict,
            value=score,
            details=cortex.summary or f"Taxonomies={', '.join(cortex.taxonomies) or 'none'}",
        )
    ]
    return score, ScoreBreakdown(category="Cortex analysis", score=round(score, 1), rationale=rationale), evidence


def _decision(score: int) -> str:
    if score >= 75:
        return "stop"
    if score >= 45:
        return "review"
    return "continue"


def _summary(score: int, decision: str, request: ScoringRequest) -> str:
    if decision == "stop":
        return (
            f"Threat score {score}/100 for {request.asset_name} is high. "
            "Stop the workflow and escalate to incident response immediately."
        )
    if decision == "review":
        return (
            f"Threat score {score}/100 for {request.asset_name} needs analyst review. "
            "Keep the workflow paused until triage is complete."
        )
    return (
        f"Threat score {score}/100 for {request.asset_name} is acceptable for controlled continuation. "
        "Proceed with the workflow while monitoring the case."
    )


def _recommendation_body(request: ScoringRequest, score: int, decision: str, breakdown: List[ScoreBreakdown]) -> str:
    action_lines = {
        "stop": [
            "1. Stop the workflow immediately.",
            "2. Isolate the impacted asset or user session.",
            "3. Open an incident and assign IR ownership.",
            "4. Preserve forensic evidence from Wazuh, MISP, and Cortex.",
        ],
        "review": [
            "1. Pause the workflow pending analyst validation.",
            "2. Confirm whether indicators are true positives.",
            "3. Enrich the case with host, user, and network context.",
            "4. Resume only after analyst approval.",
        ],
        "continue": [
            "1. Continue the workflow with monitoring enabled.",
            "2. Keep this case attached to the workflow record.",
            "3. Re-score if new MISP or Cortex evidence appears.",
        ],
    }
    breakdown_lines = [f"- {item.category}: {item.score} ({item.rationale})" for item in breakdown]
    notes = request.notes or "No additional analyst notes provided."
    return "\n".join(
        [
            f"Security recommendation for workflow: {request.title}",
            f"Asset: {request.asset_name}",
            f"Workflow ID: {request.workflow_id or 'not supplied'}",
            f"Threat score: {score}/100",
            f"Decision: {decision.upper()}",
            "",
            "Scoring breakdown:",
            *breakdown_lines,
            "",
            "Recommended actions:",
            *action_lines[decision],
            "",
            f"Analyst notes: {notes}",
        ]
    )


def build_recommendation(request: ScoringRequest) -> RecommendationResponse:
    parts = [_score_wazuh(request.wazuh_alert), _score_misp(request.misp_enrichment), _score_cortex(request.cortex_analysis)]
    total = sum(item[0] for item in parts)
    score = min(int(round(total)), 100)
    breakdown = [item[1] for item in parts if item[1] is not None]
    evidence = [entry for item in parts for entry in item[2]]
    decision = _decision(score)
    summary = _summary(score, decision, request)
    subject = f"[{decision.upper()}] Security recommendation for {request.asset_name} ({score}/100)"
    body = _recommendation_body(request, score, decision, breakdown)

    return RecommendationResponse(
        score=score,
        decision=decision,
        allow_workflow_to_continue=decision == "continue",
        summary=summary,
        ai_generated=False,
        ai_provider="rules-fallback",
        recommendation_subject=subject,
        recommendation_body=body,
        breakdown=breakdown,
        evidence=evidence,
        iocs=[],
        pkis=[],
    )
