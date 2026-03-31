from __future__ import annotations

from typing import Any, List

from .models import CortexAnalysis, EvidenceItem, MISPEnrichment, RecommendationResponse, ScoreBreakdown, ScoringRequest, WazuhAlert
from .score_model import extract_feature_map, get_score_model


def _wazuh_component(alert: WazuhAlert | None) -> tuple[float, ScoreBreakdown | None, list[EvidenceItem]]:
    if not alert:
        return 0.0, None, []
    base = min(alert.rule_level * 2.6, 24)
    groups = [group.lower() for group in alert.groups]
    if any(group in groups for group in ["malware", "privilege_escalation", "web"]):
        base += 6
    if "authentication_failed" in groups:
        base += 4
    score = min(base, 30)
    breakdown = ScoreBreakdown(
        category="Threat Pressure",
        score=round(score, 1),
        rationale=f"Wazuh telemetry raised pressure through rule level {alert.rule_level} and groups {', '.join(alert.groups) or 'none'}.",
    )
    evidence = [
        EvidenceItem(
            source="Wazuh",
            title=alert.rule_description,
            severity=str(alert.rule_level),
            value=score,
            details=f"Agent={alert.agent_name or 'unknown'}, source_ip={alert.source_ip or 'n/a'}",
        )
    ]
    return score, breakdown, evidence


def _misp_component(misp: MISPEnrichment | None) -> tuple[float, ScoreBreakdown | None, list[EvidenceItem]]:
    if not misp:
        return 0.0, None, []
    severity_map = {1: 20, 2: 15, 3: 9, 4: 4}
    score = severity_map[misp.threat_level_id] + min(misp.attribute_count * 0.8, 6)
    if misp.known_bad_indicator:
        score += 5
    score = min(score, 25)
    breakdown = ScoreBreakdown(
        category="Threat Intelligence Confidence",
        score=round(score, 1),
        rationale=f"MISP enrichment contributed threat level {misp.threat_level_id} with {misp.attribute_count} attributes and known-bad matching={misp.known_bad_indicator}.",
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
    return score, breakdown, evidence


def _cortex_component(cortex: CortexAnalysis | None) -> tuple[float, ScoreBreakdown | None, list[EvidenceItem]]:
    if not cortex:
        return 0.0, None, []
    verdict_map = {"malicious": 18, "suspicious": 12, "unknown": 6, "safe": 0}
    score = verdict_map.get(cortex.verdict.lower(), 6) + min(cortex.artifacts_flagged * 1.8, 7)
    if any("confidence:high" in item.lower() or "malicious" in item.lower() for item in cortex.taxonomies):
        score += 4
    score = min(score, 25)
    breakdown = ScoreBreakdown(
        category="Exploitability and Validation",
        score=round(score, 1),
        rationale=f"Cortex analyzer {cortex.analyzer_name} returned {cortex.verdict} with {cortex.artifacts_flagged} flagged artifacts.",
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
    return score, breakdown, evidence


def _compliance_component(request: ScoringRequest) -> tuple[float, ScoreBreakdown]:
    text = " ".join(
        value
        for value in [
            request.title,
            request.asset_name,
            request.workflow_id or "",
            request.notes or "",
            request.misp_enrichment.event_info if request.misp_enrichment else "",
        ]
        if value
    ).lower()
    score = 4.0
    if any(token in text for token in ["bank", "payment", "pci", "card", "swift", "core", "finance"]):
        score += 12
    if any(token in text for token in ["customer", "credential", "identity", "privilege", "payment gateway"]):
        score += 6
    score = min(score, 20)
    return (
        score,
        ScoreBreakdown(
            category="ISO 27001 / PCI DSS Impact",
            score=round(score, 1),
            rationale="Compliance impact grows when customer data, payment systems, identity, or core banking keywords are involved.",
        ),
    )


def _workflow_component(request: ScoringRequest, score_so_far: float) -> tuple[float, ScoreBreakdown]:
    workflow_text = f"{request.workflow_id or ''} {request.notes or ''}".lower()
    score = 3.0
    if request.workflow_id:
        score += 4
    if any(token in workflow_text for token in ["critical", "production", "playbook", "containment", "banking", "core"]):
        score += 6
    if score_so_far >= 70:
        score += 4
    score = min(score, 15)
    return (
        score,
        ScoreBreakdown(
            category="Workflow and Operational Exposure",
            score=round(score, 1),
            rationale="Operational playbooks and production workflows increase urgency when the case already carries strong malicious pressure.",
        ),
    )


def _summary(score: int, decision: str, request: ScoringRequest) -> str:
    if decision == "stop":
        return f"H-Brain banking score {score}/100 marks {request.asset_name} as a high-risk incident. Stop the workflow and launch the response playbook immediately."
    if decision == "review":
        return f"H-Brain banking score {score}/100 requires analyst validation for {request.asset_name}. Hold the workflow until triage confirms the path."
    return f"H-Brain banking score {score}/100 allows controlled continuation for {request.asset_name}, with monitoring and staged workflow safeguards."


def _playbook(request: ScoringRequest, decision: str) -> str:
    if decision == "stop":
        return "Critical banking incident containment playbook"
    if "payment" in f"{request.title} {request.notes or ''}".lower():
        return "Payment security validation playbook"
    if decision == "review":
        return "Enhanced analyst triage playbook"
    return "Monitored workflow continuation playbook"


def _recommendation_body(request: ScoringRequest, score: int, decision: str, breakdown: List[ScoreBreakdown], workflow_playbook: str) -> str:
    if decision == "stop":
        actions = [
            "1. Stop the workflow and activate the incident response bridge.",
            "2. Isolate the impacted asset or edge session.",
            "3. Preserve Wazuh, MISP, Cortex, and workflow evidence.",
            "4. Execute the banking containment playbook and notify stakeholders.",
        ]
    elif decision == "review":
        actions = [
            "1. Pause the workflow pending analyst review.",
            "2. Validate indicators against threat intelligence and host telemetry.",
            "3. Confirm whether customer, payment, or identity exposure exists.",
            "4. Resume only after the review playbook is cleared.",
        ]
    else:
        actions = [
            "1. Continue the workflow with elevated monitoring.",
            "2. Re-score if new Wazuh, MISP, or Cortex evidence is received.",
            "3. Keep this case attached to the workflow execution record.",
        ]
    body = [
        f"Hanicar H-Brain recommendation for workflow: {request.title}",
        f"Asset: {request.asset_name}",
        f"Workflow ID: {request.workflow_id or 'not supplied'}",
        f"H-Brain banking score: {score}/100",
        f"Decision: {decision.upper()}",
        f"Workflow playbook: {workflow_playbook}",
        "",
        "Score rationale:",
        *[f"- {item.category}: {item.score} ({item.rationale})" for item in breakdown],
        "",
        "Recommended actions:",
        *actions,
        "",
        f"Analyst notes: {request.notes or 'No additional analyst notes provided.'}",
    ]
    return "\n".join(body)


def build_recommendation(request: ScoringRequest, ai_features: dict[str, Any] | None = None, cve_count: int = 0) -> RecommendationResponse:
    parts = [_wazuh_component(request.wazuh_alert), _misp_component(request.misp_enrichment), _cortex_component(request.cortex_analysis)]
    component_score = sum(item[0] for item in parts)
    compliance_score, compliance_breakdown = _compliance_component(request)
    workflow_score, workflow_breakdown = _workflow_component(request, component_score + compliance_score)
    model = get_score_model()
    feature_map = extract_feature_map(request, ai_features=ai_features, cve_count=cve_count)
    heuristic_score = min(int(round(component_score + compliance_score + workflow_score)), 100)
    model_score = model.predict_score(feature_map)
    score = max(0, min(100, int(round((model_score * 0.8) + (heuristic_score * 0.2)))))
    decision = model.decision(score)
    breakdown = [item[1] for item in parts if item[1] is not None] + [compliance_breakdown, workflow_breakdown]
    evidence = [entry for item in parts for entry in item[2]]
    summary = _summary(score, decision, request)
    workflow_playbook = _playbook(request, decision)
    body = _recommendation_body(request, score, decision, breakdown, workflow_playbook)
    subject = f"[{decision.upper()}] Hanicar H-Brain recommendation for {request.asset_name} ({score}/100)"

    return RecommendationResponse(
        score=score,
        decision=decision,
        allow_workflow_to_continue=decision == "continue",
        summary=summary,
        ai_generated=False,
        ai_provider="rules-fallback",
        score_model=model.model_name,
        recommendation_subject=subject,
        recommendation_body=body,
        workflow_playbook=workflow_playbook,
        breakdown=breakdown,
        evidence=evidence,
        iocs=[],
        pkis=[],
    )
