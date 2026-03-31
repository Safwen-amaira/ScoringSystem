from __future__ import annotations

from typing import Any

from .models import CortexAnalysis, EvidenceItem, MISPEnrichment, RecommendationResponse, ScoreBreakdown, ScoringRequest, WazuhAlert
from .score_model import extract_feature_map, get_score_model


def _wazuh_component(alert: WazuhAlert | None) -> tuple[float, ScoreBreakdown | None, list[EvidenceItem]]:
    if not alert:
        return 0.0, None, []
    score = min(alert.rule_level * 2.2, 26)
    groups = [group.lower() for group in alert.groups]
    if "authentication_failed" in groups:
        score += 4
    if any(group in groups for group in ["malware", "web", "privilege_escalation"]):
        score += 5
    score = min(score, 30)
    return (
        score,
        ScoreBreakdown(category="Wazuh Telemetry", score=round(score, 1), rationale=f"Wazuh rule level {alert.rule_level} with groups {', '.join(alert.groups) or 'none'} contributed operational pressure."),
        [EvidenceItem(source="Wazuh", title=alert.rule_description, severity=str(alert.rule_level), value=round(score, 1), details=f"Agent={alert.agent_name or 'unknown'}, source_ip={alert.source_ip or 'n/a'}")],
    )


def _misp_component(misp: MISPEnrichment | None) -> tuple[float, ScoreBreakdown | None, list[EvidenceItem]]:
    if not misp:
        return 0.0, None, []
    threat_map = {1: 18, 2: 12, 3: 7, 4: 2}
    score = threat_map[misp.threat_level_id] + min(misp.attribute_count * 0.35, 8)
    if misp.known_bad_indicator:
        score += 6
    score = min(score, 26)
    return (
        score,
        ScoreBreakdown(category="MISP Intelligence", score=round(score, 1), rationale=f"MISP threat level {misp.threat_level_id} with {misp.attribute_count} attributes and known-bad={misp.known_bad_indicator} shaped the intelligence posture."),
        [EvidenceItem(source="MISP", title=misp.event_info, severity=f"threat-level-{misp.threat_level_id}", value=round(score, 1), details=f"Tags={', '.join(misp.tags) or 'none'}")],
    )


def _cortex_component(cortex: CortexAnalysis | None) -> tuple[float, ScoreBreakdown | None, list[EvidenceItem]]:
    if not cortex:
        return 0.0, None, []
    verdict_map = {"malicious": 20, "suspicious": 11, "unknown": 4, "safe": 0}
    score = verdict_map.get(cortex.verdict.lower(), 4) + min(cortex.artifacts_flagged * 1.2, 8)
    score = min(score, 28)
    return (
        score,
        ScoreBreakdown(category="Cortex Analysis", score=round(score, 1), rationale=f"Cortex analyzer {cortex.analyzer_name} returned {cortex.verdict} with {cortex.artifacts_flagged} flagged artifacts."),
        [EvidenceItem(source="Cortex", title=f"{cortex.analyzer_name} verdict", severity=cortex.verdict, value=round(score, 1), details=cortex.summary or f"Taxonomies={', '.join(cortex.taxonomies) or 'none'}")],
    )


def _compliance_component(request: ScoringRequest) -> tuple[float, ScoreBreakdown]:
    text = " ".join(filter(None, [request.title, request.asset_name, request.workflow_id or "", request.notes or "", request.misp_enrichment.event_info if request.misp_enrichment else ""])).lower()
    score = 2.0
    if any(token in text for token in ["bank", "payment", "pci", "swift", "issuer", "merchant", "card"]):
        score += 10
    if any(token in text for token in ["customer", "credential", "identity", "account", "iban"]):
        score += 6
    score = min(score, 18)
    return score, ScoreBreakdown(category="ISO 27001 / PCI DSS Context", score=round(score, 1), rationale="Banking systems, customer identities, and payment paths increase regulatory and business impact.")


def _workflow_component(request: ScoringRequest) -> tuple[float, ScoreBreakdown]:
    text = f"{request.workflow_id or ''} {request.notes or ''}".lower()
    score = 1.0
    if request.workflow_id:
        score += 3
    if any(token in text for token in ["critical", "production", "workflow", "containment", "playbook"]):
        score += 5
    score = min(score, 10)
    return score, ScoreBreakdown(category="Workflow Exposure", score=round(score, 1), rationale="Production workflows and containment-sensitive playbooks increase urgency.")


def _weighted_feature_map(feature_map: dict[str, float]) -> dict[str, float]:
    weighted = dict(feature_map)
    weighted["cortex_malicious"] *= 1.5
    weighted["known_bad_indicator"] *= 1.3
    weighted["lateral_movement_signal"] *= 1.2
    weighted["exfiltration_signal"] *= 1.2
    return weighted


def _rule_boosts(feature_map: dict[str, float]) -> tuple[float, list[ScoreBreakdown]]:
    score = 0.0
    reasons: list[ScoreBreakdown] = []
    if feature_map["cortex_malicious"] >= 1:
        score += 25
        reasons.append(ScoreBreakdown(category="Rule Boost", score=25, rationale="Cortex marked the case as malicious (+25)."))
    if feature_map["known_bad_indicator"] >= 1:
        score += 15
        reasons.append(ScoreBreakdown(category="Rule Boost", score=15, rationale="MISP known-bad indicator matched the case (+15)."))
    if feature_map["lateral_movement_signal"] >= 1:
        score += 10
        reasons.append(ScoreBreakdown(category="Rule Boost", score=10, rationale="Lateral movement was detected or inferred (+10)."))
    if feature_map["exfiltration_signal"] >= 1:
        score += 12
        reasons.append(ScoreBreakdown(category="Rule Boost", score=12, rationale="Exfiltration behavior was detected or inferred (+12)."))
    if feature_map["alert_volume"] > 10:
        score += 10
        reasons.append(ScoreBreakdown(category="Burst Detection", score=10, rationale="Alert volume exceeded 10 related events in a short period (+10)."))
    return score, reasons


def _contextual_decision(score: int, feature_map: dict[str, float]) -> str:
    if score >= 85:
        return "stop"
    if score >= 70 and feature_map["banking_asset"] >= 1:
        return "stop"
    if score >= 60 and feature_map["lateral_movement_signal"] >= 1:
        return "stop"
    if score >= 50:
        return "review"
    return "continue"


def _apply_hard_bounds(score: float, feature_map: dict[str, float]) -> tuple[int, list[ScoreBreakdown]]:
    changes: list[ScoreBreakdown] = []
    if feature_map["rule_level"] <= 3 and not any(feature_map[key] >= 1 for key in ["cortex_malicious", "known_bad_indicator", "lateral_movement_signal", "exfiltration_signal"]):
        score = min(score, 24)
        changes.append(ScoreBreakdown(category="Protective Cap", score=-999, rationale="Low-rule event without strong signals was capped below 25."))
    if feature_map["cortex_malicious"] >= 1 and feature_map["banking_asset"] >= 1:
        score = max(score, 80)
        changes.append(ScoreBreakdown(category="Critical Floor", score=999, rationale="Malicious Cortex verdict on a banking asset forced the score to at least 80."))
    return max(0, min(100, int(round(score)))), changes


def _summary(score: int, decision: str, request: ScoringRequest) -> str:
    if decision == "stop":
        return f"H-Brain banking score {score}/100 marks {request.asset_name} as a high-risk incident. Stop the workflow and launch containment immediately."
    if decision == "review":
        return f"H-Brain banking score {score}/100 requires analyst validation for {request.asset_name}. Hold the workflow while triage confirms the threat path."
    return f"H-Brain banking score {score}/100 allows controlled continuation for {request.asset_name}, with monitoring and staged safeguards."


def _playbook(request: ScoringRequest, decision: str) -> str:
    if decision == "stop":
        return "Critical banking incident containment playbook"
    if decision == "review":
        return "Enhanced analyst triage playbook"
    if "payment" in f"{request.title} {request.notes or ''}".lower():
        return "Payment security validation playbook"
    return "Monitored workflow continuation playbook"


def _recommendation_body(request: ScoringRequest, score: int, decision: str, breakdown: list[ScoreBreakdown], workflow_playbook: str) -> str:
    actions = {
        "stop": [
            "1. Stop the workflow and activate the incident response bridge.",
            "2. Isolate impacted assets, sessions, or network paths.",
            "3. Preserve Wazuh, MISP, Cortex, and workflow evidence immediately.",
            "4. Execute the banking containment playbook and notify stakeholders.",
        ],
        "review": [
            "1. Pause the workflow pending analyst review.",
            "2. Validate the strongest indicators against host and identity telemetry.",
            "3. Confirm whether customer, payment, or identity exposure exists.",
            "4. Resume only after review approval is documented.",
        ],
        "continue": [
            "1. Continue with elevated monitoring and logging.",
            "2. Re-score the case if new Wazuh, MISP, or Cortex evidence is received.",
            "3. Keep the incident linked to the workflow execution record.",
        ],
    }[decision]
    body = [
        f"Hanicar H-Brain recommendation for workflow: {request.title}",
        f"Asset: {request.asset_name}",
        f"Workflow ID: {request.workflow_id or 'not supplied'}",
        f"H-Brain banking score: {score}/100",
        f"Decision: {decision.upper()}",
        f"Workflow playbook: {workflow_playbook}",
        "",
        "Score rationale:",
        *[f"- {item.category}: {item.rationale}" for item in breakdown],
        "",
        "Recommended actions:",
        *actions,
        "",
        f"Analyst notes: {request.notes or 'No additional analyst notes provided.'}",
    ]
    return "\n".join(body)


def build_recommendation(request: ScoringRequest, ai_features: dict[str, Any] | None = None, cve_count: int = 0) -> RecommendationResponse:
    parts = [_wazuh_component(request.wazuh_alert), _misp_component(request.misp_enrichment), _cortex_component(request.cortex_analysis)]
    base_rule_score = sum(item[0] for item in parts)
    compliance_score, compliance_breakdown = _compliance_component(request)
    workflow_score, workflow_breakdown = _workflow_component(request)
    feature_map = extract_feature_map(request, ai_features=ai_features, cve_count=cve_count)
    weighted_feature_map = _weighted_feature_map(feature_map)
    model = get_score_model()
    ml_score = model.predict_score(weighted_feature_map)
    boost_score, boost_breakdowns = _rule_boosts(feature_map)
    rule_score = min(100.0, base_rule_score + compliance_score + workflow_score + boost_score)
    hybrid_score = (0.75 * ml_score) + (0.25 * rule_score)
    confidence_modifier = 0.8 + (0.2 * max(0.0, min(1.0, feature_map["intel_confidence"])))
    adjusted_score = hybrid_score * confidence_modifier
    score, boundary_breakdowns = _apply_hard_bounds(adjusted_score, feature_map)
    decision = _contextual_decision(score, feature_map)

    breakdown = [
        item[1] for item in parts if item[1] is not None
    ] + [
        compliance_breakdown,
        workflow_breakdown,
        ScoreBreakdown(category="ML Score", score=round(ml_score, 1), rationale="RandomForest model prediction derived from banking CTI scenario training data."),
        ScoreBreakdown(category="Rule Engine Score", score=round(rule_score, 1), rationale="Deterministic SOC rule score built from source telemetry, compliance context, and strong-signal boosts."),
        ScoreBreakdown(category="Confidence Modifier", score=round(confidence_modifier, 2), rationale="Intel confidence was used only as a multiplier, not as a direct source of risk."),
        *boost_breakdowns,
        *boundary_breakdowns,
    ]
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
