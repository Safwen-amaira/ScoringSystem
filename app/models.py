from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    source: str = Field(..., description="Origin of the evidence, e.g. Wazuh, MISP, Cortex")
    title: str
    severity: Optional[str] = None
    value: Optional[float] = None
    details: Optional[str] = None


class IOCItem(BaseModel):
    type: str
    value: str
    source: str


class PKIMetric(BaseModel):
    name: str
    value: float
    description: str


class WazuhAlert(BaseModel):
    rule_level: int = Field(..., ge=0, le=20)
    rule_description: str
    groups: List[str] = Field(default_factory=list)
    agent_name: Optional[str] = None
    source_ip: Optional[str] = None


class MISPEnrichment(BaseModel):
    threat_level_id: int = Field(..., ge=1, le=4, description="1 high, 4 low in MISP semantics")
    event_info: str
    tags: List[str] = Field(default_factory=list)
    attribute_count: int = Field(default=0, ge=0)
    known_bad_indicator: bool = False


class CortexAnalysis(BaseModel):
    analyzer_name: str
    verdict: str = Field(..., description="malicious, suspicious, safe, or unknown")
    taxonomies: List[str] = Field(default_factory=list)
    artifacts_flagged: int = Field(default=0, ge=0)
    summary: Optional[str] = None


class ScoringRequest(BaseModel):
    title: str
    asset_name: str
    analyst_email: Optional[str] = None
    workflow_id: Optional[str] = None
    wazuh_alert: Optional[WazuhAlert] = None
    misp_enrichment: Optional[MISPEnrichment] = None
    cortex_analysis: Optional[CortexAnalysis] = None
    notes: Optional[str] = None


class RawIntelligenceRequest(BaseModel):
    title: Optional[str] = None
    iris_case_name: Optional[str] = None
    asset_name: Optional[str] = None
    analyst_email: Optional[str] = None
    workflow_id: Optional[str] = None
    source: Optional[str] = None
    wazuh_alert: Optional[dict] = None
    misp_event: Optional[dict] = None
    cortex_analysis: Optional[dict] = None
    notes: Optional[str] = None


class ScoreBreakdown(BaseModel):
    category: str
    score: float
    rationale: str


class RecommendationResponse(BaseModel):
    score: int
    decision: str
    allow_workflow_to_continue: bool
    summary: str
    ai_generated: bool
    ai_provider: str
    score_model: str = "hbrain-banking-v1"
    recommendation_subject: str
    recommendation_body: str
    workflow_playbook: str = ""
    breakdown: List[ScoreBreakdown]
    evidence: List[EvidenceItem]
    iocs: List[IOCItem]
    pkis: List[PKIMetric]


class ScoreResponse(BaseModel):
    score: int
    decision: str
    allow_workflow_to_continue: bool
    summary: str
    ai_generated: bool
    ai_provider: str
    score_model: str = "hbrain-banking-v1"
    workflow_playbook: str = ""
    breakdown: List[ScoreBreakdown]
    evidence: List[EvidenceItem]
    iocs: List[IOCItem]
    pkis: List[PKIMetric]


class EmailContentResponse(BaseModel):
    subject: str
    html: str
    text: str
    ai_generated: bool
    ai_provider: str


class ScoreAndRecommendationHTMLResponse(BaseModel):
    score: ScoreResponse
    recommendation: RecommendationResponse
    email: EmailContentResponse


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    token: str
    email: str
    display_name: str


class DashboardCaseSummary(BaseModel):
    id: int
    case_name: str
    iris_case_name: Optional[str] = None
    asset_name: str
    severity: str
    score: int
    decision: str
    workflow_playbook: str
    mitre_count: int
    created_at: str
    cve_count: int
    ioc_count: int
    ai_provider: str


class DashboardCaseDetail(BaseModel):
    id: int
    case_name: str
    iris_case_name: Optional[str] = None
    asset_name: str
    severity: str
    score: int
    decision: str
    summary: str
    recommendation_subject: str
    recommendation_body: str
    workflow_playbook: str
    score_model: str = "hbrain-banking-v1"
    created_at: str
    iocs: List[IOCItem]
    pkis: List[PKIMetric]
    cves: List[dict]
    mitre_attacks: List[dict]
    raw_payload: dict
    normalized_payload: dict
    result_payload: dict
    email_payload: dict


class DashboardCaseListResponse(BaseModel):
    items: List[DashboardCaseSummary]
    total: int
    page: int
    page_size: int


class CVEListResponse(BaseModel):
    items: List[dict]
    total: int
    page: int
    page_size: int


class DashboardOverview(BaseModel):
    total_cases: int
    critical_cases: int
    average_score: float
    open_stop_cases: int
    cve_matches: int
    unread_notifications: int
    latest_cases: List[DashboardCaseSummary]


class WazuhAlertIngestRequest(BaseModel):
    title: Optional[str] = None
    iris_case_name: Optional[str] = None
    asset_name: Optional[str] = None
    workflow_id: Optional[str] = None
    notes: Optional[str] = None
    wazuh_alert: dict
    auto_create_incident: bool = True


class ExternalItemResponse(BaseModel):
    id: int
    source_id: str
    title: str
    severity: str
    created_at: str
    raw_payload: dict


class ExternalItemListResponse(BaseModel):
    items: List[ExternalItemResponse]
    total: int
    page: int
    page_size: int


class NotificationItem(BaseModel):
    id: int
    title: str
    severity: str
    created_at: str
    case_id: Optional[int] = None
    is_read: bool
    body: str


class NotificationListResponse(BaseModel):
    items: List[NotificationItem]
    total: int


class SettingsResponse(BaseModel):
    misp_base_url: str = ""
    misp_api_key: str = ""
    cortex_base_url: str = ""
    cortex_api_key: str = ""
    iris_base_url: str = ""
    iris_api_key: str = ""
    notification_email: str = ""
    dashboard_email: str = ""
    ollama_model: str = ""
    ollama_base_url: str = ""


class SettingsUpdateRequest(BaseModel):
    misp_base_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    cortex_base_url: Optional[str] = None
    cortex_api_key: Optional[str] = None
    iris_base_url: Optional[str] = None
    iris_api_key: Optional[str] = None
    notification_email: Optional[str] = None
    dashboard_email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class MitreTechniqueResponse(BaseModel):
    external_id: str
    name: str
    tactics: List[str]
    platforms: List[str]
    url: str


class MitreTechniqueListResponse(BaseModel):
    items: List[MitreTechniqueResponse]
    total: int
    page: int
    page_size: int
