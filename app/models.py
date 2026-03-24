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
    asset_name: Optional[str] = None
    analyst_email: Optional[str] = None
    workflow_id: Optional[str] = None
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
    recommendation_subject: str
    recommendation_body: str
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
