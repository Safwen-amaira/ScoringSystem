from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ai import AIRecommendationService
from .cve import extract_cve_ids
from .db import (
    dashboard_overview,
    ensure_cves,
    get_case,
    init_db,
    list_cases,
    list_cves,
    login,
    require_session,
    seed_demo_case,
    store_case,
    sync_recent_cves,
)
from .emailer import send_recommendation_mail
from .hbrain_store import (
    create_notification,
    get_settings,
    init_hbrain_store,
    list_external_items,
    list_iris_cases,
    list_mitre,
    list_notifications,
    mark_notification_read,
    store_cortex_job,
    store_misp_event,
    store_wazuh_alert,
    sync_cortex_from_settings,
    sync_iris_from_settings,
    sync_misp_from_settings,
    sync_mitre_techniques,
    update_settings,
)
from .ingestion import compute_pkis, extract_iocs, normalize_raw_request
from .mitre import match_techniques
from .models import (
    CVEListResponse,
    ChatRequest,
    ChatResponse,
    DashboardCaseDetail,
    DashboardCaseListResponse,
    DashboardOverview,
    EmailContentResponse,
    ExternalItemListResponse,
    LoginRequest,
    LoginResponse,
    MitreTechniqueListResponse,
    NotificationListResponse,
    RawIntelligenceRequest,
    RecommendationResponse,
    ScoreAndRecommendationHTMLResponse,
    ScoreResponse,
    ScoringRequest,
    SettingsResponse,
    SettingsUpdateRequest,
    WazuhAlertIngestRequest,
)
from .score_model import TRAINING_CSV, ensure_training_dataset, get_score_model
from .scoring import build_recommendation


app = FastAPI(title="Hanicar H-Brain", version="0.2.0")
ai_service = AIRecommendationService()

allowed_origins = [origin.strip() for origin in os.getenv("HANICAR_DASHBOARD_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = Path(__file__).resolve().parent.parent / "web"
app.mount("/assets", StaticFiles(directory=static_dir), name="assets")


@app.on_event("startup")
def startup() -> None:
    init_db()
    init_hbrain_store()
    sync_recent_cves()
    sync_mitre_techniques()
    ensure_training_dataset()
    get_score_model()
    seed_demo_case()


@app.get("/")
def home() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    user = require_session(authorization.split(" ", 1)[1])
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return user


def _combined_text(raw_request: RawIntelligenceRequest, normalized_request: ScoringRequest) -> str:
    return " ".join(
        filter(
            None,
            [
                normalized_request.title,
                normalized_request.asset_name,
                normalized_request.workflow_id or "",
                normalized_request.notes or "",
                raw_request.iris_case_name or "",
                str(raw_request.wazuh_alert or ""),
                str(raw_request.misp_event or ""),
                str(raw_request.cortex_analysis or ""),
            ],
        )
    )


def _score_response(result: RecommendationResponse) -> ScoreResponse:
    return ScoreResponse(
        score=result.score,
        decision=result.decision,
        allow_workflow_to_continue=result.allow_workflow_to_continue,
        summary=result.summary,
        ai_generated=result.ai_generated,
        ai_provider=result.ai_provider,
        score_model=result.score_model,
        workflow_playbook=result.workflow_playbook,
        breakdown=result.breakdown,
        evidence=result.evidence,
        iocs=result.iocs,
        pkis=result.pkis,
    )


def _build_full_result(request: ScoringRequest, cve_count: int = 0) -> RecommendationResponse:
    ai_features = ai_service.extract_score_features(request)
    result = build_recommendation(request, ai_features=ai_features, cve_count=cve_count)
    summary, body, ai_generated, ai_provider = ai_service.enrich_recommendation(request, result)
    result.iocs = extract_iocs(request.model_dump())
    result.pkis = compute_pkis(request, result.iocs)
    result.summary = summary
    result.recommendation_body = body
    result.ai_generated = ai_generated
    result.ai_provider = ai_provider
    return result


def _normalize_raw(request: RawIntelligenceRequest) -> tuple[ScoringRequest, RecommendationResponse, list[dict]]:
    cve_ids = extract_cve_ids(request.model_dump())
    cve_rows = ensure_cves(cve_ids)
    normalized_request, iocs, pkis = normalize_raw_request(request)
    result = _build_full_result(normalized_request, cve_count=len(cve_rows))
    result.iocs = iocs
    result.pkis = pkis
    return normalized_request, result, cve_rows


def _email_payload(request: ScoringRequest, result: RecommendationResponse) -> EmailContentResponse:
    html_body, html_ai_generated, html_ai_provider = ai_service.render_email_html(request, result)
    return EmailContentResponse(
        subject=result.recommendation_subject,
        html=html_body,
        text=result.recommendation_body,
        ai_generated=html_ai_generated,
        ai_provider=html_ai_provider,
    )


def _store_raw_case(raw_request: RawIntelligenceRequest, normalized_request: ScoringRequest, result: RecommendationResponse, cve_rows: list[dict]) -> int:
    email_payload = _email_payload(normalized_request, result)
    if raw_request.wazuh_alert:
        store_wazuh_alert(
            source_id=str(raw_request.wazuh_alert.get("id") or raw_request.wazuh_alert.get("_id") or normalized_request.title),
            title=str(raw_request.wazuh_alert.get("rule", {}).get("description") or normalized_request.title),
            severity="critical" if (raw_request.wazuh_alert.get("rule", {}).get("level") or 0) >= 14 else "high" if (raw_request.wazuh_alert.get("rule", {}).get("level") or 0) >= 10 else "medium",
            raw_payload=raw_request.wazuh_alert,
        )
    if raw_request.misp_event:
        event = raw_request.misp_event.get("Event", raw_request.misp_event)
        store_misp_event(
            source_id=str(event.get("id") or event.get("uuid") or normalized_request.title),
            title=str(event.get("info") or normalized_request.title),
            severity="critical" if str(event.get("threat_level_id") or "4") == "1" else "high" if str(event.get("threat_level_id") or "4") == "2" else "medium",
            raw_payload=raw_request.misp_event,
        )
    if raw_request.cortex_analysis:
        blob = str(raw_request.cortex_analysis).lower()
        store_cortex_job(
            source_id=str(raw_request.cortex_analysis.get("id") or raw_request.cortex_analysis.get("_id") or normalized_request.title),
            title=str(raw_request.cortex_analysis.get("analyzerName") or raw_request.cortex_analysis.get("analyzer_name") or normalized_request.title),
            severity="critical" if "malicious" in blob else "high" if "suspicious" in blob else "medium",
            raw_payload=raw_request.cortex_analysis,
        )
    case_id = store_case(
        raw_payload=raw_request.model_dump(),
        normalized_request=normalized_request,
        result=result,
        email_payload=email_payload,
        cve_ids=[item["cve_id"] for item in cve_rows],
        iris_case_name=raw_request.iris_case_name,
    )
    techniques, _ = list_mitre(page=1, page_size=1000, search=None)
    for technique in match_techniques(techniques, _combined_text(raw_request, normalized_request)):
        from .hbrain_store import link_case_mitre

        link_case_mitre(case_id, [technique["external_id"]])
    if result.decision in {"stop", "review"}:
        create_notification(case_id, result.recommendation_subject, "critical" if result.decision == "stop" else "high", result.summary)
    return case_id


@app.post("/api/auth/login", response_model=LoginResponse)
def auth_login(request: LoginRequest) -> LoginResponse:
    session = login(request.email, request.password)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return LoginResponse(**session)


@app.post("/api/score", response_model=ScoreResponse)
def score(request: ScoringRequest) -> ScoreResponse:
    return _score_response(_build_full_result(request))


@app.post("/api/email-content", response_model=EmailContentResponse)
def email_content(request: ScoringRequest) -> EmailContentResponse:
    result = _build_full_result(request)
    return _email_payload(request, result)


@app.post("/api/analyze", response_model=RecommendationResponse)
def analyze(request: ScoringRequest) -> RecommendationResponse:
    return _build_full_result(request)


@app.post("/api/score/raw", response_model=ScoreResponse)
def score_raw(request: RawIntelligenceRequest) -> ScoreResponse:
    normalized_request, result, cve_rows = _normalize_raw(request)
    _store_raw_case(request, normalized_request, result, cve_rows)
    return _score_response(result)


@app.post("/api/recommendation", response_model=RecommendationResponse)
def recommendation(request: RawIntelligenceRequest) -> RecommendationResponse:
    normalized_request, result, cve_rows = _normalize_raw(request)
    _store_raw_case(request, normalized_request, result, cve_rows)
    return result


@app.post("/api/recommendation/email", response_model=EmailContentResponse)
def recommendation_email(request: RawIntelligenceRequest) -> EmailContentResponse:
    normalized_request, result, cve_rows = _normalize_raw(request)
    _store_raw_case(request, normalized_request, result, cve_rows)
    return _email_payload(normalized_request, result)


@app.post("/api/intelligence/score-html", response_model=ScoreAndRecommendationHTMLResponse)
def intelligence_score_html(request: RawIntelligenceRequest) -> ScoreAndRecommendationHTMLResponse:
    normalized_request, result, cve_rows = _normalize_raw(request)
    _store_raw_case(request, normalized_request, result, cve_rows)
    return ScoreAndRecommendationHTMLResponse(
        score=_score_response(result),
        recommendation=result,
        email=_email_payload(normalized_request, result),
    )


@app.post("/api/score-and-email")
def score_and_email(request: ScoringRequest) -> dict:
    response = _build_full_result(request)
    email_payload = _email_payload(request, response)
    try:
        sent = send_recommendation_mail(
            request,
            response.recommendation_subject,
            response.recommendation_body,
            email_payload.html,
        )
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=502, detail=f"Email dispatch failed: {exc}") from exc

    return {"score": _score_response(response).model_dump(), "email": email_payload.model_dump(), "email_sent": sent}


@app.post("/api/chat", response_model=ChatResponse)
def api_chat(request: ChatRequest, _: dict = Depends(_current_user)) -> ChatResponse:
    reply = ai_service.chat([message.model_dump() for message in request.messages])
    return ChatResponse(message={"role": "assistant", "content": reply})


@app.get("/api/dashboard/overview", response_model=DashboardOverview)
def api_dashboard_overview(_: dict = Depends(_current_user)) -> DashboardOverview:
    overview = dashboard_overview()
    notifications, unread = list_notifications()
    return DashboardOverview(
        total_cases=overview.total_cases,
        critical_cases=overview.critical_cases,
        average_score=overview.average_score,
        open_stop_cases=overview.open_stop_cases,
        cve_matches=overview.cve_matches,
        unread_notifications=unread,
        latest_cases=overview.latest_cases,
    )


@app.get("/api/dashboard/cases", response_model=DashboardCaseListResponse)
def api_dashboard_cases(
    page: int = 1,
    page_size: int = 10,
    severity: str | None = None,
    decision: str | None = None,
    min_score: int | None = None,
    search: str | None = None,
    _: dict = Depends(_current_user),
) -> DashboardCaseListResponse:
    page_size = min(max(page_size, 1), 100)
    items, total = list_cases(page=page, page_size=page_size, severity=severity, decision=decision, min_score=min_score, search=search)
    return DashboardCaseListResponse(items=items, total=total, page=page, page_size=page_size)


@app.get("/api/dashboard/cases/{case_id}", response_model=DashboardCaseDetail)
def api_dashboard_case(case_id: int, _: dict = Depends(_current_user)) -> DashboardCaseDetail:
    detail = get_case(case_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.post("/api/dashboard/cases/ingest", response_model=DashboardCaseDetail)
def api_dashboard_ingest(request: RawIntelligenceRequest, _: dict = Depends(_current_user)) -> DashboardCaseDetail:
    normalized_request, result, cve_rows = _normalize_raw(request)
    case_id = _store_raw_case(request, normalized_request, result, cve_rows)
    detail = get_case(case_id)
    if not detail:
        raise HTTPException(status_code=500, detail="Stored case could not be loaded")
    return detail


@app.get("/api/dashboard/cves", response_model=CVEListResponse)
def api_dashboard_cves(
    page: int = 1,
    page_size: int = 12,
    search: str | None = None,
    _: dict = Depends(_current_user),
) -> CVEListResponse:
    page_size = min(max(page_size, 1), 100)
    items, total = list_cves(page=page, page_size=page_size, search=search)
    return CVEListResponse(items=items, total=total, page=page, page_size=page_size)


@app.get("/api/dashboard/notifications", response_model=NotificationListResponse)
def api_notifications(_: dict = Depends(_current_user)) -> NotificationListResponse:
    items, total = list_notifications()
    return NotificationListResponse(items=items, total=total)


@app.post("/api/dashboard/notifications/{notification_id}/read")
def api_notification_read(notification_id: int, _: dict = Depends(_current_user)) -> dict[str, str]:
    mark_notification_read(notification_id)
    return {"status": "ok"}


@app.get("/api/dashboard/settings", response_model=SettingsResponse)
def api_settings(_: dict = Depends(_current_user)) -> SettingsResponse:
    return get_settings()


@app.post("/api/dashboard/settings", response_model=SettingsResponse)
def api_settings_update(request: SettingsUpdateRequest, user: dict = Depends(_current_user)) -> SettingsResponse:
    try:
        return update_settings(user["email"], request.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/integrations/wazuh/alerts")
def api_wazuh_alert_ingest(request: WazuhAlertIngestRequest) -> dict:
    title = request.title or request.wazuh_alert.get("rule", {}).get("description") or "Wazuh alert"
    severity_value = request.wazuh_alert.get("rule", {}).get("level", 5)
    severity = "critical" if severity_value >= 14 else "high" if severity_value >= 10 else "medium" if severity_value >= 6 else "low"
    alert_id = store_wazuh_alert(
        source_id=str(request.wazuh_alert.get("id") or request.wazuh_alert.get("_id") or title),
        title=title,
        severity=severity,
        raw_payload=request.wazuh_alert,
    )
    case_id = None
    if request.auto_create_incident:
        raw_request = RawIntelligenceRequest(
            title=title,
            iris_case_name=request.iris_case_name,
            asset_name=request.asset_name or request.wazuh_alert.get("agent", {}).get("name") or "unknown-asset",
            workflow_id=request.workflow_id,
            wazuh_alert=request.wazuh_alert,
            notes=request.notes,
            source="wazuh",
        )
        normalized_request, result, cve_rows = _normalize_raw(raw_request)
        case_id = _store_raw_case(raw_request, normalized_request, result, cve_rows)
    if severity in {"critical", "high"}:
        create_notification(case_id, f"Wazuh {severity} alert", severity, title)
    return {"status": "ok", "alert_id": alert_id, "case_id": case_id}


@app.get("/api/model/training-dataset")
def api_training_dataset(_: dict = Depends(_current_user)) -> dict[str, str]:
    return {"path": str(TRAINING_CSV), "status": "ready" if TRAINING_CSV.exists() else "missing"}


@app.get("/api/dashboard/wazuh-alerts", response_model=ExternalItemListResponse)
def api_wazuh_alerts(
    page: int = 1,
    page_size: int = 10,
    severity: str | None = None,
    _: dict = Depends(_current_user),
) -> ExternalItemListResponse:
    items, total = list_external_items("wazuh_alerts", page=page, page_size=min(max(page_size, 1), 100), severity=severity)
    return ExternalItemListResponse(items=items, total=total, page=page, page_size=min(max(page_size, 1), 100))


@app.post("/api/dashboard/misp/sync", response_model=ExternalItemListResponse)
def api_misp_sync(page_size: int = 10, _: dict = Depends(_current_user)) -> ExternalItemListResponse:
    sync_misp_from_settings()
    items, total = list_external_items("misp_events", page=1, page_size=min(max(page_size, 1), 100))
    return ExternalItemListResponse(items=items, total=total, page=1, page_size=min(max(page_size, 1), 100))


@app.get("/api/dashboard/misp/events", response_model=ExternalItemListResponse)
def api_misp_events(
    page: int = 1,
    page_size: int = 10,
    severity: str | None = None,
    _: dict = Depends(_current_user),
) -> ExternalItemListResponse:
    items, total = list_external_items("misp_events", page=page, page_size=min(max(page_size, 1), 100), severity=severity)
    return ExternalItemListResponse(items=items, total=total, page=page, page_size=min(max(page_size, 1), 100))


@app.post("/api/dashboard/cortex/sync", response_model=ExternalItemListResponse)
def api_cortex_sync(page_size: int = 10, _: dict = Depends(_current_user)) -> ExternalItemListResponse:
    sync_cortex_from_settings()
    items, total = list_external_items("cortex_jobs", page=1, page_size=min(max(page_size, 1), 100))
    return ExternalItemListResponse(items=items, total=total, page=1, page_size=min(max(page_size, 1), 100))


@app.get("/api/dashboard/cortex/jobs", response_model=ExternalItemListResponse)
def api_cortex_jobs(
    page: int = 1,
    page_size: int = 10,
    severity: str | None = None,
    _: dict = Depends(_current_user),
) -> ExternalItemListResponse:
    items, total = list_external_items("cortex_jobs", page=page, page_size=min(max(page_size, 1), 100), severity=severity)
    return ExternalItemListResponse(items=items, total=total, page=page, page_size=min(max(page_size, 1), 100))


@app.post("/api/dashboard/iris/sync", response_model=ExternalItemListResponse)
def api_iris_sync(page_size: int = 10, _: dict = Depends(_current_user)) -> ExternalItemListResponse:
    sync_iris_from_settings()
    items, total = list_iris_cases(page=1, page_size=min(max(page_size, 1), 100))
    return ExternalItemListResponse(items=items, total=total, page=1, page_size=min(max(page_size, 1), 100))


@app.get("/api/dashboard/iris/cases", response_model=ExternalItemListResponse)
def api_iris_cases(
    page: int = 1,
    page_size: int = 10,
    severity: str | None = None,
    _: dict = Depends(_current_user),
) -> ExternalItemListResponse:
    items, total = list_iris_cases(page=page, page_size=min(max(page_size, 1), 100), severity=severity)
    return ExternalItemListResponse(items=items, total=total, page=page, page_size=min(max(page_size, 1), 100))


@app.get("/api/dashboard/mitre", response_model=MitreTechniqueListResponse)
def api_mitre(
    page: int = 1,
    page_size: int = 10,
    search: str | None = None,
    _: dict = Depends(_current_user),
) -> MitreTechniqueListResponse:
    items, total = list_mitre(page=page, page_size=min(max(page_size, 1), 100), search=search)
    return MitreTechniqueListResponse(items=items, total=total, page=page, page_size=min(max(page_size, 1), 100))
