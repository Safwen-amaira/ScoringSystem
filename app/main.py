from __future__ import annotations
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ai import AIRecommendationService
from .cve import extract_cve_ids
from .db import dashboard_overview, ensure_cves, get_case, init_db, list_cases, list_cves, login, require_session, seed_demo_case, store_case, sync_recent_cves
from .emailer import send_recommendation_mail
from .ingestion import compute_pkis, extract_iocs, normalize_raw_request
from .models import CVEListResponse, DashboardCaseDetail, DashboardCaseListResponse, DashboardOverview, EmailContentResponse, LoginRequest, LoginResponse, RawIntelligenceRequest, RecommendationResponse, ScoreResponse, ScoringRequest
from .scoring import build_recommendation

app = FastAPI(title="Threat Recommendation Engine", version="0.1.0")
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
    sync_recent_cves()
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


def _build_full_result(request: ScoringRequest) -> RecommendationResponse:
    result = build_recommendation(request)
    summary, body, ai_generated, ai_provider = ai_service.enrich_recommendation(request, result)
    result.iocs = extract_iocs(request.model_dump())
    result.pkis = compute_pkis(request, result.iocs)

    result.summary = summary
    result.recommendation_body = body
    result.ai_generated = ai_generated
    result.ai_provider = ai_provider
    return result


def _normalize_raw(request: RawIntelligenceRequest) -> tuple[ScoringRequest, RecommendationResponse, list[dict]]:
    normalized_request, iocs, pkis = normalize_raw_request(request)
    result = _build_full_result(normalized_request)
    result.iocs = iocs
    result.pkis = pkis
    cve_rows = ensure_cves(extract_cve_ids(request.model_dump()))
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
    return store_case(
        raw_payload=raw_request.model_dump(),
        normalized_request=normalized_request,
        result=result,
        email_payload=email_payload,
        cve_ids=[item["cve_id"] for item in cve_rows],
        iris_case_name=raw_request.iris_case_name,
    )


@app.post("/api/auth/login", response_model=LoginResponse)
def auth_login(request: LoginRequest) -> LoginResponse:
    session = login(request.email, request.password)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return LoginResponse(**session)


@app.post("/api/score", response_model=ScoreResponse)
def score(request: ScoringRequest) -> ScoreResponse:
    result = _build_full_result(request)
    return ScoreResponse(
        score=result.score,
        decision=result.decision,
        allow_workflow_to_continue=result.allow_workflow_to_continue,
        summary=result.summary,
        ai_generated=result.ai_generated,
        ai_provider=result.ai_provider,
        breakdown=result.breakdown,
        evidence=result.evidence,
        iocs=result.iocs,
        pkis=result.pkis,
    )


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
    return ScoreResponse(
        score=result.score,
        decision=result.decision,
        allow_workflow_to_continue=result.allow_workflow_to_continue,
        summary=result.summary,
        ai_generated=result.ai_generated,
        ai_provider=result.ai_provider,
        breakdown=result.breakdown,
        evidence=result.evidence,
        iocs=result.iocs,
        pkis=result.pkis,
    )


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
    except Exception as exc:  # pragma: no cover - defensive surface for external SMTP issues
        raise HTTPException(status_code=502, detail=f"Email dispatch failed: {exc}") from exc

    return {
        "score": ScoreResponse(
            score=response.score,
            decision=response.decision,
            allow_workflow_to_continue=response.allow_workflow_to_continue,
            summary=response.summary,
            ai_generated=response.ai_generated,
            ai_provider=response.ai_provider,
            breakdown=response.breakdown,
            evidence=response.evidence,
            iocs=response.iocs,
            pkis=response.pkis,
        ).model_dump(),
        "email": email_payload.model_dump(),
        "email_sent": sent,
    }


@app.get("/api/dashboard/overview", response_model=DashboardOverview)
def api_dashboard_overview(_: dict = Depends(_current_user)) -> DashboardOverview:
    return dashboard_overview()


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
    items, total = list_cases(page=page, page_size=page_size, severity=severity, decision=decision, min_score=min_score, search=search)
    return DashboardCaseListResponse(items=items, total=total, page=page, page_size=page_size)


@app.get("/api/dashboard/cases/{case_id}", response_model=DashboardCaseDetail)
def api_dashboard_case(case_id: int, _: dict = Depends(_current_user)) -> DashboardCaseDetail:
    detail = get_case(case_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.get("/api/dashboard/cves", response_model=CVEListResponse)
def api_dashboard_cves(
    page: int = 1,
    page_size: int = 12,
    search: str | None = None,
    _: dict = Depends(_current_user),
) -> CVEListResponse:
    items, total = list_cves(page=page, page_size=page_size, search=search)
    return CVEListResponse(items=items, total=total, page=page, page_size=page_size)


@app.post("/api/dashboard/cases/ingest", response_model=DashboardCaseDetail)
def api_dashboard_ingest(request: RawIntelligenceRequest, _: dict = Depends(_current_user)) -> DashboardCaseDetail:
    normalized_request, result, cve_rows = _normalize_raw(request)
    case_id = _store_raw_case(request, normalized_request, result, cve_rows)
    detail = get_case(case_id)
    if not detail:
        raise HTTPException(status_code=500, detail="Stored case could not be loaded")
    return detail
