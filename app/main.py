from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ai import AIRecommendationService
from .emailer import send_recommendation_mail
from .ingestion import compute_pkis, extract_iocs, normalize_raw_request
from .models import EmailContentResponse, RawIntelligenceRequest, RecommendationResponse, ScoreResponse, ScoringRequest
from .scoring import build_recommendation

app = FastAPI(title="Threat Recommendation Engine", version="0.1.0")
ai_service = AIRecommendationService()

static_dir = Path(__file__).resolve().parent.parent / "web"
app.mount("/assets", StaticFiles(directory=static_dir), name="assets")


@app.get("/")
def home() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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


def _normalize_raw(request: RawIntelligenceRequest) -> tuple[ScoringRequest, RecommendationResponse]:
    normalized_request, iocs, pkis = normalize_raw_request(request)
    result = _build_full_result(normalized_request)
    result.iocs = iocs
    result.pkis = pkis
    return normalized_request, result


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
    html_body, html_ai_generated, html_ai_provider = ai_service.render_email_html(request, result)
    return EmailContentResponse(
        subject=result.recommendation_subject,
        html=html_body,
        text=result.recommendation_body,
        ai_generated=html_ai_generated,
        ai_provider=html_ai_provider,
    )


@app.post("/api/analyze", response_model=RecommendationResponse)
def analyze(request: ScoringRequest) -> RecommendationResponse:
    return _build_full_result(request)


@app.post("/api/score/raw", response_model=ScoreResponse)
def score_raw(request: RawIntelligenceRequest) -> ScoreResponse:
    _, result = _normalize_raw(request)
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
    _, result = _normalize_raw(request)
    return result


@app.post("/api/recommendation/email", response_model=EmailContentResponse)
def recommendation_email(request: RawIntelligenceRequest) -> EmailContentResponse:
    normalized_request, result = _normalize_raw(request)
    html_body, html_ai_generated, html_ai_provider = ai_service.render_email_html(normalized_request, result)
    return EmailContentResponse(
        subject=result.recommendation_subject,
        html=html_body,
        text=result.recommendation_body,
        ai_generated=html_ai_generated,
        ai_provider=html_ai_provider,
    )


@app.post("/api/score-and-email")
def score_and_email(request: ScoringRequest) -> dict:
    response = _build_full_result(request)
    html_body, html_ai_generated, html_ai_provider = ai_service.render_email_html(request, response)
    try:
        sent = send_recommendation_mail(
            request,
            response.recommendation_subject,
            response.recommendation_body,
            html_body,
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
        "email": EmailContentResponse(
            subject=response.recommendation_subject,
            html=html_body,
            text=response.recommendation_body,
            ai_generated=html_ai_generated,
            ai_provider=html_ai_provider,
        ).model_dump(),
        "email_sent": sent,
    }
