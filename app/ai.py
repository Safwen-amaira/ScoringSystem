from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any
from urllib import error, request

from .models import RecommendationResponse, ScoringRequest


class AIRecommendationService:
    def __init__(self) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        self.provider_name = os.getenv("AI_PROVIDER", "file-agent")
        self.ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.timeout = int(os.getenv("AI_TIMEOUT_SECONDS", "30"))
        self.summary_prompt = (base_dir / "agents" / "security_summary.md").read_text(encoding="utf-8")
        self.email_prompt = (base_dir / "agents" / "email_html.md").read_text(encoding="utf-8")

    def enrich_recommendation(self, scoring_request: ScoringRequest, draft: RecommendationResponse) -> tuple[str, str, bool, str]:
        if self.provider_name == "ollama":
            try:
                return self._ollama_recommendation(scoring_request, draft)
            except Exception:
                pass
        return draft.summary, draft.recommendation_body, False, "file-agent"

    def render_email_html(self, scoring_request: ScoringRequest, recommendation: RecommendationResponse) -> tuple[str, bool, str]:
        if self.provider_name == "ollama":
            try:
                return self._ollama_email_html(scoring_request, recommendation)
            except Exception:
                pass
        return self._fallback_email_html(scoring_request, recommendation), False, "file-agent"

    def extract_score_features(self, scoring_request: ScoringRequest) -> dict[str, Any]:
        if self.provider_name == "ollama":
            try:
                return self._ollama_score_features(scoring_request)
            except Exception:
                pass
        return self._fallback_score_features(scoring_request)

    def chat(self, messages: list[dict[str, str]]) -> str:
        system_prompt = (
            "You are H-Brain, the UI that was developed by Hanicar Security, "
            "the Tunisian cybersecurity company. If asked for the website, answer with "
            "https://hanicar.tn. You are technically strong in cybersecurity, CTI, SOC "
            "operations, incident response, Wazuh, MISP, Cortex, IRIS, MITRE ATT&CK, "
            "banking security, ISO 27001/27002, PCI DSS, threat hunting, malware triage, "
            "and containment. Be concise, operational, and practical."
        )
        if self.provider_name == "ollama":
            try:
                return self._ollama_chat(system_prompt, messages)
            except Exception:
                pass
        if messages:
            return (
                "H-Brain here. I am the cybersecurity assistant developed by Hanicar Security. "
                "Ollama is unavailable right now, but I can still help you reason through "
                "incident triage, enrichment, scoring, and containment."
            )
        return (
            "H-Brain here. I am the cybersecurity assistant developed by Hanicar Security, "
            "the Tunisian cybersecurity company. Ask me about incident response, CTI, "
            "Wazuh, MISP, Cortex, IRIS, MITRE ATT&CK, or banking security operations."
        )

    def _ollama_recommendation(self, scoring_request: ScoringRequest, draft: RecommendationResponse) -> tuple[str, str, bool, str]:
        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "recommendation_body": {"type": "string"},
            },
            "required": ["summary", "recommendation_body"],
            "additionalProperties": False,
        }
        prompt = json.dumps(
            {
                "agent_prompt": self.summary_prompt,
                "case": scoring_request.model_dump(),
                "draft": draft.model_dump(),
            }
        )
        result = self._call_ollama(prompt, schema)
        return result["summary"], result["recommendation_body"], True, "ollama"

    def _ollama_email_html(self, scoring_request: ScoringRequest, recommendation: RecommendationResponse) -> tuple[str, bool, str]:
        schema = {
            "type": "object",
            "properties": {
                "html": {"type": "string"},
            },
            "required": ["html"],
            "additionalProperties": False,
        }
        prompt = json.dumps(
            {
                "agent_prompt": self.email_prompt,
                "case": scoring_request.model_dump(),
                "recommendation": recommendation.model_dump(),
            }
        )
        result = self._call_ollama(prompt, schema)
        return result["html"], True, "ollama"

    def _ollama_score_features(self, scoring_request: ScoringRequest) -> dict[str, Any]:
        schema = {
            "type": "object",
            "properties": {
                "confidence": {"type": "number"},
                "banking_context": {"type": "boolean"},
                "customer_impact": {"type": "boolean"},
                "external_exposure": {"type": "boolean"},
                "credential_risk": {"type": "boolean"},
                "endpoint_criticality": {"type": "number"},
                "alert_volume": {"type": "number"},
            },
            "required": ["confidence", "banking_context", "customer_impact", "external_exposure", "credential_risk", "endpoint_criticality", "alert_volume"],
            "additionalProperties": False,
        }
        prompt = json.dumps(
            {
                "instruction": "Extract only structured scoring hints for a banking CTI scoring model.",
                "case": scoring_request.model_dump(),
            }
        )
        return self._call_ollama(prompt, schema)

    def _ollama_chat(self, system_prompt: str, messages: list[dict[str, str]]) -> str:
        endpoint = f"{self.ollama_url.rstrip('/')}/api/chat"
        payload = {
            "model": self.ollama_model,
            "stream": False,
            "messages": [{"role": "system", "content": system_prompt}, *messages],
            "options": {"temperature": 0.2},
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        http_request = request.Request(endpoint, data=body, headers=headers, method="POST")

        try:
            with request.urlopen(http_request, timeout=self.timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
                return raw.get("message", {}).get("content", "").strip()
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP error {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama connection failed: {exc.reason}") from exc

    def _call_ollama(self, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        endpoint = f"{self.ollama_url.rstrip('/')}/api/generate"
        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0.2},
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        http_request = request.Request(endpoint, data=body, headers=headers, method="POST")

        try:
            with request.urlopen(http_request, timeout=self.timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
                return json.loads(raw["response"])
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP error {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama connection failed: {exc.reason}") from exc

    def _fallback_email_html(self, scoring_request: ScoringRequest, recommendation: RecommendationResponse) -> str:
        evidence_items = "".join(
            f"<li><strong>{html.escape(item.source)}</strong>: {html.escape(item.title)}"
            f" ({html.escape(item.severity or 'n/a')})</li>"
            for item in recommendation.evidence
        )
        actions = self._extract_actions(recommendation.recommendation_body)
        action_items = "".join(f"<li>{html.escape(action)}</li>" for action in actions)
        return f"""
<html>
  <body style="font-family:Arial,sans-serif;color:#12202f;background:#f4f7fb;padding:24px;">
    <div style="max-width:760px;margin:0 auto;background:#ffffff;border-radius:16px;padding:24px;border:1px solid #dbe4ee;">
      <p style="font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:#2f7d6b;">Security Recommendation</p>
      <h1 style="margin:0 0 16px;font-size:28px;color:#0f2740;">{html.escape(scoring_request.title)}</h1>
      <p><strong>Asset:</strong> {html.escape(scoring_request.asset_name)}</p>
      <p><strong>Workflow ID:</strong> {html.escape(scoring_request.workflow_id or 'not supplied')}</p>
      <p><strong>Threat score:</strong> {recommendation.score}/100</p>
      <p><strong>Decision:</strong> {html.escape(recommendation.decision.upper())}</p>
      <p>{html.escape(recommendation.summary)}</p>
      <h2 style="font-size:20px;color:#0f2740;">Evidence</h2>
      <ul>{evidence_items or '<li>No evidence items were supplied.</li>'}</ul>
      <h2 style="font-size:20px;color:#0f2740;">Recommended Actions</h2>
      <ol>{action_items}</ol>
    </div>
  </body>
</html>
""".strip()

    def _extract_actions(self, recommendation_body: str) -> list[str]:
        actions: list[str] = []
        for line in recommendation_body.splitlines():
            stripped = line.strip()
            number, separator, remainder = stripped.partition(". ")
            if number.isdigit() and separator:
                actions.append(stripped.split(". ", 1)[1])
        if not actions:
            actions.append("Review the recommendation body for operational next steps.")
        return actions

    def _fallback_score_features(self, scoring_request: ScoringRequest) -> dict[str, Any]:
        text = " ".join(
            filter(
                None,
                [
                    scoring_request.title,
                    scoring_request.asset_name,
                    scoring_request.workflow_id or "",
                    scoring_request.notes or "",
                    scoring_request.misp_enrichment.event_info if scoring_request.misp_enrichment else "",
                    scoring_request.cortex_analysis.summary if scoring_request.cortex_analysis and scoring_request.cortex_analysis.summary else "",
                ],
            )
        ).lower()
        return {
            "confidence": 0.74,
            "banking_context": any(token in text for token in ["bank", "payment", "pci", "swift", "card"]),
            "customer_impact": any(token in text for token in ["customer", "account", "identity"]),
            "external_exposure": any(token in text for token in ["external", "internet", "public", "edge"]),
            "credential_risk": any(token in text for token in ["credential", "password", "authentication", "login"]),
            "endpoint_criticality": 5 if any(token in text for token in ["swift", "payment", "core", "issuer", "merchant"]) else 3,
            "alert_volume": 6 if any(token in text for token in ["multiple", "burst", "campaign"]) else 3,
        }
