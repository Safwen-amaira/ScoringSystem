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
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        self.timeout = int(os.getenv("AI_TIMEOUT_SECONDS", "30"))
        self.chat_timeout = int(os.getenv("AI_CHAT_TIMEOUT_SECONDS", "20"))
        self.summary_prompt = (base_dir / "agents" / "security_summary.md").read_text(encoding="utf-8")
        self.email_prompt = (base_dir / "agents" / "email_html.md").read_text(encoding="utf-8")

    def apply_runtime_settings(self, base_url: str | None = None, model: str | None = None) -> None:
        if base_url:
            self.ollama_url = base_url.strip()
        if model:
            self.ollama_model = model.strip()

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
            "You are H-Brain, the cybersecurity assistant developed by Hanicar Security (https://hanicar.tn). "
            "You are an expert in SOC operations, incident response, Wazuh, MISP, Cortex, IRIS, and MITRE ATT&CK. "
            "ALWAYS think before answering. Show your reasoning process inside <thought> tags. "
            "After the thinking process, provide a concise, operational, and practical final response. "
            "If asked for the website, answer with https://hanicar.tn. "
            "Be technically sharp, keep the final response brief and actionable."
        )
        recent_messages = messages[-10:]
        errors: list[str] = []
        for base_url in self._candidate_base_urls():
            try:
                model_candidates = self._candidate_models(base_url)
            except Exception as exc:
                errors.append(f"Connectivity at {base_url}: {exc}")
                continue

            if not model_candidates:
                errors.append(f"No models found at {base_url}")
                continue

            for model_name in model_candidates:
                try:
                    reply = self._ollama_chat(system_prompt, recent_messages, base_url=base_url, model=model_name)
                    if reply:
                        self.ollama_url = base_url
                        self.ollama_model = model_name
                        return reply
                except Exception as exc:
                    errors.append(f"Model {model_name} @ {base_url}: {exc}")
                    continue

        if messages:
            return self._fallback_chat_response(messages[-1]["content"], errors=errors)
        return (
            "H-Brain here. I am the cybersecurity assistant developed by Hanicar Security. "
            "Ask me anything about your SOC telemetry. (Reasoning enabled)."
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

    def _ollama_chat(self, system_prompt: str, messages: list[dict[str, str]], base_url: str | None = None, model: str | None = None) -> str:
        endpoint = f"{(base_url or self.ollama_url).rstrip('/')}/api/chat"
        payload = {
            "model": model or self.ollama_model,
            "stream": False,
            "messages": [{"role": "system", "content": system_prompt}, *messages],
            "keep_alive": "10m",
            "options": {
                "temperature": 0.4,
                "num_predict": 1024,
                "top_p": 0.9,
            },
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        http_request = request.Request(endpoint, data=body, headers=headers, method="POST")

        try:
            with request.urlopen(http_request, timeout=self.chat_timeout) as response:
                raw = json.loads(response.read().decode("utf-8"))
                return raw.get("message", {}).get("content", "").strip()
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP error {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama connection failed: {exc.reason}") from exc

    def _candidate_base_urls(self) -> list[str]:
        candidates = [
            self.ollama_url,
            "http://ollama:11434",
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://host.docker.internal:11434",
            "http://172.17.0.1:11434",
            "http://192.168.1.1:11434",
        ]
        unique: list[str] = []
        for candidate in candidates:
            if candidate and candidate not in unique:
                unique.append(candidate)
        return unique

    def _candidate_models(self, base_url: str) -> list[str]:
        models = [self.ollama_model]
        try:
            available = self._list_models(base_url)
        except Exception:
            available = []
        for model_name in available:
            if model_name not in models:
                models.append(model_name)
        return models

    def _list_models(self, base_url: str) -> list[str]:
        endpoint = f"{base_url.rstrip('/')}/api/tags"
        http_request = request.Request(endpoint, headers={"Content-Type": "application/json"}, method="GET")
        try:
            with request.urlopen(http_request, timeout=min(self.chat_timeout, 30)) as response:
                raw = json.loads(response.read().decode("utf-8"))
                return [item.get("name") for item in raw.get("models", []) if item.get("name")]
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama tags HTTP error {exc.code}: {details}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Ollama tags connection failed: {exc.reason}") from exc

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

    def _fallback_chat_response(self, user_message: str, errors: list[str] | None = None) -> str:
        text = user_message.strip().lower()
        if not text:
            return "H-Brain here. Share the alert, IOC, case context, or investigation goal, and I will help with triage, enrichment, scoring, containment, and response actions."

        report = ""
        if errors:
            report = (
                "\n\n--- H-Brain Connectivity Report ---\n"
                "I attempted to reach your Ollama instance but encountered these issues:\n"
                + "\n".join(f"• {e}" for e in errors[:4])
                + "\nEnsure Ollama is running and accessible (check http://YOUR_OLLAMA_IP:11434/api/tags)."
            )

        if any(token in text for token in ["who developed", "who made", "who are you", "developer", "developed you", "made you"]):
            return f"H-Brain was developed by Hanicar Security, the Tunisian cybersecurity company (https://hanicar.tn).{report}"
        if any(token in text for token in ["what is cve", "what are cves", "cves mean", "cve mean"]):
            return f"CVE (Common Vulnerabilities and Exposures) is a public identifier for a known security flaw. In SOC work, CVEs help us assess exposure and prioritize patching.{report}"
        if "mitre" in text or "attack" in text:
            return f"MITRE ATT&CK is a behavior-based adversary behavior model. We use it to explain what stage of an intrusion an incident represents.{report}"
        if "ioc" in text or "indicator" in text:
            return f"Indicators of Compromise (IOCs) are digital artifacts like malicious IPs, hashes, or domains used to hunt and block threats.{report}"
        if "wazuh" in text:
            return f"Wazuh is our detection engine that translates raw telemetry into high-confidence security alerts.{report}"
        if "misp" in text:
            return f"MISP is our threat intelligence repository used for indicator enrichment and campaign matching.{report}"
        if "cortex" in text:
            return f"Cortex is our analysis engine that provides verdicts on artifacts like URLs or files.{report}"
        if "iris" in text:
            return f"IRIS is our case management platform where investigations are documented and coordinated.{report}"
        if any(token in text for token in ["score", "scoring", "how score", "risk score"]):
            return f"H-Brain uses a hybrid banking scoring model: deep SOC rules + machine learning (RandomForest) trained on banking CTI scenarios.{report}"
        if any(token in text for token in ["contain", "containment", "response", "incident response"]):
            return f"For IR, start with isolation and evidence preservation. Map to MITRE ATT&CK to understand next steps.{report}"

        return (
            "H-Brain here. I couldn't reach your LLM engine, so I am providing a limited response.\n"
            "I can help with CTI, incident response, Wazuh, MISP, Cortex, IRIS, MITRE ATT&CK, scoring, containment, and banking SOC workflows. "
            f"Share the alert, question, or case details and I will respond with operational guidance.{report}"
        )
