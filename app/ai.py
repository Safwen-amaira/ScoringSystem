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
        self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
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
            "You are H-Brain, a elite cybersecurity engineering assistant developed by Hanicar Security (https://hanicar.tn). "
            "Expertise: SOC operations, incident response, Wazuh, MISP, Cortex, IRIS, and MITRE ATT&CK. "
            "MANDATORY: Always think before answering. Show your reasoning process inside <thought> tags. "
            "Your thought process should analyze the query, identify relevant SOC telemetry, and plan a sharp, technical response. "
            "Provide a final response that is concise, operational, and practical. "
            "Use markdown, bold key terms, and maintain a premium, professional tone. "
            "If asked about Hanicar Security, refer to https://hanicar.tn. "
            "Be technically sharp, avoid generic filler, and keep the final response brief and actionable."
        )
        recent_messages = messages[-10:]
        # Try current known working url/model first to avoid latency
        try:
            reply = self._ollama_chat(system_prompt, recent_messages, base_url=self.ollama_url, model=self.ollama_model)
            if reply:
                return reply
        except Exception:
            pass

        for base_url in self._candidate_base_urls():
            if base_url == self.ollama_url:
                continue
            model_candidates = self._candidate_models(base_url)
            if not model_candidates:
                continue
            for model_name in model_candidates:
                try:
                    reply = self._ollama_chat(system_prompt, recent_messages, base_url=base_url, model=model_name)
                    if reply:
                        self.ollama_url = base_url
                        self.ollama_model = model_name
                        return reply
                except Exception:
                    continue
        if messages:
            return self._fallback_chat_response(messages[-1]["content"])
        return (
            "H-Brain here. I am the cybersecurity assistant developed by Hanicar Security. "
            "I've been upgraded to be faster and more thoughtful. Ask me anything about your SOC telemetry."
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
            "http://127.0.0.1:11434",
            "http://localhost:11434",
            "http://host.docker.internal:11434",
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
            with request.urlopen(http_request, timeout=min(self.chat_timeout, 8)) as response:
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
        
        # Build compliance recommendations section
        compliance_html = ""
        compliance_rec = getattr(recommendation, 'compliance_recommendation', None)
        if compliance_rec and compliance_rec.get("threat_category"):
            cf = compliance_rec.get("compliance_framework", {})
            iso_count = len(cf.get("iso_27001_controls", []))
            pci_count = len(cf.get("pci_dss_controls", []))
            mitre_count = len(cf.get("mitre_attck_mitigations", []))
            immediate = compliance_rec.get("immediate_actions", [])
            immediate_items = "".join(f"<li>{html.escape(action)}</li>" for action in immediate if action)
            
            compliance_html = f"""
      <div style="margin-top:24px;padding:16px;background:#f8fafc;border-radius:12px;border:1px solid #e2e8f0;">
        <h2 style="font-size:18px;color:#0f2740;margin:0 0 12px;">Compliance & Recommendations</h2>
        <p><strong>Threat Category:</strong> {html.escape(compliance_rec.get("threat_category", "unknown").replace("_", " "))}</p>
        <p><strong>Severity:</strong> <span style="background:{'#dc2626' if compliance_rec.get('severity') == 'critical' else '#ea580c' if compliance_rec.get('severity') == 'high' else '#ca8a04' if compliance_rec.get('severity') == 'medium' else '#16a34a'};color:#fff;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:bold;">{html.escape(compliance_rec.get("severity", "low").upper())}</span></p>
        <p><strong>Framework Coverage:</strong> {iso_count} ISO 27001 controls, {pci_count} PCI DSS controls, {mitre_count} MITRE ATT&CK mitigations</p>
        {f'<h3 style="font-size:16px;color:#dc2626;margin:12px 0 8px;">Immediate Actions</h3><ol>{immediate_items}</ol>' if immediate_items else ''}
      </div>
"""
        
        return f"""
<html>
  <body style="font-family:Arial,sans-serif;color:#12202f;background:#f4f7fb;padding:24px;">
    <div style="max-width:760px;margin:0 auto;background:#ffffff;border-radius:16px;padding:24px;border:1px solid #dbe4ee;">
      <p style="font-size:12px;letter-spacing:1.5px;text-transform:uppercase;color:#2f7d6b;">H-Brain Security Recommendation</p>
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
      {compliance_html}
      <p style="margin-top:24px;padding-top:16px;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;">Generated by H-Brain | Hanicar Security | <a href="https://hanicar.tn" style="color:#2f7d6b;">https://hanicar.tn</a></p>
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

    def _fallback_chat_response(self, user_message: str) -> str:
        text = user_message.strip().lower()
        if not text:
            return "H-Brain here. Share the alert, IOC, case context, or investigation goal, and I will help with triage, enrichment, scoring, containment, and response actions."
        
        # Improved Fallback with better context matching
        if any(token in text for token in ["who developed", "who made", "who are you", "developer", "developed you", "made you"]):
            return "H-Brain was developed by Hanicar Security, the Tunisian cybersecurity company. If you need the website, it is https://hanicar.tn."
        
        if "cve" in text and any(token in text for token in ["what is", "mean", "define", "list"]):
            return "CVE means **Common Vulnerabilities and Exposures**. It is a public identifier for a known security flaw (e.g., CVE-2024-3400). In SOC work, we use CVEs to map alerts to known vulnerabilities and prioritize patching."
        
        if "ddos" in text and any(token in text for token in ["stop", "prevent", "mitigate", "contain"]):
            return (
                "To mitigate a **DDoS attack**: \n"
                "1. **Identify type**: Volumetric, Protocol, or Application-layer.\n"
                "2. **Enable Mitigation**: Route traffic through a scrubbing center or WAF.\n"
                "3. **Rate Limiting**: Apply rate-limiting at your edge firewalls/load balancers.\n"
                "4. **IP Blocking**: Block known malicious source IPs in real-time."
            )

        if "malware" in text and any(token in text for token in ["contain", "stop", "handle", "mal"]):
            return (
                "**Malware Containment Checklist:**\n"
                "1. **Isolate**: Segment the affected host from the network immediately.\n"
                "2. **Process Kill**: Use EDR or Wazuh to terminate the malicious process.\n"
                "3. **Block IOCs**: Null-route C2 IPs and domains in your firewall.\n"
                "4. **Preserve Evidence**: Take a memory dump and disk image for forensics."
            )

        if "mitre" in text or "attack" in text:
            if "stop" in text or "contain" in text:
                 return "To contain an attack mapped to **MITRE ATT&CK**, identify the technique (e.g., T1059) and apply the specific Mitigation (M1041, etc.) defined in the framework."
            return "**MITRE ATT&CK** is a globally accessible knowledge base of adversary tactics and techniques. It helps analysts understand the 'how' and 'why' of an intrusion stage (Initial Access, Persistence, Exfiltration, etc.)."
        
        if "ioc" in text or "indicator" in text:
            return "An **IOC (Indicator of Compromise)** is evidence that a network has been breached (e.g., hashes, malicious IPs, strings). We use MISP and Cortex to enrich alerts with IOC context."
        
        if "wazuh" in text:
            return "**Wazuh** is your HIDS/SIEM layer. It provides endpoint security monitoring and threat detection telemetry used by H-Brain for incident scoring."
        
        if "misp" in text:
            return "**MISP** is your threat intelligence platform. It shares events and attributes that H-Brain uses to identify known-bad infrastructure in your alerts."
        
        if "cortex" in text:
            return "**Cortex** provides automated analysis (analyzers/responders). It confirms if an artifact is malicious through external sandboxes or intelligence."
        
        if "iris" in text:
            return "**IRIS** is your case management system. H-Brain links incidents to IRIS cases to track investigative tasks and legal chain of custody."
        
        if any(token in text for token in ["score", "scoring", "how score", "risk score"]):
            return "H-Brain uses a **Hybrid Banking Scoring Model**: deterministic SOC logic (Wazuh/MISP) combined with ML refinement to determine if an incident requires immediate containment or review."

        return (
            "**H-Brain Notice**: The primary AI engine is currently under load or unreachable. \n\n"
            "I can still assist with triage, incident response, and SOC guidelines. "
            "Please share specific IOCs (IP, domain, hash) or Alert IDs for operational context."
        )
