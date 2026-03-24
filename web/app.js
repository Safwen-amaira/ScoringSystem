const form = document.getElementById("score-form");
const decisionEl = document.getElementById("decision");
const scorePillEl = document.getElementById("score-pill");
const summaryEl = document.getElementById("summary");
const breakdownEl = document.getElementById("breakdown");
const mailBodyEl = document.getElementById("mail-body");
const providerEl = document.getElementById("provider");
const iocBodyEl = document.getElementById("ioc-body");
const pkiBodyEl = document.getElementById("pki-body");

function splitCsv(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildPayload(formData) {
  return {
    title: formData.get("title"),
    asset_name: formData.get("asset_name"),
    workflow_id: formData.get("workflow_id") || null,
    analyst_email: formData.get("analyst_email") || null,
    notes: formData.get("notes") || null,
    wazuh_alert: {
      rule_level: Number(formData.get("wazuh_rule_level") || 0),
      rule_description: formData.get("wazuh_rule_description"),
      groups: splitCsv(formData.get("wazuh_groups") || ""),
      source_ip: formData.get("wazuh_source_ip") || null,
    },
    misp_enrichment: {
      threat_level_id: Number(formData.get("misp_threat_level_id") || 4),
      event_info: formData.get("misp_event_info"),
      tags: splitCsv(formData.get("misp_tags") || ""),
      attribute_count: Number(formData.get("misp_attribute_count") || 0),
      known_bad_indicator: formData.get("misp_known_bad_indicator") === "on",
    },
    cortex_analysis: {
      analyzer_name: formData.get("cortex_analyzer_name"),
      verdict: formData.get("cortex_verdict"),
      taxonomies: splitCsv(formData.get("cortex_taxonomies") || ""),
      artifacts_flagged: Number(formData.get("cortex_artifacts_flagged") || 0),
      summary: formData.get("cortex_summary") || null,
    },
  };
}

function parseOptionalJson(rawText) {
  const text = (rawText || "").trim();
  if (!text) {
    return null;
  }
  return JSON.parse(text);
}

function buildRawPayload(formData) {
  return {
    title: formData.get("title") || null,
    asset_name: formData.get("asset_name") || null,
    workflow_id: formData.get("workflow_id") || null,
    analyst_email: formData.get("analyst_email") || null,
    notes: formData.get("notes") || null,
    wazuh_alert: parseOptionalJson(formData.get("raw_wazuh_json")),
    misp_event: parseOptionalJson(formData.get("raw_misp_json")),
    cortex_analysis: parseOptionalJson(formData.get("raw_cortex_json")),
  };
}

function hasRawInput(formData) {
  return ["raw_wazuh_json", "raw_misp_json", "raw_cortex_json"].some((name) => (formData.get(name) || "").trim().length > 0);
}

function renderResult(result, emailResult) {
  decisionEl.textContent = result.decision.toUpperCase();
  scorePillEl.textContent = result.score;
  summaryEl.textContent = result.summary;
  providerEl.textContent = `Recommendation engine: ${result.ai_provider}${result.ai_generated ? " (AI)" : " (fallback)"}`;

  const tone =
    result.decision === "stop" ? "var(--danger)" : result.decision === "review" ? "var(--warn)" : "var(--accent)";
  scorePillEl.style.boxShadow = `0 0 0 6px color-mix(in srgb, ${tone} 16%, transparent)`;
  scorePillEl.style.color = tone;

  breakdownEl.innerHTML = "";
  result.breakdown.forEach((item) => {
    const card = document.createElement("article");
    card.className = "breakdown-card";
    card.innerHTML = `<strong>${item.category}</strong><p>${item.score}/max contribution</p><p>${item.rationale}</p>`;
    breakdownEl.appendChild(card);
  });

  iocBodyEl.textContent = JSON.stringify(result.iocs || [], null, 2);
  pkiBodyEl.textContent = JSON.stringify(result.pkis || [], null, 2);
  mailBodyEl.textContent = emailResult.html;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  decisionEl.textContent = "Scoring...";
  breakdownEl.innerHTML = "";
  mailBodyEl.textContent = "";
  iocBodyEl.textContent = "";
  pkiBodyEl.textContent = "";

  const formData = new FormData(form);
  const rawMode = hasRawInput(formData);
  let response;

  try {
    const payload = rawMode ? buildRawPayload(formData) : buildPayload(formData);
    response = await fetch(rawMode ? "/api/recommendation" : "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    decisionEl.textContent = "Error";
    summaryEl.textContent = error.message;
    return;
  }

  if (!response.ok) {
    const text = await response.text();
    decisionEl.textContent = "Error";
    summaryEl.textContent = text;
    return;
  }

  const result = await response.json();
  renderResult(result, { html: result.recommendation_body });
});
