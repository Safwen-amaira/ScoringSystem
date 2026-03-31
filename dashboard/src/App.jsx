import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
const DEFAULT_EMAIL = "admin@hanicar.tn";
const DEFAULT_PASSWORD = "bornasroot";

function api(path, token, options = {}) {
  return fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  }).then(async (response) => {
    if (!response.ok) {
      throw new Error(await response.text());
    }
    return response.json();
  });
}

function parseJson(value) {
  const trimmed = value.trim();
  return trimmed ? JSON.parse(trimmed) : null;
}

function severityTone(value) {
  return `severity-${value || "low"}`;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function App() {
  const [token, setToken] = useState(localStorage.getItem("hanicar_dashboard_token") || "");
  const [userEmail, setUserEmail] = useState(localStorage.getItem("hanicar_dashboard_user") || "");
  const [loginError, setLoginError] = useState("");
  const [overview, setOverview] = useState(null);
  const [cases, setCases] = useState([]);
  const [caseTotal, setCaseTotal] = useState(0);
  const [cves, setCves] = useState([]);
  const [cvePage, setCvePage] = useState(1);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({ severity: "", decision: "", minScore: "", search: "" });
  const [formState, setFormState] = useState({
    title: "Hanicar perimeter breach review",
    iris_case_name: "IRIS-HANICAR-2026-042",
    asset_name: "edge-fw-01",
    workflow_id: "wf-hanicar-react-001",
    wazuh_alert: '{\n  "rule": {"level": 14, "description": "Attempted exploit detected for CVE-2024-3400"},\n  "agent": {"name": "edge-fw-01"},\n  "data": {"srcip": "198.51.100.77"}\n}',
    misp_event: '{\n  "Event": {"info": "Campaign infrastructure referencing CVE-2024-3400", "threat_level_id": "1", "Attribute": [{"value": "malicious.hanicar-demo.net"}]}\n}',
    cortex_analysis: '{\n  "analyzerName": "VirusTotal",\n  "summary": {"taxonomies": [{"namespace": "VT", "predicate": "malicious", "value": "high"}]}\n}',
    notes: "Escalate if critical CVE overlap is confirmed against perimeter equipment.",
  });

  const stats = useMemo(() => {
    if (!overview) {
      return [];
    }
    return [
      { label: "Total Cases", value: overview.total_cases },
      { label: "Critical Cases", value: overview.critical_cases },
      { label: "Average Score", value: overview.average_score },
      { label: "CVE Matches", value: overview.cve_matches },
    ];
  }, [overview]);

  useEffect(() => {
    if (!token) {
      return;
    }
    bootstrap(token).catch((error) => {
      setLoginError(error.message);
      logout();
    });
  }, [token, cvePage]); // eslint-disable-line react-hooks/exhaustive-deps

  async function bootstrap(activeToken = token) {
    const query = new URLSearchParams({ page: "1", page_size: "12" });
    if (filters.severity) query.set("severity", filters.severity);
    if (filters.decision) query.set("decision", filters.decision);
    if (filters.minScore) query.set("min_score", filters.minScore);
    if (filters.search) query.set("search", filters.search);

    const [overviewPayload, casesPayload, cvesPayload] = await Promise.all([
      api("/api/dashboard/overview", activeToken),
      api(`/api/dashboard/cases?${query.toString()}`, activeToken),
      api(`/api/dashboard/cves?page=${cvePage}&page_size=8`, activeToken),
    ]);

    setOverview(overviewPayload);
    setCases(casesPayload.items);
    setCaseTotal(casesPayload.total);
    setCves(cvesPayload.items);
  }

  async function handleLogin(event) {
    event.preventDefault();
    setLoginError("");
    try {
      const payload = await api("/api/auth/login", "", {
        method: "POST",
        body: JSON.stringify({ email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD }),
      });
      localStorage.setItem("hanicar_dashboard_token", payload.token);
      localStorage.setItem("hanicar_dashboard_user", payload.email);
      setUserEmail(payload.email);
      setToken(payload.token);
    } catch (error) {
      setLoginError(error.message);
    }
  }

  function logout() {
    localStorage.removeItem("hanicar_dashboard_token");
    localStorage.removeItem("hanicar_dashboard_user");
    setToken("");
    setUserEmail("");
    setOverview(null);
    setCases([]);
    setSelectedCase(null);
  }

  async function openCase(caseId) {
    const payload = await api(`/api/dashboard/cases/${caseId}`, token);
    setSelectedCase(payload);
  }

  async function applyFilters() {
    await bootstrap();
  }

  async function ingestCase(event) {
    event.preventDefault();
    setLoading(true);
    try {
      const payload = await api("/api/dashboard/cases/ingest", token, {
        method: "POST",
        body: JSON.stringify({
          title: formState.title,
          iris_case_name: formState.iris_case_name,
          asset_name: formState.asset_name,
          workflow_id: formState.workflow_id,
          wazuh_alert: parseJson(formState.wazuh_alert),
          misp_event: parseJson(formState.misp_event),
          cortex_analysis: parseJson(formState.cortex_analysis),
          notes: formState.notes,
        }),
      });
      await bootstrap();
      setSelectedCase(payload);
    } catch (error) {
      window.alert(`Ingestion failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <p className="eyebrow">Hanicar Security</p>
          <h1>CTI Dashboard</h1>
          <p className="lede">Gold-themed live threat intelligence workspace with case correlation, CVE matching, and analyst-grade visibility.</p>
          <form onSubmit={handleLogin}>
            <div className="input-lock">
              <label>Email</label>
              <input value={DEFAULT_EMAIL} readOnly />
            </div>
            <div className="input-lock">
              <label>Password</label>
              <input value={DEFAULT_PASSWORD} readOnly type="password" />
            </div>
            <button type="submit">Enter Hanicar Console</button>
          </form>
          {loginError ? <p className="error-text">{loginError}</p> : null}
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="monogram">HS</div>
          <div>
            <p className="eyebrow">Hanicar Security</p>
            <h2>CTI Dashboard</h2>
          </div>
        </div>
        <div className="sidebar-panel">
          <p className="eyebrow">Session</p>
          <h3>{userEmail || "admin@hanicar.tn"}</h3>
          <button className="ghost-button" onClick={logout} type="button">
            Logout
          </button>
        </div>
        <div className="sidebar-panel">
          <p className="eyebrow">Latest Alerts</p>
          <div className="sidebar-list">
            {cases.map((item) => (
              <button key={item.id} className={`sidebar-case ${severityTone(item.severity)}`} onClick={() => openCase(item.id)} type="button">
                <span>{item.case_name}</span>
                <small>{item.score} | {item.decision.toUpperCase()}</small>
              </button>
            ))}
          </div>
        </div>
      </aside>

      <main className="content">
        <header className="hero">
          <div>
            <p className="eyebrow">Operational Intelligence</p>
            <h1>Clear CTI workflows with gold-grade signal correlation</h1>
            <p className="lede">Use the dashboard for incidents, CVE overlap, raw telemetry review, and analyst recommendations while the original UI remains available on port 8000.</p>
          </div>
          <div className="hero-badge">Hanicar Gold Tier</div>
        </header>

        <section className="stats-grid">
          {stats.map((stat) => (
            <article key={stat.label} className="stat-card">
              <span>{stat.label}</span>
              <strong>{stat.value}</strong>
            </article>
          ))}
        </section>

        <section className="workspace-grid">
          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Filters</p>
                <h3>Incident refinement</h3>
              </div>
              <button className="ghost-button" onClick={applyFilters} type="button">
                Apply
              </button>
            </div>
            <div className="filter-grid">
              <label>
                Severity
                <select value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}>
                  <option value="">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </label>
              <label>
                Decision
                <select value={filters.decision} onChange={(event) => setFilters((current) => ({ ...current, decision: event.target.value }))}>
                  <option value="">All</option>
                  <option value="stop">Stop</option>
                  <option value="review">Review</option>
                  <option value="continue">Continue</option>
                </select>
              </label>
              <label>
                Min Score
                <input value={filters.minScore} onChange={(event) => setFilters((current) => ({ ...current, minScore: event.target.value }))} placeholder="60" />
              </label>
              <label>
                Search
                <input value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} placeholder="IRIS case or asset" />
              </label>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Case Intake</p>
                <h3>Store a CTI case</h3>
              </div>
              <span className="mini-pill">{loading ? "Storing..." : "Ready"}</span>
            </div>
            <form className="intake-form" onSubmit={ingestCase}>
              <div className="two-col">
                <label>
                  Case Name
                  <input value={formState.title} onChange={(event) => setFormState((current) => ({ ...current, title: event.target.value }))} />
                </label>
                <label>
                  IRIS Case
                  <input value={formState.iris_case_name} onChange={(event) => setFormState((current) => ({ ...current, iris_case_name: event.target.value }))} />
                </label>
              </div>
              <div className="two-col">
                <label>
                  Asset
                  <input value={formState.asset_name} onChange={(event) => setFormState((current) => ({ ...current, asset_name: event.target.value }))} />
                </label>
                <label>
                  Workflow
                  <input value={formState.workflow_id} onChange={(event) => setFormState((current) => ({ ...current, workflow_id: event.target.value }))} />
                </label>
              </div>
              <label>
                Wazuh JSON
                <textarea value={formState.wazuh_alert} onChange={(event) => setFormState((current) => ({ ...current, wazuh_alert: event.target.value }))} />
              </label>
              <label>
                MISP JSON
                <textarea value={formState.misp_event} onChange={(event) => setFormState((current) => ({ ...current, misp_event: event.target.value }))} />
              </label>
              <label>
                Cortex JSON
                <textarea value={formState.cortex_analysis} onChange={(event) => setFormState((current) => ({ ...current, cortex_analysis: event.target.value }))} />
              </label>
              <label>
                Notes
                <textarea value={formState.notes} onChange={(event) => setFormState((current) => ({ ...current, notes: event.target.value }))} />
              </label>
              <button type="submit">Ingest and Analyze</button>
            </form>
          </section>
        </section>

        <section className="workspace-grid lower-grid">
          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Incidents</p>
                <h3>{caseTotal} tracked cases</h3>
              </div>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Decision</th>
                    <th>CVEs</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <button className="inline-link" onClick={() => openCase(item.id)} type="button">
                          {item.case_name}
                        </button>
                      </td>
                      <td><span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span></td>
                      <td>{item.score}</td>
                      <td>{item.decision}</td>
                      <td>{item.cve_count}</td>
                      <td>{formatDate(item.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">CVE Database</p>
                <h3>Recent external matches</h3>
              </div>
              <div className="pagination-box">
                <button className="ghost-button" disabled={cvePage <= 1} onClick={() => setCvePage((page) => Math.max(1, page - 1))} type="button">Prev</button>
                <span>Page {cvePage}</span>
                <button className="ghost-button" onClick={() => setCvePage((page) => page + 1)} type="button">Next</button>
              </div>
            </div>
            <div className="cve-list">
              {cves.map((item) => (
                <article key={item.cve_id} className="cve-card">
                  <div className="cve-head">
                    <strong>{item.cve_id}</strong>
                    <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span>
                  </div>
                  <p>{item.summary}</p>
                  <small>CVSS {item.cvss} | {formatDate(item.published)}</small>
                </article>
              ))}
            </div>
          </section>
        </section>
      </main>

      {selectedCase ? (
        <div className="modal-shell" onClick={() => setSelectedCase(null)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="panel-head">
              <div>
                <p className="eyebrow">{selectedCase.severity.toUpperCase()} | {selectedCase.score}/100 | {selectedCase.decision.toUpperCase()}</p>
                <h3>{selectedCase.case_name}</h3>
              </div>
              <button className="ghost-button" onClick={() => setSelectedCase(null)} type="button">Close</button>
            </div>
            <p className="lede">{selectedCase.summary}</p>
            <div className="summary-row">
              <div><span>Asset</span><strong>{selectedCase.asset_name}</strong></div>
              <div><span>IRIS Case</span><strong>{selectedCase.iris_case_name || "N/A"}</strong></div>
              <div><span>Created</span><strong>{formatDate(selectedCase.created_at)}</strong></div>
            </div>
            {[
              ["Recommendation", selectedCase.recommendation_body],
              ["MISP Event", selectedCase.raw_payload?.misp_event || {}],
              ["IOCs", selectedCase.iocs || []],
              ["Cortex Analysis", selectedCase.raw_payload?.cortex_analysis || {}],
              ["Wazuh Alert", selectedCase.raw_payload?.wazuh_alert || {}],
              ["CVEs", selectedCase.cves || []],
              ["PKIs", selectedCase.pkis || []],
            ].map(([title, value], index) => (
              <details key={title} className="accordion" open={index === 0}>
                <summary>{title}</summary>
                <pre>{typeof value === "string" ? value : JSON.stringify(value, null, 2)}</pre>
              </details>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default App;
