import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
const DEFAULT_EMAIL = "admin@hanicar.tn";
const DEFAULT_PASSWORD = "bornasroot";
const PAGE_OPTIONS = [10, 50, 100];

const NAV_ITEMS = [
  { id: "incidents", label: "Incidents" },
  { id: "wazuh", label: "Wazuh Alerts" },
  { id: "cortex", label: "Cortex Jobs" },
  { id: "misp", label: "MISP Events" },
  { id: "iris", label: "IRIS Cases" },
  { id: "mitre", label: "MITRE ATT&CK" },
  { id: "settings", label: "Settings" },
];

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
    if (response.status === 204) {
      return null;
    }
    return response.json();
  });
}

function severityTone(value) {
  return `severity-${(value || "low").toLowerCase()}`;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function parseJson(value) {
  const trimmed = value.trim();
  return trimmed ? JSON.parse(trimmed) : null;
}

function Pagination({ page, total, pageSize, onPageChange, onPageSizeChange }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pagination-box">
      <div className="page-size-box">
        <span>Rows</span>
        <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
          {PAGE_OPTIONS.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
      </div>
      <button className="ghost-button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} type="button">Prev</button>
      <span>Page {page} / {totalPages}</span>
      <button className="ghost-button" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)} type="button">Next</button>
    </div>
  );
}

function PanelHeader({ eyebrow, title, actions }) {
  return (
    <div className="panel-head">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h3>{title}</h3>
      </div>
      {actions ? <div className="panel-actions">{actions}</div> : null}
    </div>
  );
}

function DataTable({ columns, rows, empty = "No records available." }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => <th key={column.key}>{column.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.length ? rows.map((row, index) => (
            <tr key={row.id || row.external_id || row.source_id || index}>
              {columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : row[column.key]}</td>)}
            </tr>
          )) : (
            <tr>
              <td colSpan={columns.length} className="empty-cell">{empty}</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function DetailsBlock({ title, value, open = false }) {
  return (
    <details className="accordion" open={open}>
      <summary>{title}</summary>
      <pre>{typeof value === "string" ? value : JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function App() {
  const [token, setToken] = useState(localStorage.getItem("hanicar_dashboard_token") || "");
  const [userEmail, setUserEmail] = useState(localStorage.getItem("hanicar_dashboard_user") || "");
  const [loginError, setLoginError] = useState("");
  const [activeNav, setActiveNav] = useState("incidents");
  const [overview, setOverview] = useState(null);
  const [notifications, setNotifications] = useState({ items: [], total: 0 });
  const [showNotifications, setShowNotifications] = useState(false);
  const [selectedCase, setSelectedCase] = useState(null);
  const [selectedExternal, setSelectedExternal] = useState(null);
  const [selectedMitre, setSelectedMitre] = useState(null);
  const [busy, setBusy] = useState("");
  const [caseFilters, setCaseFilters] = useState({ severity: "", decision: "", minScore: "", search: "" });
  const [casePage, setCasePage] = useState(1);
  const [casePageSize, setCasePageSize] = useState(10);
  const [incidentState, setIncidentState] = useState({ items: [], total: 0 });
  const [cvePage, setCvePage] = useState(1);
  const [cvePageSize, setCvePageSize] = useState(10);
  const [cves, setCves] = useState({ items: [], total: 0 });
  const [settingsForm, setSettingsForm] = useState({ misp_base_url: "", misp_api_key: "", cortex_base_url: "", cortex_api_key: "", iris_base_url: "", iris_api_key: "", notification_email: "", dashboard_email: "", ollama_model: "", ollama_base_url: "", current_password: "", new_password: "" });
  const [sectionState, setSectionState] = useState({
    wazuh: { items: [], total: 0, page: 1, pageSize: 10, severity: "" },
    cortex: { items: [], total: 0, page: 1, pageSize: 10, severity: "" },
    misp: { items: [], total: 0, page: 1, pageSize: 10, severity: "" },
    iris: { items: [], total: 0, page: 1, pageSize: 10, severity: "" },
    mitre: { items: [], total: 0, page: 1, pageSize: 10, search: "" },
  });
  const [intake, setIntake] = useState({
    title: "Hanicar H-Brain perimeter incident",
    iris_case_name: "IRIS-HANICAR-2026-101",
    asset_name: "edge-fw-01",
    workflow_id: "wf-hbrain-001",
    notes: "Potential perimeter exploitation against banking edge services.",
    wazuh_alert: '{\n  "rule": {"level": 14, "description": "Attempted exploit detected for CVE-2024-3400"},\n  "agent": {"name": "edge-fw-01"},\n  "data": {"srcip": "198.51.100.77"}\n}',
    misp_event: '{\n  "Event": {"info": "Campaign infrastructure referencing CVE-2024-3400", "threat_level_id": "1", "Attribute": [{"value": "malicious.hanicar-demo.net"}]}\n}',
    cortex_analysis: '{\n  "analyzerName": "VirusTotal",\n  "summary": {"taxonomies": [{"namespace": "VT", "predicate": "malicious", "value": "high"}]}\n}',
  });

  const stats = useMemo(() => {
    if (!overview) return [];
    return [
      { label: "Live Incidents", value: overview.total_cases, trend: "Across linked workflows and cases" },
      { label: "Critical Queue", value: overview.critical_cases, trend: "Immediate banking response path" },
      { label: "Average Risk Score", value: overview.average_score, trend: "Model-driven H-Brain score" },
      { label: "Unread Notifications", value: overview.unread_notifications, trend: "High and critical signal feed" },
    ];
  }, [overview]);

  useEffect(() => {
    if (!token) return undefined;
    bootstrap(token);
    const timer = window.setInterval(() => bootstrap(token, true), 20000);
    return () => window.clearInterval(timer);
  }, [token, activeNav, casePage, casePageSize, cvePage, cvePageSize, caseFilters, sectionState.wazuh.page, sectionState.wazuh.pageSize, sectionState.wazuh.severity, sectionState.cortex.page, sectionState.cortex.pageSize, sectionState.cortex.severity, sectionState.misp.page, sectionState.misp.pageSize, sectionState.misp.severity, sectionState.iris.page, sectionState.iris.pageSize, sectionState.iris.severity, sectionState.mitre.page, sectionState.mitre.pageSize, sectionState.mitre.search]);

  async function fetchSection(section, activeToken = token) {
    const state = sectionState[section];
    if (section === "mitre") {
      const query = new URLSearchParams({ page: String(state.page), page_size: String(state.pageSize) });
      if (state.search) query.set("search", state.search);
      return api(`/api/dashboard/mitre?${query.toString()}`, activeToken);
    }
    const routeMap = {
      wazuh: "/api/dashboard/wazuh-alerts",
      cortex: "/api/dashboard/cortex/jobs",
      misp: "/api/dashboard/misp/events",
      iris: "/api/dashboard/iris/cases",
    };
    const query = new URLSearchParams({ page: String(state.page), page_size: String(state.pageSize) });
    if (state.severity) query.set("severity", state.severity);
    return api(`${routeMap[section]}?${query.toString()}`, activeToken);
  }

  async function bootstrap(activeToken = token, quiet = false) {
    try {
      const caseQuery = new URLSearchParams({ page: String(casePage), page_size: String(casePageSize) });
      if (caseFilters.severity) caseQuery.set("severity", caseFilters.severity);
      if (caseFilters.decision) caseQuery.set("decision", caseFilters.decision);
      if (caseFilters.minScore) caseQuery.set("min_score", caseFilters.minScore);
      if (caseFilters.search) caseQuery.set("search", caseFilters.search);
      const payloads = await Promise.all([
        api("/api/dashboard/overview", activeToken),
        api(`/api/dashboard/cases?${caseQuery.toString()}`, activeToken),
        api(`/api/dashboard/cves?page=${cvePage}&page_size=${cvePageSize}`, activeToken),
        api("/api/dashboard/notifications", activeToken),
        api("/api/dashboard/settings", activeToken),
        fetchSection("wazuh", activeToken),
        fetchSection("cortex", activeToken),
        fetchSection("misp", activeToken),
        fetchSection("iris", activeToken),
        fetchSection("mitre", activeToken),
      ]);
      setOverview(payloads[0]);
      setIncidentState({ items: payloads[1].items, total: payloads[1].total });
      setCves({ items: payloads[2].items, total: payloads[2].total });
      setNotifications(payloads[3]);
      setSettingsForm((current) => ({ ...current, ...payloads[4], current_password: current.current_password, new_password: current.new_password }));
      setSectionState((current) => ({
        ...current,
        wazuh: { ...current.wazuh, items: payloads[5].items, total: payloads[5].total },
        cortex: { ...current.cortex, items: payloads[6].items, total: payloads[6].total },
        misp: { ...current.misp, items: payloads[7].items, total: payloads[7].total },
        iris: { ...current.iris, items: payloads[8].items, total: payloads[8].total },
        mitre: { ...current.mitre, items: payloads[9].items, total: payloads[9].total },
      }));
      if (!quiet) setLoginError("");
    } catch (error) {
      if (!quiet) setLoginError(error.message);
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    try {
      const payload = await api("/api/auth/login", "", { method: "POST", body: JSON.stringify({ email: DEFAULT_EMAIL, password: DEFAULT_PASSWORD }) });
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
  }

  async function openCase(caseId) {
    const payload = await api(`/api/dashboard/cases/${caseId}`, token);
    setSelectedCase(payload);
  }

  async function markNotificationAndOpen(item) {
    await api(`/api/dashboard/notifications/${item.id}/read`, token, { method: "POST" });
    await bootstrap(token, true);
    setShowNotifications(false);
    if (item.case_id) {
      setActiveNav("incidents");
      await openCase(item.case_id);
    }
  }

  async function syncSource(source) {
    const routeMap = { cortex: "/api/dashboard/cortex/sync", misp: "/api/dashboard/misp/sync", iris: "/api/dashboard/iris/sync" };
    setBusy(source);
    try {
      await api(routeMap[source], token, { method: "POST" });
      await bootstrap(token, true);
    } finally {
      setBusy("");
    }
  }

  async function saveSettings(event) {
    event.preventDefault();
    setBusy("settings");
    try {
      const payload = await api("/api/dashboard/settings", token, { method: "POST", body: JSON.stringify(settingsForm) });
      setSettingsForm((current) => ({ ...current, ...payload, current_password: "", new_password: "" }));
    } finally {
      setBusy("");
    }
  }

  async function ingestIncident(event) {
    event.preventDefault();
    setBusy("ingest");
    try {
      const payload = await api("/api/dashboard/cases/ingest", token, {
        method: "POST",
        body: JSON.stringify({
          title: intake.title,
          iris_case_name: intake.iris_case_name,
          asset_name: intake.asset_name,
          workflow_id: intake.workflow_id,
          wazuh_alert: parseJson(intake.wazuh_alert),
          misp_event: parseJson(intake.misp_event),
          cortex_analysis: parseJson(intake.cortex_analysis),
          notes: intake.notes,
          source: "dashboard",
        }),
      });
      await bootstrap(token, true);
      setActiveNav("incidents");
      setSelectedCase(payload);
    } catch (error) {
      window.alert(`Ingestion failed: ${error.message}`);
    } finally {
      setBusy("");
    }
  }

  function updateSection(section, patch) {
    setSectionState((current) => ({ ...current, [section]: { ...current[section], ...patch } }));
  }

  const latestCases = overview?.latest_cases || [];
  const externalSection = ["wazuh", "cortex", "misp", "iris"].includes(activeNav);

  if (!token) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <div className="login-orbit" />
          <p className="eyebrow">Hanicar Security</p>
          <h1>Hanicar H-Brain</h1>
          <p className="lede">Production CTI and SOC intelligence workspace with banking-grade scoring, source correlation, and workflow-ready recommendations.</p>
          <form onSubmit={handleLogin}>
            <div className="input-lock"><label>Email</label><input value={DEFAULT_EMAIL} readOnly /></div>
            <div className="input-lock"><label>Password</label><input value={DEFAULT_PASSWORD} readOnly type="password" /></div>
            <button type="submit">Launch H-Brain</button>
          </form>
          {loginError ? <p className="error-text">{loginError}</p> : null}
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-shell">
      <aside className="sidebar">
        <div className="brand-block"><div className="monogram">HB</div><div><p className="eyebrow">Hanicar Security</p><h2>Hanicar H-Brain</h2></div></div>
        <nav className="main-nav">
          {NAV_ITEMS.map((item) => (
            <button key={item.id} className={`nav-item ${activeNav === item.id ? "active" : ""}`} onClick={() => setActiveNav(item.id)} type="button">{item.label}</button>
          ))}
        </nav>
        <div className="sidebar-panel">
          <p className="eyebrow">Live Queue</p>
          <div className="sidebar-list">
            {latestCases.map((item) => (
              <button key={item.id} className={`sidebar-case ${severityTone(item.severity)}`} onClick={() => openCase(item.id)} type="button">
                <span>{item.case_name}</span>
                <small>{item.score}/100 � {item.decision.toUpperCase()}</small>
              </button>
            ))}
          </div>
        </div>
        <div className="sidebar-panel profile-panel"><div><p className="eyebrow">Session</p><strong>{userEmail || DEFAULT_EMAIL}</strong></div><button className="ghost-button" onClick={logout} type="button">Logout</button></div>
      </aside>

      <main className="content">
        <header className="hero">
          <div className="hero-copy">
            <p className="eyebrow">Operational CTI</p>
            <h1>Gold-grade SOC intelligence built for real incident response.</h1>
            <p className="lede">Hanicar H-Brain unifies incidents, Wazuh, MISP, Cortex, IRIS, MITRE ATT&CK, CVE overlap, and workflow decisions in one high-clarity operating surface.</p>
          </div>
          <div className="hero-right">
            <div className="notification-group">
              <button className="gold-chip" onClick={() => setShowNotifications((current) => !current)} type="button">Notifications <span>{notifications.total}</span></button>
              {showNotifications ? (
                <div className="notification-popover">
                  {notifications.items.length ? notifications.items.map((item) => (
                    <button key={item.id} className={`notification-item ${item.is_read ? "read" : ""}`} onClick={() => markNotificationAndOpen(item)} type="button">
                      <strong>{item.title}</strong><span>{item.body}</span><small>{item.severity.toUpperCase()} � {formatDate(item.created_at)}</small>
                    </button>
                  )) : <p className="empty-note">No notifications available.</p>}
                </div>
              ) : null}
            </div>
            <div className="hero-badge"><span>Model</span><strong>H-Brain Banking RF</strong></div>
          </div>
        </header>

        <section className="stats-grid">
          {stats.map((stat) => (
            <article key={stat.label} className="stat-card"><span>{stat.label}</span><strong>{stat.value}</strong><small>{stat.trend}</small></article>
          ))}
        </section>

        <section className="command-grid">
          <article className="panel accent-panel">
            <PanelHeader eyebrow="Scoring Engine" title="Model-backed banking response score" />
            <div className="score-ring"><div className="score-center"><span>Average</span><strong>{overview?.average_score ?? 0}</strong></div></div>
            <div className="mini-metrics">
              <div><span>Workflow gates</span><strong>{overview?.open_stop_cases ?? 0}</strong></div>
              <div><span>CVE links</span><strong>{overview?.cve_matches ?? 0}</strong></div>
              <div><span>Dataset</span><strong>CSV-trained</strong></div>
            </div>
          </article>
          <article className="panel panel-tall">
            <PanelHeader eyebrow="Incident Intake" title="Submit multi-source intelligence" />
            <form className="intake-form" onSubmit={ingestIncident}>
              <div className="two-col">
                <label>Case Name<input value={intake.title} onChange={(event) => setIntake((current) => ({ ...current, title: event.target.value }))} /></label>
                <label>IRIS Case Name<input value={intake.iris_case_name} onChange={(event) => setIntake((current) => ({ ...current, iris_case_name: event.target.value }))} /></label>
              </div>
              <div className="two-col">
                <label>Asset<input value={intake.asset_name} onChange={(event) => setIntake((current) => ({ ...current, asset_name: event.target.value }))} /></label>
                <label>Workflow Playbook ID<input value={intake.workflow_id} onChange={(event) => setIntake((current) => ({ ...current, workflow_id: event.target.value }))} /></label>
              </div>
              <label>Wazuh Alert JSON<textarea value={intake.wazuh_alert} onChange={(event) => setIntake((current) => ({ ...current, wazuh_alert: event.target.value }))} /></label>
              <label>MISP Event JSON<textarea value={intake.misp_event} onChange={(event) => setIntake((current) => ({ ...current, misp_event: event.target.value }))} /></label>
              <label>Cortex Analysis JSON<textarea value={intake.cortex_analysis} onChange={(event) => setIntake((current) => ({ ...current, cortex_analysis: event.target.value }))} /></label>
              <label>Analyst Notes<textarea value={intake.notes} onChange={(event) => setIntake((current) => ({ ...current, notes: event.target.value }))} /></label>
              <button type="submit">{busy === "ingest" ? "Analyzing..." : "Analyze and Save Incident"}</button>
            </form>
          </article>
        </section>

        {activeNav === "incidents" ? (
          <section className="panel page-panel">
            <PanelHeader eyebrow="Incidents" title="Realtime incident management" actions={<><label className="filter-inline">Severity<select value={caseFilters.severity} onChange={(event) => setCaseFilters((current) => ({ ...current, severity: event.target.value }))}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="filter-inline">Decision<select value={caseFilters.decision} onChange={(event) => setCaseFilters((current) => ({ ...current, decision: event.target.value }))}><option value="">All</option><option value="stop">Stop</option><option value="review">Review</option><option value="continue">Continue</option></select></label><label className="filter-inline">Score<input value={caseFilters.minScore} onChange={(event) => setCaseFilters((current) => ({ ...current, minScore: event.target.value }))} placeholder="Min" /></label><label className="filter-inline grow">Search<input value={caseFilters.search} onChange={(event) => setCaseFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Case, IRIS, asset" /></label></>} />
            <DataTable columns={[{ key: "case_name", label: "Incident", render: (item) => <button className="inline-link" onClick={() => openCase(item.id)} type="button">{item.case_name}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "score", label: "Score" }, { key: "decision", label: "Decision" }, { key: "workflow_playbook", label: "Workflow" }, { key: "mitre_count", label: "MITRE" }, { key: "cve_count", label: "CVEs" }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={incidentState.items} />
            <div className="bottom-row">
              <Pagination page={casePage} total={incidentState.total} pageSize={casePageSize} onPageChange={setCasePage} onPageSizeChange={(value) => { setCasePage(1); setCasePageSize(value); }} />
              <Pagination page={cvePage} total={cves.total} pageSize={cvePageSize} onPageChange={setCvePage} onPageSizeChange={(value) => { setCvePage(1); setCvePageSize(value); }} />
            </div>
            <div className="split-cards">
              <article className="subpanel"><PanelHeader eyebrow="Case Stream" title="Latest scoring output" /><div className="feed-list">{incidentState.items.slice(0, 5).map((item) => <button key={item.id} className="feed-card" onClick={() => openCase(item.id)} type="button"><div><strong>{item.case_name}</strong><small>{item.workflow_playbook}</small></div><span className={`severity-pill ${severityTone(item.severity)}`}>{item.score}</span></button>)}</div></article>
              <article className="subpanel"><PanelHeader eyebrow="CVE Matches" title="External vulnerability overlap" /><div className="cve-list">{cves.items.map((item) => <article key={item.cve_id} className="cve-card"><div className="cve-head"><strong>{item.cve_id}</strong><span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span></div><p>{item.summary}</p><small>CVSS {item.cvss} � {formatDate(item.published)}</small></article>)}</div></article>
            </div>
          </section>
        ) : null}

        {externalSection ? (
          <section className="panel page-panel">
            <PanelHeader eyebrow={activeNav.toUpperCase()} title={`${NAV_ITEMS.find((item) => item.id === activeNav)?.label || activeNav} workspace`} actions={<>{activeNav !== "wazuh" ? <button className="ghost-button" onClick={() => syncSource(activeNav)} type="button">{busy === activeNav ? "Syncing..." : "Sync now"}</button> : null}<label className="filter-inline">Severity<select value={sectionState[activeNav].severity} onChange={(event) => updateSection(activeNav, { severity: event.target.value, page: 1 })}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></>} />
            <DataTable columns={[{ key: "source_id", label: "Source ID" }, { key: "title", label: "Title", render: (item) => <button className="inline-link" onClick={() => setSelectedExternal({ title: item.title, payload: item.raw_payload, type: activeNav })} type="button">{item.title}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={sectionState[activeNav].items} empty={`No ${activeNav} data available yet.`} />
            <Pagination page={sectionState[activeNav].page} total={sectionState[activeNav].total} pageSize={sectionState[activeNav].pageSize} onPageChange={(value) => updateSection(activeNav, { page: value })} onPageSizeChange={(value) => updateSection(activeNav, { page: 1, pageSize: value })} />
          </section>
        ) : null}

        {activeNav === "mitre" ? (
          <section className="panel page-panel">
            <PanelHeader eyebrow="MITRE" title="MITRE ATT&CK coverage map" actions={<label className="filter-inline grow">Search<input value={sectionState.mitre.search} onChange={(event) => updateSection("mitre", { search: event.target.value, page: 1 })} placeholder="Tactic, technique, ID" /></label>} />
            <DataTable columns={[{ key: "external_id", label: "Technique" }, { key: "name", label: "Name", render: (item) => <button className="inline-link" onClick={() => setSelectedMitre(item)} type="button">{item.name}</button> }, { key: "tactics", label: "Tactics", render: (item) => item.tactics.join(", ") || "-" }, { key: "platforms", label: "Platforms", render: (item) => item.platforms.join(", ") || "-" }]} rows={sectionState.mitre.items} />
            <Pagination page={sectionState.mitre.page} total={sectionState.mitre.total} pageSize={sectionState.mitre.pageSize} onPageChange={(value) => updateSection("mitre", { page: value })} onPageSizeChange={(value) => updateSection("mitre", { page: 1, pageSize: value })} />
          </section>
        ) : null}

        {activeNav === "settings" ? (
          <section className="panel page-panel">
            <PanelHeader eyebrow="Settings" title="Connector and operator configuration" />
            <form className="settings-grid" onSubmit={saveSettings}>
              <label>Dashboard Email<input value={settingsForm.dashboard_email} onChange={(event) => setSettingsForm((current) => ({ ...current, dashboard_email: event.target.value }))} /></label>
              <label>Notification Email<input value={settingsForm.notification_email} onChange={(event) => setSettingsForm((current) => ({ ...current, notification_email: event.target.value }))} /></label>
              <label>MISP URL<input value={settingsForm.misp_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_base_url: event.target.value }))} /></label>
              <label>MISP API Key<input value={settingsForm.misp_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_api_key: event.target.value }))} /></label>
              <label>Cortex URL<input value={settingsForm.cortex_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_base_url: event.target.value }))} /></label>
              <label>Cortex API Key<input value={settingsForm.cortex_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_api_key: event.target.value }))} /></label>
              <label>IRIS URL<input value={settingsForm.iris_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_base_url: event.target.value }))} /></label>
              <label>IRIS API Key<input value={settingsForm.iris_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_api_key: event.target.value }))} /></label>
              <label>Ollama Base URL<input value={settingsForm.ollama_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_base_url: event.target.value }))} /></label>
              <label>Ollama Model<input value={settingsForm.ollama_model} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_model: event.target.value }))} /></label>
              <label>Current Password<input type="password" value={settingsForm.current_password} onChange={(event) => setSettingsForm((current) => ({ ...current, current_password: event.target.value }))} /></label>
              <label>New Password<input type="password" value={settingsForm.new_password} onChange={(event) => setSettingsForm((current) => ({ ...current, new_password: event.target.value }))} /></label>
              <div className="settings-actions"><button type="submit">{busy === "settings" ? "Saving..." : "Save configuration"}</button><div className="settings-hint"><span>Stored in database</span><strong>Wazuh remains HTTP-ingest only</strong></div></div>
            </form>
          </section>
        ) : null}
      </main>

      {selectedCase ? <div className="modal-shell" onClick={() => setSelectedCase(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={`${selectedCase.severity.toUpperCase()} � ${selectedCase.score}/100 � ${selectedCase.decision.toUpperCase()}`} title={selectedCase.case_name} actions={<button className="ghost-button" onClick={() => setSelectedCase(null)} type="button">Close</button>} /><p className="lede">{selectedCase.summary}</p><div className="summary-grid"><div><span>Asset</span><strong>{selectedCase.asset_name}</strong></div><div><span>IRIS Case</span><strong>{selectedCase.iris_case_name || "Not linked"}</strong></div><div><span>Workflow</span><strong>{selectedCase.workflow_playbook}</strong></div><div><span>Score Model</span><strong>{selectedCase.score_model}</strong></div></div><DetailsBlock title="Recommendation" value={selectedCase.recommendation_body} open /><DetailsBlock title="MISP Event" value={selectedCase.raw_payload?.misp_event || {}} /><DetailsBlock title="Wazuh Alert" value={selectedCase.raw_payload?.wazuh_alert || {}} /><DetailsBlock title="Cortex Analysis" value={selectedCase.raw_payload?.cortex_analysis || {}} /><DetailsBlock title="MITRE ATT&CK" value={selectedCase.mitre_attacks || []} /><DetailsBlock title="CVEs" value={selectedCase.cves || []} /><DetailsBlock title="IOCs" value={selectedCase.iocs || []} /><DetailsBlock title="PKIs" value={selectedCase.pkis || []} /><DetailsBlock title="Email Payload" value={selectedCase.email_payload || {}} /><DetailsBlock title="Normalized Request" value={selectedCase.normalized_payload || {}} /></div></div> : null}
      {selectedExternal ? <div className="modal-shell" onClick={() => setSelectedExternal(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedExternal.type.toUpperCase()} title={selectedExternal.title} actions={<button className="ghost-button" onClick={() => setSelectedExternal(null)} type="button">Close</button>} /><DetailsBlock title="Raw Payload" value={selectedExternal.payload} open /></div></div> : null}
      {selectedMitre ? <div className="modal-shell" onClick={() => setSelectedMitre(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedMitre.external_id} title={selectedMitre.name} actions={<button className="ghost-button" onClick={() => setSelectedMitre(null)} type="button">Close</button>} /><p className="lede">{selectedMitre.description}</p><div className="summary-grid"><div><span>Tactics</span><strong>{selectedMitre.tactics.join(", ") || "-"}</strong></div><div><span>Platforms</span><strong>{selectedMitre.platforms.join(", ") || "-"}</strong></div><div><span>Reference</span><strong>{selectedMitre.url || "-"}</strong></div></div><DetailsBlock title="Detection Guidance" value={selectedMitre.detection || "No detection guidance available."} open /></div></div> : null}
    </div>
  );
}

export default App;
