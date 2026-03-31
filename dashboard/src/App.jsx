import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
const DEFAULT_EMAIL = "admin@hanicar.tn";
const DEFAULT_PASSWORD = "bornasroot";
const PAGE_OPTIONS = [10, 50, 100];
const LOGO_URL = "https://hanicar.tn/logo.png";

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: "grid" },
  { id: "incidents", label: "Incidents", icon: "shield" },
  { id: "wazuh", label: "Wazuh Alerts", icon: "pulse" },
  { id: "cortex", label: "Cortex Jobs", icon: "scan" },
  { id: "misp", label: "MISP Events", icon: "intel" },
  { id: "iris", label: "IRIS Cases", icon: "case" },
  { id: "mitre", label: "MITRE ATT&CK", icon: "target" },
  { id: "settings", label: "Settings", icon: "gear" },
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
    if (!response.ok) throw new Error(await response.text());
    if (response.status === 204) return null;
    return response.json();
  });
}

function Icon({ name }) {
  const paths = {
    grid: <path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z" />,
    shield: <path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z" />,
    pulse: <path d="M3 12h4l2-5 4 10 2-5h6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
    scan: <path d="M7 4H4v3M17 4h3v3M20 17v3h-3M4 17v3h3M8 12h8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
    intel: <path d="M4 6h16v12H4zM8 10h8M8 14h5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
    case: <path d="M9 4h6l1 2h4v12H4V6h4l1-2z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />,
    target: <path d="M12 3v4M12 17v4M3 12h4M17 12h4M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0M12 12m-8 0a8 8 0 1 0 16 0a8 8 0 1 0-16 0" fill="none" stroke="currentColor" strokeWidth="2" />,
    gear: <path d="M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8zm0-5l1.5 2.2 2.7.4.8 2.6 2.2 1.5-1 2.5 1 2.5-2.2 1.5-.8 2.6-2.7.4L12 21l-1.5-2.2-2.7-.4-.8-2.6-2.2-1.5 1-2.5-1-2.5 2.2-1.5.8-2.6 2.7-.4z" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />,
    bell: <path d="M12 4a4 4 0 0 1 4 4v3.5l1.7 2.5H6.3L8 11.5V8a4 4 0 0 1 4-4zm-2 13a2 2 0 0 0 4 0" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
    user: <path d="M12 12a4 4 0 1 0 0-8a4 4 0 1 0 0 8zm-7 8a7 7 0 0 1 14 0" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
    search: <path d="M11 18a7 7 0 1 1 0-14a7 7 0 1 1 0 14zm10 3-5-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />,
  };
  return <svg viewBox="0 0 24 24" className="icon">{paths[name] || paths.grid}</svg>;
}

function severityTone(value) { return `severity-${(value || "low").toLowerCase()}`; }
function severityColor(value) { return ({ critical: "#6e0f13", high: "#c62828", medium: "#f9a825", low: "#2e7d32" }[(value || "low").toLowerCase()] || "#2e7d32"); }
function formatDate(value) { return value ? new Date(value).toLocaleString() : "-"; }
function parseJson(value) { const trimmed = value.trim(); return trimmed ? JSON.parse(trimmed) : null; }

function Pagination({ page, total, pageSize, onPageChange, onPageSizeChange }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return <div className="pagination-box"><div className="page-size-box"><span>Rows</span><select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>{PAGE_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}</select></div><button className="ghost-button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} type="button">Prev</button><span>Page {page} / {totalPages}</span><button className="ghost-button" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)} type="button">Next</button></div>;
}

function PanelHeader({ eyebrow, title, actions }) {
  return <div className="panel-head"><div><p className="eyebrow">{eyebrow}</p><h3>{title}</h3></div>{actions ? <div className="panel-actions">{actions}</div> : null}</div>;
}

function DataTable({ columns, rows, empty = "No records available." }) {
  return <div className="table-wrap"><table><thead><tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr></thead><tbody>{rows.length ? rows.map((row, index) => <tr key={row.id || row.external_id || row.source_id || index}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : row[column.key]}</td>)}</tr>) : <tr><td colSpan={columns.length} className="empty-cell">{empty}</td></tr>}</tbody></table></div>;
}

function DetailsBlock({ title, value, open = false }) {
  return <details className="accordion" open={open}><summary>{title}</summary><pre>{typeof value === "string" ? value : JSON.stringify(value, null, 2)}</pre></details>;
}

function LineChart({ values }) {
  const safe = values.length ? values : [28, 42, 35, 55, 48, 62, 57];
  const max = Math.max(...safe, 1);
  const points = safe.map((value, index) => `${index * (100 / (safe.length - 1 || 1))},${90 - (value / max) * 70}`).join(" ");
  const area = `0,95 ${points} 100,95`;
  return <svg viewBox="0 0 100 100" className="line-chart" preserveAspectRatio="none"><defs><linearGradient id="scoreArea" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="rgba(255,167,38,0.7)" /><stop offset="100%" stopColor="rgba(255,167,38,0.02)" /></linearGradient></defs><path d={`M ${area}`} fill="url(#scoreArea)" /><polyline points={points} fill="none" stroke="#ff9800" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}

function SeverityHeatmap({ items }) {
  const cells = items.length ? items.slice(0, 28) : Array.from({ length: 28 }, (_, index) => ({ severity: ["low", "medium", "high", "critical"][index % 4], score: 25 + index }));
  return <div className="severity-heatmap">{cells.map((item, index) => <span key={`${item.id || index}`} style={{ backgroundColor: severityColor(item.severity) }} title={`${item.case_name || item.title || "Incident"} - ${item.severity}`} />)}</div>;
}

function RingChart({ value }) {
  const pct = Math.max(0, Math.min(100, Math.round(value || 0)));
  return <div className="ring-meter" style={{ background: `conic-gradient(#ffa726 ${pct}%, #2c2f36 ${pct}% 100%)` }}><div><span>Coverage</span><strong>{pct}%</strong></div></div>;
}

function App() {
  const [token, setToken] = useState(localStorage.getItem("hanicar_dashboard_token") || "");
  const [userEmail, setUserEmail] = useState(localStorage.getItem("hanicar_dashboard_user") || "");
  const [loginError, setLoginError] = useState("");
  const [activeNav, setActiveNav] = useState("overview");
  const [search, setSearch] = useState("");
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
  const [sectionState, setSectionState] = useState({ wazuh: { items: [], total: 0, page: 1, pageSize: 10, severity: "" }, cortex: { items: [], total: 0, page: 1, pageSize: 10, severity: "" }, misp: { items: [], total: 0, page: 1, pageSize: 10, severity: "" }, iris: { items: [], total: 0, page: 1, pageSize: 10, severity: "" }, mitre: { items: [], total: 0, page: 1, pageSize: 10, search: "" } });
  const [intake, setIntake] = useState({ title: "Hanicar H-Brain perimeter incident", iris_case_name: "IRIS-HANICAR-2026-101", asset_name: "edge-fw-01", workflow_id: "wf-hbrain-001", notes: "Potential perimeter exploitation against banking edge services.", wazuh_alert: '{\n  "rule": {"level": 14, "description": "Attempted exploit detected for CVE-2024-3400"},\n  "agent": {"name": "edge-fw-01"},\n  "data": {"srcip": "198.51.100.77"}\n}', misp_event: '{\n  "Event": {"info": "Campaign infrastructure referencing CVE-2024-3400", "threat_level_id": "1", "Attribute": [{"value": "malicious.hanicar-demo.net"}]}\n}', cortex_analysis: '{\n  "analyzerName": "VirusTotal",\n  "summary": {"taxonomies": [{"namespace": "VT", "predicate": "malicious", "value": "high"}]}\n}' });

  const stats = useMemo(() => overview ? [{ label: "Realtime Incidents", value: overview.total_cases, meta: "+ live intake" }, { label: "Critical Queue", value: overview.critical_cases, meta: "stop workflows" }, { label: "Average Risk", value: overview.average_score, meta: "model-backed" }, { label: "Unread Alerts", value: overview.unread_notifications, meta: "notification center" }] : [], [overview]);
  const filteredIncidents = useMemo(() => { const needle = search.trim().toLowerCase(); return needle ? incidentState.items.filter((item) => JSON.stringify(item).toLowerCase().includes(needle)) : incidentState.items; }, [incidentState.items, search]);
  const scoreSeries = useMemo(() => filteredIncidents.slice(0, 7).map((item) => item.score).reverse(), [filteredIncidents]);
  const severityMix = useMemo(() => ({ critical: filteredIncidents.filter((item) => item.severity === "critical").length, high: filteredIncidents.filter((item) => item.severity === "high").length, medium: filteredIncidents.filter((item) => item.severity === "medium").length, low: filteredIncidents.filter((item) => item.severity === "low").length }), [filteredIncidents]);
  const coverageValue = useMemo(() => Math.min(100, Math.round(((overview?.cve_matches || 0) + (overview?.total_cases || 0)) * 4)), [overview]);

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
    const routeMap = { wazuh: "/api/dashboard/wazuh-alerts", cortex: "/api/dashboard/cortex/jobs", misp: "/api/dashboard/misp/events", iris: "/api/dashboard/iris/cases" };
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
      setSectionState((current) => ({ ...current, wazuh: { ...current.wazuh, items: payloads[5].items, total: payloads[5].total }, cortex: { ...current.cortex, items: payloads[6].items, total: payloads[6].total }, misp: { ...current.misp, items: payloads[7].items, total: payloads[7].total }, iris: { ...current.iris, items: payloads[8].items, total: payloads[8].total }, mitre: { ...current.mitre, items: payloads[9].items, total: payloads[9].total } }));
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
      const payload = await api("/api/dashboard/cases/ingest", token, { method: "POST", body: JSON.stringify({ title: intake.title, iris_case_name: intake.iris_case_name, asset_name: intake.asset_name, workflow_id: intake.workflow_id, wazuh_alert: parseJson(intake.wazuh_alert), misp_event: parseJson(intake.misp_event), cortex_analysis: parseJson(intake.cortex_analysis), notes: intake.notes, source: "dashboard" }) });
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
    return <div className="login-screen"><div className="login-card"><img src={LOGO_URL} alt="Hanicar Security" className="login-logo" /><p className="eyebrow">Hanicar Security</p><h1>Hanicar H-Brain</h1><p className="lede">Firebase-inspired CTI and SOC intelligence workspace with banking-grade scoring, source correlation, and workflow-ready recommendations.</p><form onSubmit={handleLogin}><div className="input-lock"><label>Email</label><input value={DEFAULT_EMAIL} readOnly /></div><div className="input-lock"><label>Password</label><input value={DEFAULT_PASSWORD} readOnly type="password" /></div><button type="submit">Launch H-Brain</button></form>{loginError ? <p className="error-text">{loginError}</p> : null}</div></div>;
  }

  return <div className="firebase-shell"><aside className="sidebar firebase-sidebar"><div className="brand-block brand-logo-block"><img src={LOGO_URL} alt="Hanicar Security" className="brand-logo" /><div><p className="eyebrow">Hanicar Security</p><h2>Hanicar H-Brain</h2></div></div><p className="nav-caption">Main Menu</p><nav className="main-nav">{NAV_ITEMS.map((item) => <button key={item.id} className={`nav-item ${activeNav === item.id ? "active" : ""}`} onClick={() => setActiveNav(item.id)} type="button"><Icon name={item.icon} /><span>{item.label}</span></button>)}</nav><div className="sidebar-footer"><p className="nav-caption">Severity History</p><SeverityHeatmap items={filteredIncidents} /><div className="profile-mini"><Icon name="user" /><span>{userEmail || DEFAULT_EMAIL}</span></div></div></aside><main className="firebase-main"><header className="topbar"><div><p className="eyebrow">Good Morning</p><h1>{activeNav === "overview" ? "Overview" : NAV_ITEMS.find((item) => item.id === activeNav)?.label}</h1><p className="lede">Welcome to the Hanicar H-Brain operational console.</p></div><div className="topbar-actions"><label className="search-box"><Icon name="search" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search incidents, IRIS, CVE, MITRE" /></label><div className="notification-group"><button className="icon-button" onClick={() => setShowNotifications((current) => !current)} type="button"><Icon name="bell" /><span>{notifications.total}</span></button>{showNotifications ? <div className="notification-popover">{notifications.items.length ? notifications.items.map((item) => <button key={item.id} className={`notification-item ${item.is_read ? "read" : ""}`} onClick={() => markNotificationAndOpen(item)} type="button"><strong>{item.title}</strong><span>{item.body}</span><small>{item.severity.toUpperCase()} · {formatDate(item.created_at)}</small></button>) : <p className="empty-note">No notifications available.</p>}</div> : null}</div><div className="avatar-chip"><img src={LOGO_URL} alt="Hanicar avatar" /><span>Admin</span></div></div></header><section className="stats-grid firebase-stats">{stats.map((stat) => <article key={stat.label} className="stat-card firebase-card"><span>{stat.label}</span><strong>{stat.value}</strong><small>{stat.meta}</small></article>)}</section>

        {activeNav === "overview" ? <><section className="overview-grid"><article className="panel firebase-card quick-actions-card"><PanelHeader eyebrow="Shortcuts" title="Core response modules" /><div className="quick-actions-grid">{[["Incidents", "shield", overview?.total_cases || 0],["Wazuh", "pulse", sectionState.wazuh.total],["Cortex", "scan", sectionState.cortex.total],["MISP", "intel", sectionState.misp.total]].map(([label, icon, value]) => <button key={label} className="quick-action" onClick={() => setActiveNav(label.toLowerCase() === "incidents" ? "incidents" : label.toLowerCase())} type="button"><Icon name={icon} /><span>{label}</span><strong>{value}</strong></button>)}</div></article><article className="panel firebase-card chart-card wide-card"><PanelHeader eyebrow="Risk Trend" title="Incident score movement" actions={<span className="mini-badge">7 latest cases</span>} /><div className="chart-stage"><LineChart values={scoreSeries} /></div></article><article className="panel firebase-card compact-card"><PanelHeader eyebrow="Coverage" title="Intel match ratio" /><RingChart value={coverageValue} /></article></section><section className="overview-grid second-row"><article className="panel firebase-card"><PanelHeader eyebrow="Severity Matrix" title="GitHub-style incident intensity" /><SeverityHeatmap items={filteredIncidents} /><div className="severity-legend">{Object.entries(severityMix).map(([key, value]) => <span key={key}><i style={{ backgroundColor: severityColor(key) }} />{key} ({value})</span>)}</div></article><article className="panel firebase-card"><PanelHeader eyebrow="Live Feed" title="Latest incidents" /><div className="feed-list">{filteredIncidents.slice(0, 5).map((item) => <button key={item.id} className="feed-card" onClick={() => openCase(item.id)} type="button"><div><strong>{item.case_name}</strong><small>{item.workflow_playbook}</small></div><span className={`severity-pill ${severityTone(item.severity)}`}>{item.score}</span></button>)}</div></article><article className="panel firebase-card"><PanelHeader eyebrow="CVE Overlap" title="Recent vulnerability matches" /><div className="cve-list">{cves.items.slice(0, 4).map((item) => <article key={item.cve_id} className="cve-card"><div className="cve-head"><strong>{item.cve_id}</strong><span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span></div><p>{item.summary}</p><small>CVSS {item.cvss}</small></article>)}</div></article></section></> : null}
        {activeNav === "incidents" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Incidents" title="Realtime incident management" actions={<><label className="filter-inline">Severity<select value={caseFilters.severity} onChange={(event) => setCaseFilters((current) => ({ ...current, severity: event.target.value }))}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="filter-inline">Decision<select value={caseFilters.decision} onChange={(event) => setCaseFilters((current) => ({ ...current, decision: event.target.value }))}><option value="">All</option><option value="stop">Stop</option><option value="review">Review</option><option value="continue">Continue</option></select></label><label className="filter-inline">Score<input value={caseFilters.minScore} onChange={(event) => setCaseFilters((current) => ({ ...current, minScore: event.target.value }))} placeholder="Min" /></label><label className="filter-inline grow">Search<input value={caseFilters.search} onChange={(event) => setCaseFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Case, IRIS, asset" /></label></>} /><DataTable columns={[{ key: "case_name", label: "Incident", render: (item) => <button className="inline-link" onClick={() => openCase(item.id)} type="button">{item.case_name}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "score", label: "Score" }, { key: "decision", label: "Decision" }, { key: "workflow_playbook", label: "Workflow" }, { key: "mitre_count", label: "MITRE" }, { key: "cve_count", label: "CVEs" }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={filteredIncidents} /><div className="bottom-row"><Pagination page={casePage} total={incidentState.total} pageSize={casePageSize} onPageChange={setCasePage} onPageSizeChange={(value) => { setCasePage(1); setCasePageSize(value); }} /><Pagination page={cvePage} total={cves.total} pageSize={cvePageSize} onPageChange={setCvePage} onPageSizeChange={(value) => { setCvePage(1); setCvePageSize(value); }} /></div></section> : null}
        {externalSection ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow={activeNav.toUpperCase()} title={`${NAV_ITEMS.find((item) => item.id === activeNav)?.label || activeNav} workspace`} actions={<>{activeNav !== "wazuh" ? <button className="ghost-button" onClick={() => syncSource(activeNav)} type="button">{busy === activeNav ? "Syncing..." : "Sync now"}</button> : null}<label className="filter-inline">Severity<select value={sectionState[activeNav].severity} onChange={(event) => updateSection(activeNav, { severity: event.target.value, page: 1 })}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></>} /><DataTable columns={[{ key: "source_id", label: "Source ID" }, { key: "title", label: "Title", render: (item) => <button className="inline-link" onClick={() => setSelectedExternal({ title: item.title, payload: item.raw_payload, type: activeNav })} type="button">{item.title}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={sectionState[activeNav].items.filter((item) => JSON.stringify(item).toLowerCase().includes(search.toLowerCase()))} empty={`No ${activeNav} data available yet.`} /><Pagination page={sectionState[activeNav].page} total={sectionState[activeNav].total} pageSize={sectionState[activeNav].pageSize} onPageChange={(value) => updateSection(activeNav, { page: value })} onPageSizeChange={(value) => updateSection(activeNav, { page: 1, pageSize: value })} /></section> : null}
        {activeNav === "mitre" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="MITRE" title="MITRE ATT&CK coverage map" actions={<label className="filter-inline grow">Search<input value={sectionState.mitre.search} onChange={(event) => updateSection("mitre", { search: event.target.value, page: 1 })} placeholder="Tactic, technique, ID" /></label>} /><DataTable columns={[{ key: "external_id", label: "Technique" }, { key: "name", label: "Name", render: (item) => <button className="inline-link" onClick={() => setSelectedMitre(item)} type="button">{item.name}</button> }, { key: "tactics", label: "Tactics", render: (item) => item.tactics.join(", ") || "-" }, { key: "platforms", label: "Platforms", render: (item) => item.platforms.join(", ") || "-" }]} rows={sectionState.mitre.items.filter((item) => JSON.stringify(item).toLowerCase().includes(search.toLowerCase()))} /><Pagination page={sectionState.mitre.page} total={sectionState.mitre.total} pageSize={sectionState.mitre.pageSize} onPageChange={(value) => updateSection("mitre", { page: value })} onPageSizeChange={(value) => updateSection("mitre", { page: 1, pageSize: value })} /></section> : null}
        {activeNav === "settings" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Settings" title="Connector and operator configuration" /><form className="settings-grid" onSubmit={saveSettings}><label>Dashboard Email<input value={settingsForm.dashboard_email} onChange={(event) => setSettingsForm((current) => ({ ...current, dashboard_email: event.target.value }))} /></label><label>Notification Email<input value={settingsForm.notification_email} onChange={(event) => setSettingsForm((current) => ({ ...current, notification_email: event.target.value }))} /></label><label>MISP URL<input value={settingsForm.misp_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_base_url: event.target.value }))} /></label><label>MISP API Key<input value={settingsForm.misp_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_api_key: event.target.value }))} /></label><label>Cortex URL<input value={settingsForm.cortex_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_base_url: event.target.value }))} /></label><label>Cortex API Key<input value={settingsForm.cortex_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_api_key: event.target.value }))} /></label><label>IRIS URL<input value={settingsForm.iris_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_base_url: event.target.value }))} /></label><label>IRIS API Key<input value={settingsForm.iris_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_api_key: event.target.value }))} /></label><label>Ollama Base URL<input value={settingsForm.ollama_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_base_url: event.target.value }))} /></label><label>Ollama Model<input value={settingsForm.ollama_model} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_model: event.target.value }))} /></label><label>Current Password<input type="password" value={settingsForm.current_password} onChange={(event) => setSettingsForm((current) => ({ ...current, current_password: event.target.value }))} /></label><label>New Password<input type="password" value={settingsForm.new_password} onChange={(event) => setSettingsForm((current) => ({ ...current, new_password: event.target.value }))} /></label><div className="settings-actions"><button type="submit">{busy === "settings" ? "Saving..." : "Save configuration"}</button><div className="settings-hint"><span>Stored in database</span><strong>Wazuh remains HTTP-ingest only</strong></div></div></form></section> : null}
        <section className="panel firebase-card intake-dock"><PanelHeader eyebrow="Quick Intake" title="Paste raw intelligence" /><form className="intake-form compact-form" onSubmit={ingestIncident}><div className="two-col"><label>Case Name<input value={intake.title} onChange={(event) => setIntake((current) => ({ ...current, title: event.target.value }))} /></label><label>Workflow<input value={intake.workflow_id} onChange={(event) => setIntake((current) => ({ ...current, workflow_id: event.target.value }))} /></label></div><button type="submit">{busy === "ingest" ? "Analyzing..." : "Save Incident"}</button></form></section></main>{selectedCase ? <div className="modal-shell" onClick={() => setSelectedCase(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={`${selectedCase.severity.toUpperCase()} · ${selectedCase.score}/100 · ${selectedCase.decision.toUpperCase()}`} title={selectedCase.case_name} actions={<button className="ghost-button" onClick={() => setSelectedCase(null)} type="button">Close</button>} /><p className="lede">{selectedCase.summary}</p><div className="summary-grid"><div><span>Asset</span><strong>{selectedCase.asset_name}</strong></div><div><span>IRIS Case</span><strong>{selectedCase.iris_case_name || "Not linked"}</strong></div><div><span>Workflow</span><strong>{selectedCase.workflow_playbook}</strong></div><div><span>Score Model</span><strong>{selectedCase.score_model}</strong></div></div><DetailsBlock title="Recommendation" value={selectedCase.recommendation_body} open /><DetailsBlock title="MISP Event" value={selectedCase.raw_payload?.misp_event || {}} /><DetailsBlock title="Wazuh Alert" value={selectedCase.raw_payload?.wazuh_alert || {}} /><DetailsBlock title="Cortex Analysis" value={selectedCase.raw_payload?.cortex_analysis || {}} /><DetailsBlock title="MITRE ATT&CK" value={selectedCase.mitre_attacks || []} /><DetailsBlock title="CVEs" value={selectedCase.cves || []} /><DetailsBlock title="IOCs" value={selectedCase.iocs || []} /><DetailsBlock title="PKIs" value={selectedCase.pkis || []} /><DetailsBlock title="Email Payload" value={selectedCase.email_payload || {}} /><DetailsBlock title="Normalized Request" value={selectedCase.normalized_payload || {}} /></div></div> : null}{selectedExternal ? <div className="modal-shell" onClick={() => setSelectedExternal(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedExternal.type.toUpperCase()} title={selectedExternal.title} actions={<button className="ghost-button" onClick={() => setSelectedExternal(null)} type="button">Close</button>} /><DetailsBlock title="Raw Payload" value={selectedExternal.payload} open /></div></div> : null}{selectedMitre ? <div className="modal-shell" onClick={() => setSelectedMitre(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedMitre.external_id} title={selectedMitre.name} actions={<button className="ghost-button" onClick={() => setSelectedMitre(null)} type="button">Close</button>} /><p className="lede">{selectedMitre.description}</p><div className="summary-grid"><div><span>Tactics</span><strong>{selectedMitre.tactics.join(", ") || "-"}</strong></div><div><span>Platforms</span><strong>{selectedMitre.platforms.join(", ") || "-"}</strong></div><div><span>Reference</span><strong>{selectedMitre.url || "-"}</strong></div></div><DetailsBlock title="Detection Guidance" value={selectedMitre.detection || "No detection guidance available."} open /></div></div> : null}</div>;
}

export default App;
