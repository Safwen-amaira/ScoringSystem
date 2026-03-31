import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
const DEFAULT_EMAIL = "admin@hanicar.tn";
const DEFAULT_PASSWORD = "bornasroot";
const PAGE_OPTIONS = [10, 50, 100];
const LOGO_URL = "https://hanicar.tn/logo.png";
const COMPANY_URL = "https://hanicar.tn";

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: "grid" },
  { id: "incidents", label: "Incidents", icon: "shield" },
  { id: "wazuh", label: "Wazuh Alerts", icon: "pulse" },
  { id: "cortex", label: "Cortex Jobs", icon: "scan" },
  { id: "misp", label: "MISP Events", icon: "intel" },
  { id: "iris", label: "IRIS Cases", icon: "case" },
  { id: "mitre", label: "MITRE ATT&CK", icon: "target" },
  { id: "discussion", label: "Discussion", icon: "chat" },
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
    chevron: <path d="M7 10l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
    chat: <path d="M5 6h14v9H9l-4 4z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />,
  };
  return <svg viewBox="0 0 24 24" className="icon">{paths[name] || paths.grid}</svg>;
}

function severityTone(value) {
  return `severity-${(value || "low").toLowerCase()}`;
}

function severityColor(value) {
  return ({ critical: "#7f1d1d", high: "#dc2626", medium: "#d4a017", low: "#2f855a" }[(value || "low").toLowerCase()] || "#2f855a");
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function Pagination({ page, total, pageSize, onPageChange, onPageSizeChange }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return <div className="pagination-box"><div className="page-size-box"><span>Rows per page</span><select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>{PAGE_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}</select></div><div className="pager-buttons"><button className="ghost-button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} type="button">Prev</button><span>Page {page} / {totalPages}</span><button className="ghost-button" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)} type="button">Next</button></div></div>;
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

function TrendChart({ points, labels }) {
  const safe = points.length ? points : [42, 58, 51, 66, 61, 74, 68, 80];
  const max = Math.max(...safe, 1);
  const mapped = safe.map((value, index) => ({ value, x: 50 + index * ((700 - 100) / Math.max(1, safe.length - 1)), y: 240 - (value / max) * 150, label: labels[index] || `P${index + 1}` }));
  const line = mapped.map((point) => `${point.x},${point.y}`).join(" ");
  const area = `50,250 ${line} 700,250`;
  const [hovered, setHovered] = useState(mapped.at(-1) || null);
  return <div className="interactive-chart"><svg viewBox="0 0 760 280" preserveAspectRatio="none" className="trend-chart-svg">{[0, 1, 2, 3].map((row) => <line key={row} x1="50" x2="700" y1={70 + row * 45} y2={70 + row * 45} className="chart-grid-line" />)}{mapped.map((point) => <line key={point.label} x1={point.x} x2={point.x} y1="60" y2="250" className="chart-grid-vertical" />)}<path d={`M ${area}`} className="chart-area-primary" /><polyline points={line} className="chart-line-primary" />{mapped.map((point) => <g key={point.label} onMouseEnter={() => setHovered(point)}><circle cx={point.x} cy={point.y} r="5.5" className="chart-dot" /><rect x={point.x - 18} y="55" width="36" height="195" className="chart-hitbox" /><text x={point.x} y="268" textAnchor="middle" className="chart-x-label">{point.label}</text></g>)}</svg>{hovered ? <div className="chart-tooltip"><strong>{hovered.value}</strong><span>{hovered.label}</span></div> : null}</div>;
}

function SourceBars({ items }) {
  const max = Math.max(...items.map((item) => item.value), 1);
  return <div className="source-bars">{items.map((item) => <button key={item.label} className="source-bar-row" type="button" title={`${item.label}: ${item.value}`}><div><strong>{item.label}</strong><span>{item.subtitle}</span></div><div className="source-bar-track"><span className="source-bar-fill" style={{ width: `${(item.value / max) * 100}%` }} /></div><em>{item.value}</em></button>)}</div>;
}

function HeatmapCard({ items }) {
  const cells = items.length ? items.slice(0, 35) : Array.from({ length: 35 }, (_, index) => ({ severity: ["low", "medium", "high", "critical"][index % 4], score: 15 + index }));
  return <div><div className="severity-heatmap enhanced">{cells.map((item, index) => <button key={`${item.id || index}`} className="heatmap-cell" style={{ backgroundColor: severityColor(item.severity) }} title={`${item.case_name || item.title || "Incident"} - ${item.severity} - ${item.score || 0}`} type="button" />)}</div><div className="severity-legend compact">{["critical", "high", "medium", "low"].map((level) => <span key={level}><i style={{ backgroundColor: severityColor(level) }} />{level}</span>)}</div></div>;
}

function RingChart({ value, label }) {
  const pct = Math.max(0, Math.min(100, Math.round(value || 0)));
  return <div className="ring-card"><div className="ring-meter" style={{ background: `conic-gradient(#f3f4f6 ${pct}%, #2b2f36 ${pct}% 100%)` }}><div><span>{label}</span><strong>{pct}%</strong></div></div></div>;
}

function App() {
  const [token, setToken] = useState(localStorage.getItem("hanicar_dashboard_token") || "");
  const [userEmail, setUserEmail] = useState(localStorage.getItem("hanicar_dashboard_user") || "");
  const [loginError, setLoginError] = useState("");
  const [activeNav, setActiveNav] = useState("overview");
  const [overview, setOverview] = useState(null);
  const [notifications, setNotifications] = useState({ items: [], total: 0 });
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
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
  const [chatMessages, setChatMessages] = useState([]);
  const [chatDraft, setChatDraft] = useState("");
  const stats = useMemo(() => overview ? [{ label: "Total Incidents", value: overview.total_cases, meta: "Realtime synced" }, { label: "Critical Queue", value: overview.critical_cases, meta: "Needs action" }, { label: "Average Score", value: overview.average_score, meta: "Hybrid model" }, { label: "Unread Alerts", value: overview.unread_notifications, meta: "Notification center" }] : [], [overview]);
  const scoreSeries = useMemo(() => {
    const latest = incidentState.items.slice(0, 8).map((item) => item.score).reverse();
    return latest.length ? latest : [38, 61, 49, 68, 58, 72, 66, 81];
  }, [incidentState.items]);
  const scoreLabels = useMemo(() => incidentState.items.slice(0, 8).reverse().map((item) => new Date(item.created_at).toLocaleDateString(undefined, { month: "short", day: "numeric" })), [incidentState.items]);
  const sourcePulse = useMemo(() => [{ label: "Wazuh", value: sectionState.wazuh.total || 4, subtitle: "Detection pipeline" }, { label: "Cortex", value: sectionState.cortex.total || 3, subtitle: "Analyzer jobs" }, { label: "MISP", value: sectionState.misp.total || 2, subtitle: "Threat intel events" }, { label: "IRIS", value: sectionState.iris.total || 2, subtitle: "Case linkage" }], [sectionState]);
  const severityMix = useMemo(() => ({ critical: incidentState.items.filter((item) => item.severity === "critical").length, high: incidentState.items.filter((item) => item.severity === "high").length, medium: incidentState.items.filter((item) => item.severity === "medium").length, low: incidentState.items.filter((item) => item.severity === "low").length }), [incidentState.items]);
  const latestCases = overview?.latest_cases || [];
  const externalSection = ["wazuh", "cortex", "misp", "iris"].includes(activeNav);
  const coverageValue = useMemo(() => Math.min(100, Math.round(((overview?.cve_matches || 0) + (overview?.total_cases || 0)) * 4)), [overview]);

  useEffect(() => {
    if (!token) return undefined;
    bootstrap(token);
    const timer = window.setInterval(() => bootstrap(token, true), 15000);
    return () => window.clearInterval(timer);
  }, [token, activeNav, casePage, casePageSize, cvePage, cvePageSize, caseFilters, sectionState.wazuh.page, sectionState.wazuh.pageSize, sectionState.wazuh.severity, sectionState.cortex.page, sectionState.cortex.pageSize, sectionState.cortex.severity, sectionState.misp.page, sectionState.misp.pageSize, sectionState.misp.severity, sectionState.iris.page, sectionState.iris.pageSize, sectionState.iris.severity, sectionState.mitre.page, sectionState.mitre.pageSize, sectionState.mitre.search]);

  useEffect(() => {
    if (!token || activeNav !== "discussion" || chatMessages.length) return;
    sendChat([], true);
  }, [token, activeNav]);

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
    setShowProfileMenu(false);
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

  function updateSection(section, patch) {
    setSectionState((current) => ({ ...current, [section]: { ...current[section], ...patch } }));
  }

  async function sendChat(messages, introOnly = false) {
    setBusy("chat");
    try {
      const payload = await api("/api/chat", token, { method: "POST", body: JSON.stringify({ messages }) });
      setChatMessages((current) => introOnly ? [payload.message] : [...current, payload.message]);
    } finally {
      setBusy("");
    }
  }

  async function handleChatSubmit(event) {
    event.preventDefault();
    const trimmed = chatDraft.trim();
    if (!trimmed) return;
    const nextMessages = [...chatMessages, { role: "user", content: trimmed }];
    setChatMessages(nextMessages);
    setChatDraft("");
    await sendChat(nextMessages);
  }

  if (!token) {
    return <div className="login-screen"><div className="login-card"><img src={LOGO_URL} alt="Hanicar Security" className="login-logo" /><p className="eyebrow">Hanicar Security</p><h1>H-Brain</h1><p className="lede">Production-ready CTI, SOC operations, enrichment, and banking-grade incident scoring.</p><form onSubmit={handleLogin}><div className="input-lock"><label>Email</label><input value={DEFAULT_EMAIL} readOnly /></div><div className="input-lock"><label>Password</label><input value={DEFAULT_PASSWORD} readOnly type="password" /></div><button type="submit">Launch H-Brain</button></form>{loginError ? <p className="error-text">{loginError}</p> : null}</div></div>;
  }
  return <div className="firebase-shell exact-shell"><aside className="sidebar firebase-sidebar exact-sidebar"><div className="sidebar-scroll"><div className="brand-block brand-logo-block"><img src={LOGO_URL} alt="Hanicar Security" className="brand-logo" /><div><p className="eyebrow">Hanicar Security</p><h2>H-Brain</h2></div></div><p className="nav-caption">Main Menu</p><nav className="main-nav">{NAV_ITEMS.map((item) => <button key={item.id} className={`nav-item ${activeNav === item.id ? "active" : ""}`} onClick={() => { setActiveNav(item.id); setShowProfileMenu(false); }} type="button"><Icon name={item.icon} /><span>{item.label}</span></button>)}</nav><div className="sidebar-lower-links"><button className="nav-item muted-nav" onClick={() => setActiveNav("settings")} type="button"><Icon name="gear" /><span>Settings</span></button><a className="sidebar-rights" href={COMPANY_URL} target="_blank" rel="noreferrer">All rights are reserved for Hanicar Security</a></div></div></aside><main className="firebase-main exact-main"><header className="topbar exact-topbar"><div><p className="eyebrow">Operational Console</p><h1>{activeNav === "overview" ? "Overview" : NAV_ITEMS.find((item) => item.id === activeNav)?.label}</h1><p className="lede">Realtime CTI and SOC workspace for banking incident response.</p></div><div className="topbar-actions compact-actions"><div className="notification-group"><button className="icon-button" onClick={() => { setShowNotifications((current) => !current); setShowProfileMenu(false); }} type="button"><Icon name="bell" /><span>{notifications.total}</span></button>{showNotifications ? <div className="notification-popover scrollable-dropdown"><div className="dropdown-header"><strong>Notifications</strong><small>{notifications.total} unread or active</small></div>{notifications.items.length ? notifications.items.map((item) => <button key={item.id} className={`notification-item ${item.is_read ? "read" : ""}`} onClick={() => markNotificationAndOpen(item)} type="button"><strong>{item.title}</strong><span>{item.body}</span><small>{item.severity.toUpperCase()} · {formatDate(item.created_at)}</small></button>) : <p className="empty-note">No notifications available.</p>}</div> : null}</div><div className="profile-group"><button className="avatar-chip dropdown-trigger" onClick={() => { setShowProfileMenu((current) => !current); setShowNotifications(false); }} type="button"><img src={LOGO_URL} alt="Hanicar avatar" /><span>Admin</span><Icon name="chevron" /></button>{showProfileMenu ? <div className="profile-menu"><button type="button" onClick={() => { setActiveNav("settings"); setShowProfileMenu(false); }}>Settings</button><button type="button" onClick={logout}>Logout</button></div> : null}</div></div></header><section className="stats-grid firebase-stats exact-stats">{stats.map((stat) => <article key={stat.label} className="stat-card firebase-card exact-stat-card"><span>{stat.label}</span><strong>{stat.value}</strong><small>{stat.meta}</small></article>)}</section>

  {activeNav === "overview" ? <><section className="overview-grid overview-primary-grid"><article className="panel firebase-card hero-panel"><div className="hero-header"><div><p className="eyebrow">Risk movement</p><h3>Total Incident Pressure</h3></div><div className="hero-switches"><button type="button" className="toggle active">Last 7 cases</button><button type="button" className="toggle">Realtime</button></div></div><TrendChart points={scoreSeries} labels={scoreLabels} /></article><article className="panel firebase-card summary-stack"><PanelHeader eyebrow="Response" title="Containment posture" /><div className="summary-mini-grid"><button type="button" className="mini-module-card"><Icon name="shield" /><span>Incidents</span><strong>{overview?.total_cases || 0}</strong></button><button type="button" className="mini-module-card"><Icon name="pulse" /><span>Wazuh</span><strong>{sectionState.wazuh.total}</strong></button><button type="button" className="mini-module-card"><Icon name="scan" /><span>Cortex</span><strong>{sectionState.cortex.total}</strong></button><button type="button" className="mini-module-card"><Icon name="intel" /><span>MISP</span><strong>{sectionState.misp.total}</strong></button></div><RingChart value={coverageValue} label="Intel coverage" /></article></section><section className="overview-grid overview-secondary-grid"><article className="panel firebase-card"><PanelHeader eyebrow="Severity history" title="Incident intensity map" /><HeatmapCard items={incidentState.items} /></article><article className="panel firebase-card"><PanelHeader eyebrow="Source distribution" title="Realtime pipeline load" actions={<span className="mini-badge">15s refresh</span>} /><SourceBars items={sourcePulse} /></article><article className="panel firebase-card compact-insight-card"><PanelHeader eyebrow="Decision posture" title="Current split" /><div className="decision-grid"><div><span>Stop</span><strong>{incidentState.items.filter((item) => item.decision === "stop").length}</strong></div><div><span>Review</span><strong>{incidentState.items.filter((item) => item.decision === "review").length}</strong></div><div><span>Continue</span><strong>{incidentState.items.filter((item) => item.decision === "continue").length}</strong></div><div><span>Critical</span><strong>{severityMix.critical}</strong></div></div></article></section><section className="panel firebase-card page-panel"><PanelHeader eyebrow="Recent incidents" title="Latest response cases" actions={<button className="ghost-button" onClick={() => setActiveNav("incidents")} type="button">Open incident desk</button>} /><DataTable columns={[{ key: "case_name", label: "Incident", render: (item) => <button className="inline-link" onClick={() => openCase(item.id)} type="button">{item.case_name}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "score", label: "Score" }, { key: "decision", label: "Decision" }, { key: "workflow_playbook", label: "Workflow" }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={latestCases} /></section></> : null}

  {activeNav === "incidents" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Incidents" title="Realtime incident management" actions={<><label className="filter-inline">Severity<select value={caseFilters.severity} onChange={(event) => setCaseFilters((current) => ({ ...current, severity: event.target.value }))}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="filter-inline">Decision<select value={caseFilters.decision} onChange={(event) => setCaseFilters((current) => ({ ...current, decision: event.target.value }))}><option value="">All</option><option value="stop">Stop</option><option value="review">Review</option><option value="continue">Continue</option></select></label><label className="filter-inline">Score<input value={caseFilters.minScore} onChange={(event) => setCaseFilters((current) => ({ ...current, minScore: event.target.value }))} placeholder="Min" /></label><label className="filter-inline grow">Search<input value={caseFilters.search} onChange={(event) => setCaseFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Case, IRIS, asset" /></label></>} /><DataTable columns={[{ key: "case_name", label: "Incident", render: (item) => <button className="inline-link" onClick={() => openCase(item.id)} type="button">{item.case_name}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "score", label: "Score" }, { key: "decision", label: "Decision" }, { key: "workflow_playbook", label: "Workflow" }, { key: "mitre_count", label: "MITRE" }, { key: "cve_count", label: "CVEs" }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={incidentState.items} /><Pagination page={casePage} total={incidentState.total} pageSize={casePageSize} onPageChange={setCasePage} onPageSizeChange={(value) => { setCasePage(1); setCasePageSize(value); }} /></section> : null}
  {externalSection ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow={activeNav.toUpperCase()} title={`${NAV_ITEMS.find((item) => item.id === activeNav)?.label || activeNav} workspace`} actions={<>{activeNav !== "wazuh" ? <button className="ghost-button" onClick={() => syncSource(activeNav)} type="button">{busy === activeNav ? "Syncing..." : "Sync now"}</button> : null}<label className="filter-inline">Severity<select value={sectionState[activeNav].severity} onChange={(event) => updateSection(activeNav, { severity: event.target.value, page: 1 })}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></>} /><DataTable columns={[{ key: "source_id", label: "Source ID" }, { key: "title", label: "Title", render: (item) => <button className="inline-link" onClick={() => setSelectedExternal({ title: item.title, payload: item.raw_payload, type: activeNav })} type="button">{item.title}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={sectionState[activeNav].items} empty={`No ${activeNav} data available yet.`} /><Pagination page={sectionState[activeNav].page} total={sectionState[activeNav].total} pageSize={sectionState[activeNav].pageSize} onPageChange={(value) => updateSection(activeNav, { page: value })} onPageSizeChange={(value) => updateSection(activeNav, { page: 1, pageSize: value })} /></section> : null}

  {activeNav === "mitre" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="MITRE" title="MITRE ATT&CK coverage map" actions={<label className="filter-inline grow">Search<input value={sectionState.mitre.search} onChange={(event) => updateSection("mitre", { search: event.target.value, page: 1 })} placeholder="Tactic, technique, ID" /></label>} /><DataTable columns={[{ key: "external_id", label: "Technique" }, { key: "name", label: "Name", render: (item) => <button className="inline-link" onClick={() => setSelectedMitre(item)} type="button">{item.name}</button> }, { key: "tactics", label: "Tactics", render: (item) => item.tactics.join(", ") || "-" }, { key: "platforms", label: "Platforms", render: (item) => item.platforms.join(", ") || "-" }]} rows={sectionState.mitre.items} /><Pagination page={sectionState.mitre.page} total={sectionState.mitre.total} pageSize={sectionState.mitre.pageSize} onPageChange={(value) => updateSection("mitre", { page: value })} onPageSizeChange={(value) => updateSection("mitre", { page: 1, pageSize: value })} /></section> : null}

  {activeNav === "discussion" ? <section className="panel firebase-card page-panel discussion-panel"><PanelHeader eyebrow="Discussion" title="Cybersecurity engineering assistant" actions={<span className="mini-badge">Assistant</span>} /><div className="chat-thread">{chatMessages.map((message, index) => <article key={`${message.role}-${index}`} className={`chat-bubble ${message.role}`}><span>{message.role === "assistant" ? "H-Brain" : "You"}</span><p>{message.content}</p></article>)}{busy === "chat" ? <article className="chat-bubble assistant"><span>H-Brain</span><p>Analyzing your request...</p></article> : null}</div><form className="chat-form" onSubmit={handleChatSubmit}><textarea value={chatDraft} onChange={(event) => setChatDraft(event.target.value)} placeholder="Ask about triage, containment, threat hunting, Wazuh, MISP, Cortex, IRIS, MITRE, or banking incident response." /><button type="submit">Send to H-Brain</button></form></section> : null}

  {activeNav === "settings" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Settings" title="Connector and operator configuration" /><form className="settings-grid" onSubmit={saveSettings}><label>Dashboard Email<input value={settingsForm.dashboard_email} onChange={(event) => setSettingsForm((current) => ({ ...current, dashboard_email: event.target.value }))} /></label><label>Notification Email<input value={settingsForm.notification_email} onChange={(event) => setSettingsForm((current) => ({ ...current, notification_email: event.target.value }))} /></label><label>MISP URL<input value={settingsForm.misp_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_base_url: event.target.value }))} /></label><label>MISP API Key<input value={settingsForm.misp_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_api_key: event.target.value }))} /></label><label>Cortex URL<input value={settingsForm.cortex_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_base_url: event.target.value }))} /></label><label>Cortex API Key<input value={settingsForm.cortex_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_api_key: event.target.value }))} /></label><label>IRIS URL<input value={settingsForm.iris_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_base_url: event.target.value }))} /></label><label>IRIS API Key<input value={settingsForm.iris_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_api_key: event.target.value }))} /></label><label>Ollama Base URL<input value={settingsForm.ollama_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_base_url: event.target.value }))} /></label><label>Ollama Model<input value={settingsForm.ollama_model} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_model: event.target.value }))} /></label><label>Current Password<input type="password" value={settingsForm.current_password} onChange={(event) => setSettingsForm((current) => ({ ...current, current_password: event.target.value }))} /></label><label>New Password<input type="password" value={settingsForm.new_password} onChange={(event) => setSettingsForm((current) => ({ ...current, new_password: event.target.value }))} /></label><div className="settings-actions"><button type="submit">{busy === "settings" ? "Saving..." : "Save configuration"}</button><div className="settings-hint"><span>Stored in database</span><strong>Wazuh remains HTTP-ingest only</strong></div></div></form></section> : null}
</main>{selectedCase ? <div className="modal-shell" onClick={() => setSelectedCase(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={`${selectedCase.severity.toUpperCase()} · ${selectedCase.score}/100 · ${selectedCase.decision.toUpperCase()}`} title={selectedCase.case_name} actions={<button className="ghost-button" onClick={() => setSelectedCase(null)} type="button">Close</button>} /><p className="lede">{selectedCase.summary}</p><div className="summary-grid"><div><span>Asset</span><strong>{selectedCase.asset_name}</strong></div><div><span>IRIS Case</span><strong>{selectedCase.iris_case_name || "Not linked"}</strong></div><div><span>Workflow</span><strong>{selectedCase.workflow_playbook}</strong></div><div><span>Score Model</span><strong>{selectedCase.score_model}</strong></div></div><DetailsBlock title="Recommendation" value={selectedCase.recommendation_body} open /><DetailsBlock title="MISP Event" value={selectedCase.raw_payload?.misp_event || {}} /><DetailsBlock title="Wazuh Alert" value={selectedCase.raw_payload?.wazuh_alert || {}} /><DetailsBlock title="Cortex Analysis" value={selectedCase.raw_payload?.cortex_analysis || {}} /><DetailsBlock title="MITRE ATT&CK" value={selectedCase.mitre_attacks || []} /><DetailsBlock title="CVEs" value={selectedCase.cves || []} /><DetailsBlock title="IOCs" value={selectedCase.iocs || []} /><DetailsBlock title="PKIs" value={selectedCase.pkis || []} /><DetailsBlock title="Email Payload" value={selectedCase.email_payload || {}} /><DetailsBlock title="Normalized Request" value={selectedCase.normalized_payload || {}} /></div></div> : null}{selectedExternal ? <div className="modal-shell" onClick={() => setSelectedExternal(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedExternal.type.toUpperCase()} title={selectedExternal.title} actions={<button className="ghost-button" onClick={() => setSelectedExternal(null)} type="button">Close</button>} /><DetailsBlock title="Raw Payload" value={selectedExternal.payload} open /></div></div> : null}{selectedMitre ? <div className="modal-shell" onClick={() => setSelectedMitre(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedMitre.external_id} title={selectedMitre.name} actions={<button className="ghost-button" onClick={() => setSelectedMitre(null)} type="button">Close</button>} /><p className="lede">{selectedMitre.description}</p><div className="summary-grid"><div><span>Tactics</span><strong>{selectedMitre.tactics.join(", ") || "-"}</strong></div><div><span>Platforms</span><strong>{selectedMitre.platforms.join(", ") || "-"}</strong></div><div><span>Reference</span><strong>{selectedMitre.url || "-"}</strong></div></div><DetailsBlock title="Detection Guidance" value={selectedMitre.detection || "No detection guidance available."} open /></div></div> : null}</div>;
}

export default App;
