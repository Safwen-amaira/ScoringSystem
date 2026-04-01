import { useEffect, useMemo, useRef, useState } from "react";

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
  { id: "cves", label: "CVE Database", icon: "intel" },
  { id: "discussion", label: "H-Brain Assistant", icon: "chat" },
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
    robot: <path d="M12 2a2 2 0 0 1 2 2h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h4a2 2 0 0 1 2-2zM9 13v.01M15 13v.01M9 16h6" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
    copy: <g><path d="M8 4v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7.242a2 2 0 0 0-.602-1.43L16.083 2.57A2 2 0 0 0 14.685 2H10a2 2 0 0 0-2 2z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /><path d="M16 18v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h2" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></g>,
    refresh: <path d="M1 4v6h6M23 20v-6h-6M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
  };
  return <svg viewBox="0 0 24 24" className="icon">{paths[name] || paths.grid}</svg>;
}

function severityTone(value) {
  return `severity-${(value || "low").toLowerCase()}`;
}

function severityColor(value) {
  return ({ critical: "var(--critical-dark)", high: "var(--high-red)", medium: "var(--gold-primary)", low: "var(--low-green)" }[(value || "low").toLowerCase()] || "var(--low-green)");
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

function TrendChart({ points, labels, items = [] }) {
  const safe = (points.length ? points : [42, 58, 51, 66, 61, 74, 68, 80]);
  const safeLabels = (labels.length ? labels : ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]);
  const max = Math.max(...safe, 1);
  const mapped = safe.map((value, index) => {
    const originalIndex = items.length - 1 - index;
    const item = items[originalIndex];
    return {
      value,
      x: 50 + index * ((700 - 100) / Math.max(1, safe.length - 1)),
      y: 240 - (value / max) * 150,
      label: safeLabels[index] || `D${index + 1}`,
      severity: item?.severity || "low"
    };
  });
  const line = mapped.map((point) => `${point.x},${point.y}`).join(" ");
  const area = `50,250 ${line} 700,250`;
  const [hovered, setHovered] = useState(null);
  const [tooltip, setTooltip] = useState({ x: 0, y: 0 });

  const handleMouseMove = (event) => {
    const box = event.currentTarget.getBoundingClientRect();
    const x = event.clientX - box.left;
    const y = event.clientY - box.top;
    setTooltip({ x, y });

    // Find nearest point
    const svgX = (x / box.width) * 760;
    const closest = mapped.reduce((prev, curr) => (Math.abs(curr.x - svgX) < Math.abs(prev.x - svgX) ? curr : prev));
    setHovered(closest);
  };

  return <div className="interactive-chart"><svg viewBox="0 0 760 280" preserveAspectRatio="none" className="trend-chart-svg" onMouseLeave={() => setHovered(null)} onMouseMove={handleMouseMove}>{[0, 1, 2, 3].map((row) => <line key={row} x1="50" x2="700" y1={70 + row * 45} y2={70 + row * 45} className="chart-grid-line" />)}<path d={`M ${area}`} className="chart-area-primary" /><polyline points={line} className="chart-line-primary" />{mapped.map((point, i) => {
    const isFirstOrDifferent = i === 0 || point.label !== mapped[i - 1].label;
    return <g key={i}><circle cx={point.x} cy={point.y} r="5.5" className="chart-dot" style={{ opacity: hovered?.severity === point.severity && hovered?.value === point.value ? 1 : 0.4 }} />{isFirstOrDifferent && <text x={point.x} y="268" textAnchor="middle" className="chart-x-label">{point.label}</text>}</g>;
  })}</svg>{hovered ? <div className="chart-tooltip floating precise-tooltip" style={{ left: tooltip.x, top: tooltip.y - 10 }}><strong>Score: {hovered.value}</strong><div style={{ fontSize: "0.85rem", opacity: 0.9, color: severityColor(hovered.severity), fontWeight: 700, marginTop: "0.2rem" }}>Severity: {hovered.severity.toUpperCase()}</div></div> : null}</div>;
}

function SourceBars({ items }) {
  const max = Math.max(...items.map((item) => item.value), 1);
  return <div className="source-bars">{items.map((item) => <button key={item.label} className="source-bar-row" type="button" title={`${item.label}: ${item.value}`}><div><strong>{item.label}</strong><span>{item.subtitle}</span></div><div className="source-bar-track"><span className="source-bar-fill" style={{ width: `${(item.value / max) * 100}%` }} /></div><em>{item.value}</em></button>)}</div>;
}

function HeatmapCard({ items }) {
  const gridCount = Math.max(364, Math.ceil(items.length / 7) * 7);
  const grid = Array.from({ length: gridCount }, (_, index) => {
    const item = items[index];
    return item ? { severity: item.severity, title: item.case_name || item.title || "Incident", score: item.score } : { severity: "empty" };
  });

  return (
    <div>
      <div className="severity-heatmap enhanced" style={{ gridTemplateColumns: `repeat(${Math.ceil(gridCount / 7)}, 1fr)` }}>
        {grid.map((cell, index) => (
          <button
            key={index}
            className={`heatmap-cell ${cell.severity}`}
            title={cell.severity !== "empty" ? `${cell.title} | Score: ${cell.score} | Severity: ${cell.severity}` : "No activity"}
            type="button"
          />
        ))}
      </div>
      <div className="severity-legend compact">
        {["critical", "high", "medium", "low"].map((level) => (
          <span key={level}><i className={level} style={{ backgroundColor: severityColor(level) }} />{level}</span>
        ))}
      </div>
    </div>
  );
}

function TopTargetAssetsCard({ items }) {
  const assets = items.reduce((acc, item) => {
    if (item.asset_name) acc[item.asset_name] = (acc[item.asset_name] || 0) + 1;
    return acc;
  }, {});
  const top = Object.entries(assets).sort((a, b) => b[1] - a[1]).slice(0, 5);
  return (
    <div className="summary-stack" style={{ marginTop: "1rem" }}>
      {top.map(([name, count]) => (
        <div key={name} className="mini-module-card" style={{ padding: "0.85rem", borderRadius: "14px", background: "#0f1114", border: "1px solid var(--line)", marginBottom: "0.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
            <span style={{ fontSize: "0.85rem", color: "var(--muted)" }}>{name}</span>
            <strong style={{ color: "var(--gold-primary)", fontSize: "0.95rem" }}>{count} cases</strong>
          </div>
        </div>
      ))}
    </div>
  );
}

function RingChart({ value, label }) {
  const pct = Math.max(0, Math.min(100, Math.round(value || 0)));
  return <div className="ring-card"><div className="ring-meter" style={{ background: `conic-gradient(var(--gold-primary) ${pct}%, var(--bg-elevated) ${pct}% 100%)` }}><div><span>{label}</span><strong>{pct}%</strong></div></div></div>;
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
  const [pulseActive, setPulseActive] = useState(false);
  const notificationRef = useRef(null);
  const profileRef = useRef(null);
  const chatThreadRef = useRef(null);
  const autoScrollRef = useRef(true);
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
  const chatScrollRef = useRef(null);
  const [showCreateMisp, setShowCreateMisp] = useState(false);
  const [showCreateCortex, setShowCreateCortex] = useState(false);
  const [showCreateIris, setShowCreateIris] = useState(false);
  const [createForm, setCreateForm] = useState({ title: "", severity: "2", description: "", analyzer_id: "VirusTotal", data_type: "ip", data: "" });
  const stats = useMemo(() => overview ? [{ label: "Critical Queue", value: overview.critical_cases, meta: "Needs action" }, { label: "Average Score", value: overview.average_score, meta: "Hybrid model" }, { label: "Unread Alerts", value: overview.unread_notifications, meta: "Notification center" }] : [], [overview]);
  const scoreSeries = useMemo(() => {
    const series = incidentState.items.map((item) => item.score).reverse();
    return series.length ? series : [38, 61, 49, 68, 58, 72, 66, 81];
  }, [incidentState.items]);
  const scoreLabels = useMemo(() => incidentState.items.slice().reverse().map((item) => new Date(item.created_at).toLocaleDateString(undefined, { month: "short", day: "numeric" })), [incidentState.items]);
  const sourcePulse = useMemo(() => [{ label: "Wazuh", value: sectionState.wazuh.total || 4, subtitle: "Detection pipeline" }, { label: "Cortex", value: sectionState.cortex.total || 3, subtitle: "Analyzer jobs" }, { label: "MISP", value: sectionState.misp.total || 2, subtitle: "Threat intel events" }, { label: "IRIS", value: sectionState.iris.total || 2, subtitle: "Case linkage" }], [sectionState]);
  const severityMix = useMemo(() => ({ critical: incidentState.items.filter((item) => item.severity === "critical").length, high: incidentState.items.filter((item) => item.severity === "high").length, medium: incidentState.items.filter((item) => item.severity === "medium").length, low: incidentState.items.filter((item) => item.severity === "low").length }), [incidentState.items]);
  const latestCases = overview?.latest_cases || [];
  const externalSection = ["wazuh", "cortex", "misp", "iris"].includes(activeNav);
  const coverageValue = useMemo(() => Math.min(100, Math.round(((overview?.cve_matches || 0) + (overview?.total_cases || 0)) * 4)), [overview]);
  const isDiscussion = activeNav === "discussion";

  useEffect(() => {
    if (!token) return undefined;
    bootstrap(token);
    const timer = window.setInterval(() => {
      bootstrap(token, true);
      setPulseActive(true);
      setTimeout(() => setPulseActive(false), 2000);
    }, 15000);
    return () => window.clearInterval(timer);
  }, [token, activeNav, casePage, casePageSize, cvePage, cvePageSize, caseFilters, sectionState.wazuh.page, sectionState.wazuh.pageSize, sectionState.wazuh.severity, sectionState.cortex.page, sectionState.cortex.pageSize, sectionState.cortex.severity, sectionState.misp.page, sectionState.misp.pageSize, sectionState.misp.severity, sectionState.iris.page, sectionState.iris.pageSize, sectionState.iris.severity, sectionState.mitre.page, sectionState.mitre.pageSize, sectionState.mitre.search]);

  useEffect(() => {
    if (!token || activeNav !== "discussion" || chatMessages.length) return;
    sendChat([], true);
  }, [token, activeNav]);

  useEffect(() => {
    function handlePointerDown(event) {
      if (notificationRef.current && !notificationRef.current.contains(event.target)) setShowNotifications(false);
      if (profileRef.current && !profileRef.current.contains(event.target)) setShowProfileMenu(false);
    }
    document.addEventListener("mousedown", handlePointerDown);
    return () => document.removeEventListener("mousedown", handlePointerDown);
  }, []);

  useEffect(() => {
    if (!chatScrollRef.current || !autoScrollRef.current) return;
    chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
  }, [chatMessages, busy]);

  function renderFormatted(text) {
    if (!text) return null;
    const lines = text.split("\n");
    return lines.map((line, i) => {
      if (line.startsWith("# ")) {
        return <h3 key={i}>{line.replace("# ", "")}</h3>;
      }
      const parts = line.split(/(\*\*.*?\*\*)/g);
      return (
        <p key={i}>
          {parts.map((part, j) => {
            if (part.startsWith("**") && part.endsWith("**")) {
              return <strong key={j}>{part.slice(2, -2)}</strong>;
            }
            return part;
          })}
        </p>
      );
    });
  }

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
      const isOverview = activeNav === "overview";
      const caseQuery = new URLSearchParams({ page: String(casePage), page_size: isOverview ? "200" : String(casePageSize) });
      if (caseFilters.severity) caseQuery.set("severity", caseFilters.severity);
      if (caseFilters.decision) caseQuery.set("decision", caseFilters.decision);
      if (caseFilters.minScore) caseQuery.set("min_score", caseFilters.minScore);
      if (caseFilters.search) caseQuery.set("search", caseFilters.search);
      const payloads = await Promise.all([
        api("/api/dashboard/overview", activeToken),
        api(`/api/dashboard/cases?${caseQuery.toString()}`, activeToken),
        api(`/api/dashboard/cves?page=${isOverview ? "1" : String(cvePage)}&page_size=${isOverview ? "100" : String(cvePageSize)}`, activeToken),
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

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    // Simple visual feedback could be added here if needed
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

  async function markAllNotificationsRead() {
    await api("/api/dashboard/notifications/read-all", token, { method: "POST" });
    await bootstrap(token, true);
    setShowNotifications(false);
  }

  async function syncSource(source) {
    const routeMap = { cortex: "/api/dashboard/cortex/sync", misp: "/api/dashboard/misp/sync", iris: "/api/dashboard/iris/sync", cves: "/api/dashboard/cves/sync" };
    setBusy(source);
    try {
      await api(routeMap[source], token, { method: "POST" });
      await bootstrap(token, true);
    } finally {
      setBusy("");
    }
  }

  async function handleCreateEntity(type) {
    const routeMap = { misp: "/api/dashboard/misp/create", cortex: "/api/dashboard/cortex/create", iris: "/api/dashboard/iris/create" };
    const bodyMap = {
      misp: { title: createForm.title, threat_level_id: Number(createForm.severity) },
      cortex: { analyzer_id: createForm.analyzer_id, data_type: createForm.data_type, data: createForm.data },
      iris: { title: createForm.title, severity_id: Number(createForm.severity), description: createForm.description }
    };
    setBusy(type);
    try {
      await api(routeMap[type], token, { method: "POST", body: JSON.stringify(bodyMap[type]) });
      setShowCreateMisp(false);
      setShowCreateCortex(false);
      setShowCreateIris(false);
      setCreateForm({ title: "", severity: "2", description: "", analyzer_id: "VirusTotal", data_type: "ip", data: "" });
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
    } catch (error) {
      if (!introOnly) {
        setChatMessages(prev => [...prev, { role: "assistant", content: "I encountered an issue connecting to the core engine. Please ensure Ollama is running and the Qwen model is loaded." }]);
      }
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
    await sendChat(nextMessages.slice(-6));
  }

  if (!token) {
    return <div className="login-screen"><div className="login-card"><img src="https://hanicar.tn/logo.png" alt="Hanicar Security" className="login-logo" /><p className="eyebrow">Hanicar Security</p><h1>H-Brain</h1><p className="lede">Production-ready CTI, SOC operations, enrichment, and banking-grade incident scoring.</p><form onSubmit={handleLogin}><div className="input-lock"><label>Email</label><input value={DEFAULT_EMAIL} readOnly /></div><div className="input-lock"><label>Password</label><input value={DEFAULT_PASSWORD} readOnly type="password" /></div><button type="submit">Launch H-Brain</button></form>{loginError ? <p className="error-text">{loginError}</p> : null}</div></div>;
  }
  return <div className="firebase-shell exact-shell"><aside className="sidebar firebase-sidebar exact-sidebar"><div className="sidebar-scroll"><div className="brand-block brand-logo-block"><img src="https://hanicar.tn/logo.png" alt="Hanicar Security" className="brand-logo" /><div><p className="eyebrow">Hanicar Security</p><h2>H-Brain</h2></div></div><p className="nav-caption">Main Menu</p><nav className="main-nav">{NAV_ITEMS.map((item) => <button key={item.id} className={`nav-item ${activeNav === item.id ? "active" : ""}`} onClick={() => { setActiveNav(item.id); setShowProfileMenu(false); }} type="button"><Icon name={item.icon} /><span>{item.label}</span></button>)}</nav><div className="sidebar-lower-links"></div></div></aside><main className={`firebase-main exact-main ${isDiscussion ? "discussion-mode" : ""}`}>{!isDiscussion ? <><header className="topbar exact-topbar"><div><p className="eyebrow">Operational Console</p><h1>{activeNav === "overview" ? "Overview" : NAV_ITEMS.find((item) => item.id === activeNav)?.label}</h1><p className="lede">Realtime CTI and SOC workspace for banking incident response.</p></div><div className="topbar-actions compact-actions"><div className="notification-group" ref={notificationRef}><button className="icon-button" onClick={() => { setShowNotifications((current) => !current); setShowProfileMenu(false); }} type="button"><Icon name="bell" /><span>{notifications.total}</span></button>{showNotifications ? <div className="notification-popover scrollable-dropdown"><div className="dropdown-header"><div><strong>Notifications</strong><small>{notifications.total} unread or active</small></div><button className="ghost-button tiny-button" onClick={markAllNotificationsRead} type="button">Mark all read</button></div>{notifications.items.length ? notifications.items.map((item) => <button key={item.id} className={`notification-item ${item.is_read ? "read" : ""}`} onClick={() => markNotificationAndOpen(item)} type="button"><strong>{item.title}</strong><span>{item.body}</span><small>{item.severity.toUpperCase()} · {formatDate(item.created_at)}</small></button>) : <p className="empty-note">No notifications available.</p>}</div> : null}</div><div className="profile-group" ref={profileRef}><button className="avatar-chip dropdown-trigger" onClick={() => { setShowProfileMenu((current) => !current); setShowNotifications(false); }} type="button"><img src="https://hanicar.tn/logo.png" alt="Hanicar avatar" /><span>Admin</span><Icon name="chevron" /></button>{showProfileMenu ? <div className="profile-menu"><button type="button" onClick={() => { setActiveNav("settings"); setShowProfileMenu(false); }}>Settings</button><button type="button" onClick={logout}>Logout</button></div> : null}</div></div></header>{activeNav === "overview" ? <section className="stats-grid firebase-stats exact-stats">{stats.map((stat) => <article key={stat.label} className="stat-card firebase-card exact-stat-card"><span>{stat.label}</span><strong>{stat.value}</strong><small>{stat.meta}</small></article>)}</section> : null}</> : null}

    {activeNav === "overview" ? <><section className="overview-grid overview-primary-grid"><article className="panel firebase-card hero-panel"><div className="hero-header"><div><p className="eyebrow">Risk movement</p><h3>Total Incident Pressure</h3></div><div className="hero-switches"></div></div><TrendChart points={scoreSeries} labels={scoreLabels} items={incidentState.items} /></article><article className="panel firebase-card summary-stack"><PanelHeader eyebrow="Response" title="Containment posture" /><div style={{ flex: 1, display: "grid", placeItems: "center" }}><RingChart value={coverageValue} label="Intel coverage" /></div></article></section><section className="overview-grid overview-secondary-grid" style={{ gridTemplateColumns: "1.4fr 1fr 1fr" }}><article className="panel firebase-card heatmap-panel"><PanelHeader eyebrow="Intensity map" title="Operational map" /><HeatmapCard items={incidentState.items} /></article><article className="panel firebase-card"><PanelHeader eyebrow="Targeting" title="Top targeted assets" /><TopTargetAssetsCard items={incidentState.items} /></article><article className="panel firebase-card"><PanelHeader eyebrow="Distribution" title="Pipeline load" /><SourceBars items={sourcePulse} /></article></section><section className="panel firebase-card page-panel"><PanelHeader eyebrow="Recent incidents" title="Latest response cases" actions={<button className="ghost-button" onClick={() => setActiveNav("incidents")} type="button">Open incident desk</button>} /><DataTable columns={[{ key: "case_name", label: "Incident", render: (item) => <button className="inline-link" onClick={() => openCase(item.id)} type="button">{item.case_name}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "score", label: "Score" }, { key: "decision", label: "Decision" }, { key: "workflow_playbook", label: "Workflow" }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={incidentState.items} /></section></> : null}

    {activeNav === "incidents" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Incidents" title="Realtime incident management" actions={<><label className="filter-inline">Severity<select value={caseFilters.severity} onChange={(event) => setCaseFilters((current) => ({ ...current, severity: event.target.value }))}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label className="filter-inline">Decision<select value={caseFilters.decision} onChange={(event) => setCaseFilters((current) => ({ ...current, decision: event.target.value }))}><option value="">All</option><option value="stop">Stop</option><option value="review">Review</option><option value="continue">Continue</option></select></label><label className="filter-inline">Score<input value={caseFilters.minScore} onChange={(event) => setCaseFilters((current) => ({ ...current, minScore: event.target.value }))} placeholder="Min" /></label><label className="filter-inline grow">Search<input value={caseFilters.search} onChange={(event) => setCaseFilters((current) => ({ ...current, search: event.target.value }))} placeholder="Case, IRIS, asset" /></label></>} /><DataTable columns={[{ key: "case_name", label: "Incident", render: (item) => <button className="inline-link" onClick={() => openCase(item.id)} type="button">{item.case_name}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "score", label: "Score" }, { key: "decision", label: "Decision" }, { key: "workflow_playbook", label: "Workflow" }, { key: "mitre_count", label: "MITRE" }, { key: "cve_count", label: "CVEs" }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={incidentState.items} /><Pagination page={casePage} total={incidentState.total} pageSize={casePageSize} onPageChange={setCasePage} onPageSizeChange={(value) => { setCasePage(1); setCasePageSize(value); }} /></section> : null}
    {externalSection ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow={activeNav.toUpperCase()} title={`${NAV_ITEMS.find((item) => item.id === activeNav)?.label || activeNav} workspace`} actions={<>{activeNav !== "wazuh" ? <><button className="ghost-button" onClick={() => syncSource(activeNav)} type="button">{busy === activeNav ? "Syncing..." : "Sync now"}</button><button className="send-btn" onClick={() => { if (activeNav === "misp") setShowCreateMisp(true); else if (activeNav === "cortex") setShowCreateCortex(true); else if (activeNav === "iris") setShowCreateIris(true); }} style={{ height: "36px", padding: "0 1rem", borderRadius: "8px" }} type="button">Create New</button></> : null}<label className="filter-inline">Severity<select value={sectionState[activeNav].severity} onChange={(event) => updateSection(activeNav, { severity: event.target.value, page: 1 })}><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></>} /><DataTable columns={[{ key: "source_id", label: "Source ID" }, { key: "title", label: "Title", render: (item) => <button className="inline-link" onClick={() => setSelectedExternal({ title: item.title, payload: item.raw_payload, type: activeNav })} type="button">{item.title}</button> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "created_at", label: "Time", render: (item) => formatDate(item.created_at) }]} rows={sectionState[activeNav].items} empty={`No ${activeNav} data available yet.`} /><Pagination page={sectionState[activeNav].page} total={sectionState[activeNav].total} pageSize={sectionState[activeNav].pageSize} onPageChange={(value) => updateSection(activeNav, { page: value })} onPageSizeChange={(value) => updateSection(activeNav, { page: 1, pageSize: value })} /></section> : null}

    {activeNav === "mitre" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="MITRE" title="MITRE ATT&CK coverage map" actions={<label className="filter-inline grow">Search<input value={sectionState.mitre.search} onChange={(event) => updateSection("mitre", { search: event.target.value, page: 1 })} placeholder="Tactic, technique, ID" /></label>} /><DataTable columns={[{ key: "external_id", label: "Technique" }, { key: "name", label: "Name", render: (item) => <button className="inline-link" onClick={() => setSelectedMitre(item)} type="button">{item.name}</button> }, { key: "tactics", label: "Tactics", render: (item) => item.tactics.join(", ") || "-" }, { key: "platforms", label: "Platforms", render: (item) => item.platforms.join(", ") || "-" }]} rows={sectionState.mitre.items} /><Pagination page={sectionState.mitre.page} total={sectionState.mitre.total} pageSize={sectionState.mitre.pageSize} onPageChange={(value) => updateSection("mitre", { page: value })} onPageSizeChange={(value) => updateSection("mitre", { page: 1, pageSize: value })} /></section> : null}
    {activeNav === "cves" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Intelligence" title="CVE Vulnerability database" actions={<><button className="ghost-button" onClick={() => syncSource("cves")} type="button">{busy === "cves" ? "Syncing..." : "Sync now"}</button><div className="mini-badge">{cves.total} entries</div></>} /><DataTable columns={[{ key: "id", label: "CVE ID", render: (item) => <strong style={{ color: "var(--accent-primary)" }}>{item.cve_id}</strong> }, { key: "severity", label: "Severity", render: (item) => <span className={`severity-pill ${severityTone(item.severity)}`}>{item.severity}</span> }, { key: "cvss", label: "CVSS", render: (item) => item.cvss || "N/A" }, { key: "summary", label: "Description", render: (item) => <div style={{ fontSize: "0.85rem", color: "var(--muted)", maxWidth: "500px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={item.summary}>{item.summary}</div> }, { key: "published", label: "Published", render: (item) => formatDate(item.published) }]} rows={cves.items} empty="No CVE data synchronized." /><Pagination page={cvePage} total={cves.total} pageSize={cvePageSize} onPageChange={setCvePage} onPageSizeChange={(value) => { setCvePage(1); setCvePageSize(value); }} /></section> : null}

    {activeNav === "discussion" ? <section className="panel firebase-card page-panel discussion-panel premium-chat hubspot-shell"><div className="chat-interface"><header className="hubspot-chat-header"><div className="header-left"><h3>H-Brain Analysis</h3><Icon name="chevron" /><span className="badge-pill private-badge"><Icon name="lock" />Private</span></div><div className="header-right"></div></header><div className="chat-thread hubspot-thread" ref={chatScrollRef} onScroll={(event) => { const node = event.currentTarget; autoScrollRef.current = node.scrollHeight - node.scrollTop - node.clientHeight < 48; }}><div className="chat-content-container">{chatMessages.map((message, index) => {
      const isAssistant = message.role === "assistant";
      let thought = null;
      let answer = message.content;
      if (isAssistant) {
        const match = message.content.match(/<thought>([\s\S]*?)<\/thought>/);
        if (match) {
          thought = match[1].trim();
          answer = message.content.replace(/<thought>[\s\S]*?<\/thought>/, "").trim();
        }
      }
      return <article key={`${message.role}-${index}`} className={`message-row hubspot-row ${message.role}`}><div className="message-avatar">{isAssistant && <img src={LOGO_URL} alt="H-Brain" />}</div><div className="message-body">{thought ? <div className="hubspot-analysis-block"><button className="analysis-pill"><Icon name="pulse" />Analysis steps<Icon name="chevron-right" /></button><div className="connected-chips"><span className="data-chip"><Icon name="intel" />IOC Database</span><span className="data-chip"><Icon name="file" />Incident_Report.pdf</span></div></div> : null}<div className="message-text">{renderFormatted(answer)}</div></div>{!isAssistant && <div className="user-initials">AS</div>}</article>;
    })}{busy === "chat" ? <article className="message-row hubspot-row assistant loading"><div className="message-avatar"><img src={LOGO_URL} alt="H-Brain" /></div><div className="message-body"><div className="hubspot-analysis-block"><button className="analysis-pill pulsing"><Icon name="pulse" />Analyzing SOC telemetry...</button></div><div className="shimmering-bar" /></div></article> : null}</div></div><div className="hubspot-input-container"><div className="input-tag-row"><span className="input-tag">H-Brain by <a href="https://hanicar.tn" style={{ textDecoration: "none", color: "white" }}>Hanicar Security</a></span></div><form className="hubspot-input-pill" onSubmit={handleChatSubmit}><textarea value={chatDraft} onChange={(event) => setChatDraft(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); handleChatSubmit(event); } }} placeholder="Ask H-Brain Security Assistant..." /><div className="hubspot-toolbar"><div className="toolbar-left"><button type="button" className="tool-circle"><Icon name="plus" /></button><button type="button" className="content-assistant-badge">Security Assistant <small>Beta</small></button><button type="button" className="tool-icon"><Icon name="search" /></button></div><div className="toolbar-right"><button type="button" className="tool-icon"><Icon name="mic" /></button><button type="submit" className="hubspot-send-btn" disabled={busy === "chat" || !chatDraft.trim()}><Icon name="arrow-up" /></button></div></div></form></div></div></section> : null}

    {activeNav === "settings" ? <section className="panel firebase-card page-panel"><PanelHeader eyebrow="Settings" title="Connector and operator configuration" /><form className="settings-grid" onSubmit={saveSettings}><label>Dashboard Email<input value={settingsForm.dashboard_email} onChange={(event) => setSettingsForm((current) => ({ ...current, dashboard_email: event.target.value }))} /></label><label>Notification Email<input value={settingsForm.notification_email} onChange={(event) => setSettingsForm((current) => ({ ...current, notification_email: event.target.value }))} /></label><label>MISP URL<input value={settingsForm.misp_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_base_url: event.target.value }))} /></label><label>MISP API Key<input value={settingsForm.misp_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, misp_api_key: event.target.value }))} /></label><label>Cortex URL<input value={settingsForm.cortex_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_base_url: event.target.value }))} /></label><label>Cortex API Key<input value={settingsForm.cortex_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, cortex_api_key: event.target.value }))} /></label><label>IRIS URL<input value={settingsForm.iris_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_base_url: event.target.value }))} /></label><label>IRIS API Key<input value={settingsForm.iris_api_key} onChange={(event) => setSettingsForm((current) => ({ ...current, iris_api_key: event.target.value }))} /></label><label>Ollama Base URL<input value={settingsForm.ollama_base_url} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_base_url: event.target.value }))} /></label><label>Ollama Model<input value={settingsForm.ollama_model} onChange={(event) => setSettingsForm((current) => ({ ...current, ollama_model: event.target.value }))} /></label><label>Current Password<input type="password" value={settingsForm.current_password} onChange={(event) => setSettingsForm((current) => ({ ...current, current_password: event.target.value }))} /></label><label>New Password<input type="password" value={settingsForm.new_password} onChange={(event) => setSettingsForm((current) => ({ ...current, new_password: event.target.value }))} /></label><div className="settings-actions"><button type="submit">{busy === "settings" ? "Saving..." : "Save configuration"}</button><div className="settings-hint"><span>Stored in database</span><strong>Wazuh remains HTTP-ingest only</strong></div></div></form></section> : null}
  </main>{selectedCase ? <div className="modal-shell" onClick={() => setSelectedCase(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={`${selectedCase.severity.toUpperCase()} · ${selectedCase.score}/100 · ${selectedCase.decision.toUpperCase()}`} title={selectedCase.case_name} actions={<button className="ghost-button" onClick={() => setSelectedCase(null)} type="button">Close</button>} /><p className="lede">{selectedCase.summary}</p><div className="summary-grid"><div><span>Asset</span><strong>{selectedCase.asset_name}</strong></div><div><span>IRIS Case</span><strong>{selectedCase.iris_case_name || "Not linked"}</strong></div><div><span>Workflow</span><strong>{selectedCase.workflow_playbook}</strong></div><div><span>Score Model</span><strong>{selectedCase.score_model}</strong></div></div><DetailsBlock title="Recommendation" value={selectedCase.recommendation_body} open /><DetailsBlock title="MISP Event" value={selectedCase.raw_payload?.misp_event || {}} /><DetailsBlock title="Wazuh Alert" value={selectedCase.raw_payload?.wazuh_alert || {}} /><DetailsBlock title="Cortex Analysis" value={selectedCase.raw_payload?.cortex_analysis || {}} /><DetailsBlock title="MITRE ATT&CK" value={selectedCase.mitre_attacks || []} /><DetailsBlock title="CVEs" value={selectedCase.cves || []} /><DetailsBlock title="IOCs" value={selectedCase.iocs || []} /><DetailsBlock title="PKIs" value={selectedCase.pkis || []} /><DetailsBlock title="Email Payload" value={selectedCase.email_payload || {}} /><DetailsBlock title="Normalized Request" value={selectedCase.normalized_payload || {}} /></div></div> : null}{selectedExternal ? <div className="modal-shell" onClick={() => setSelectedExternal(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedExternal.type.toUpperCase()} title={selectedExternal.title} actions={<button className="ghost-button" onClick={() => setSelectedExternal(null)} type="button">Close</button>} /><DetailsBlock title="Raw Payload" value={selectedExternal.payload} open /></div></div> : null}{selectedMitre ? <div className="modal-shell" onClick={() => setSelectedMitre(null)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow={selectedMitre.external_id} title={selectedMitre.name} actions={<button className="ghost-button" onClick={() => setSelectedMitre(null)} type="button">Close</button>} /><p className="lede">{selectedMitre.description}</p><div className="summary-grid"><div><span>Tactics</span><strong>{selectedMitre.tactics.join(", ") || "-"}</strong></div><div><span>Platforms</span><strong>{selectedMitre.platforms.join(", ") || "-"}</strong></div><div><span>Reference</span><strong>{selectedMitre.url || "-"}</strong></div></div><DetailsBlock title="Detection Guidance" value={selectedMitre.detection || "No detection guidance available."} open /></div></div> : null}
    {showCreateMisp && <div className="modal-shell" onClick={() => setShowCreateMisp(false)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow="MISP" title="Create Threat Intel Event" actions={<button className="ghost-button" onClick={() => setShowCreateMisp(false)} type="button">Cancel</button>} /><form className="settings-grid" style={{ marginTop: "1rem" }} onSubmit={(e) => { e.preventDefault(); handleCreateEntity("misp"); }}><label>Event Information (Title)<input value={createForm.title} onChange={(e) => setCreateForm(c => ({ ...c, title: e.target.value }))} required /></label><label>Threat Level<select value={createForm.severity} onChange={(e) => setCreateForm(c => ({ ...c, severity: e.target.value }))}><option value="1">1 - High</option><option value="2">2 - Medium</option><option value="3">3 - Low</option><option value="4">4 - Undefined</option></select></label><div className="settings-actions"><button type="submit">{busy === "misp" ? "Creating..." : "Create Event"}</button></div></form></div></div>}
    {showCreateCortex && <div className="modal-shell" onClick={() => setShowCreateCortex(false)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow="CORTEX" title="Run External Analysis" actions={<button className="ghost-button" onClick={() => setShowCreateCortex(false)} type="button">Cancel</button>} /><form className="settings-grid" style={{ marginTop: "1rem" }} onSubmit={(e) => { e.preventDefault(); handleCreateEntity("cortex"); }}><label>Analyzer ID<input value={createForm.analyzer_id} onChange={(e) => setCreateForm(c => ({ ...c, analyzer_id: e.target.value }))} required /></label><label>Data Type<select value={createForm.data_type} onChange={(e) => setCreateForm(c => ({ ...c, data_type: e.target.value }))}><option value="ip">IP Address</option><option value="domain">Domain</option><option value="hash">File Hash</option><option value="url">URL</option></select></label><label style={{ gridColumn: "1 / -1" }}>Observable Data<input value={createForm.data} onChange={(e) => setCreateForm(c => ({ ...c, data: e.target.value }))} placeholder="e.g. 8.8.8.8" required /></label><div className="settings-actions"><button type="submit">{busy === "cortex" ? "Analyzing..." : "Run Job"}</button></div></form></div></div>}
    {showCreateIris && <div className="modal-shell" onClick={() => setShowCreateIris(false)}><div className="modal-card" onClick={(event) => event.stopPropagation()}><PanelHeader eyebrow="IRIS" title="Open Forensic Case" actions={<button className="ghost-button" onClick={() => setShowCreateIris(false)} type="button">Cancel</button>} /><form className="settings-grid" style={{ marginTop: "1rem" }} onSubmit={(e) => { e.preventDefault(); handleCreateEntity("iris"); }}><label>Case Title<input value={createForm.title} onChange={(e) => setCreateForm(c => ({ ...c, title: e.target.value }))} required /></label><label>Severity ID<select value={createForm.severity} onChange={(e) => setCreateForm(c => ({ ...c, severity: e.target.value }))}><option value="1">1 - Critical</option><option value="2">2 - High</option><option value="3">3 - Medium</option><option value="4">4 - Low</option></select></label><label style={{ gridColumn: "1 / -1" }}>Description<textarea value={createForm.description} onChange={(e) => setCreateForm(c => ({ ...c, description: e.target.value }))} /></label><div className="settings-actions"><button type="submit">{busy === "iris" ? "Opening..." : "Create Case"}</button></div></form></div></div>}
  </div>;
}

export default App;
