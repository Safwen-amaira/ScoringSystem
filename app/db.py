from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .cve import fetch_cve_by_id, fetch_recent_cves
from .models import DashboardCaseDetail, DashboardCaseSummary, DashboardOverview, EmailContentResponse, EvidenceItem, IOCItem, PKIMetric, RecommendationResponse, ScoreBreakdown, ScoringRequest
from .security import default_admin_email, default_admin_password, hash_password, issue_token, verify_password


DB_DIR = Path(os.getenv("HANICAR_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = DB_DIR / "hanicar_cti.db"


def get_connection() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_name TEXT NOT NULL,
                iris_case_name TEXT,
                asset_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                summary TEXT NOT NULL,
                recommendation_subject TEXT NOT NULL,
                recommendation_body TEXT NOT NULL,
                ai_provider TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                normalized_payload TEXT NOT NULL,
                result_payload TEXT NOT NULL,
                email_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                summary TEXT NOT NULL,
                cvss REAL NOT NULL,
                severity TEXT NOT NULL,
                published TEXT,
                modified TEXT,
                references_json TEXT,
                raw_payload TEXT NOT NULL,
                cached_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_cves (
                case_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                PRIMARY KEY(case_id, cve_id),
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );
            """
        )
        _seed_admin(connection)
        connection.commit()


def _seed_admin(connection: sqlite3.Connection) -> None:
    existing = connection.execute("SELECT id FROM users WHERE email = ?", (default_admin_email(),)).fetchone()
    if existing:
        return
    salt, password_hash = hash_password(default_admin_password())
    connection.execute(
        """
        INSERT INTO users (email, display_name, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (default_admin_email(), "Hanicar Admin", salt, password_hash, _now()),
    )


def login(email: str, password: str) -> dict[str, str] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, email, display_name, password_salt, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row or not verify_password(password, row["password_salt"], row["password_hash"]):
            return None

        token = issue_token()
        connection.execute(
            "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token, row["id"], _future(hours=12), _now()),
        )
        connection.commit()
        return {"token": token, "email": row["email"], "display_name": row["display_name"]}


def require_session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT users.id, users.email, users.display_name, sessions.expires_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] < _now():
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
            connection.commit()
            return None
        return dict(row)


def store_case(
    raw_payload: dict[str, Any],
    normalized_request: ScoringRequest,
    result: RecommendationResponse,
    email_payload: EmailContentResponse,
    cve_ids: list[str],
    iris_case_name: str | None,
) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO cases (
                case_name, iris_case_name, asset_name, severity, score, decision, summary,
                recommendation_subject, recommendation_body, ai_provider, raw_payload,
                normalized_payload, result_payload, email_payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_request.title,
                iris_case_name,
                normalized_request.asset_name,
                severity_from_case(result.score, result.decision),
                result.score,
                result.decision,
                result.summary,
                result.recommendation_subject,
                result.recommendation_body,
                result.ai_provider,
                json.dumps(raw_payload),
                json.dumps(normalized_request.model_dump()),
                json.dumps(result.model_dump()),
                json.dumps(email_payload.model_dump()),
                _now(),
            ),
        )
        case_id = int(cursor.lastrowid)
        for cve_id in cve_ids:
            connection.execute("INSERT OR IGNORE INTO case_cves (case_id, cve_id) VALUES (?, ?)", (case_id, cve_id))
        connection.commit()
        return case_id


def upsert_cve(cve: dict[str, Any]) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO cves (cve_id, summary, cvss, severity, published, modified, references_json, raw_payload, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                summary=excluded.summary,
                cvss=excluded.cvss,
                severity=excluded.severity,
                published=excluded.published,
                modified=excluded.modified,
                references_json=excluded.references_json,
                raw_payload=excluded.raw_payload,
                cached_at=excluded.cached_at
            """,
            (
                cve["cve_id"],
                cve["summary"],
                cve["cvss"],
                cve["severity"],
                cve.get("published", ""),
                cve.get("modified", ""),
                cve.get("references", "[]"),
                cve["raw_payload"],
                _now(),
            ),
        )
        connection.commit()


def ensure_cves(cve_ids: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with get_connection() as connection:
        for cve_id in cve_ids:
            row = connection.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
            if not row:
                payload = fetch_cve_by_id(cve_id)
                if payload:
                    upsert_cve(payload)
                    row = connection.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()
            if row:
                results.append(_cve_row_to_dict(row))
    return results


def sync_recent_cves() -> None:
    recent = fetch_recent_cves(limit=120)
    for item in recent:
        upsert_cve(item)


def list_cases(page: int, page_size: int, severity: str | None, decision: str | None, min_score: int | None, search: str | None) -> tuple[list[DashboardCaseSummary], int]:
    filters = ["1=1"]
    params: list[Any] = []
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    if decision:
        filters.append("decision = ?")
        params.append(decision)
    if min_score is not None:
        filters.append("score >= ?")
        params.append(min_score)
    if search:
        filters.append("(case_name LIKE ? OR asset_name LIKE ? OR iris_case_name LIKE ?)")
        token = f"%{search}%"
        params.extend([token, token, token])

    where_clause = " AND ".join(filters)
    offset = (page - 1) * page_size
    with get_connection() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM cases WHERE {where_clause}", params).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT
                cases.*,
                (SELECT COUNT(*) FROM case_cves WHERE case_id = cases.id) AS cve_count,
                json_array_length(json_extract(result_payload, '$.iocs')) AS ioc_count,
                (SELECT COUNT(*) FROM case_mitre WHERE case_id = cases.id) AS mitre_count
            FROM cases
            WHERE {where_clause}
            ORDER BY datetime(created_at) DESC
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()
    return ([_summary_from_row(row) for row in rows], int(total))


def get_case(case_id: int) -> DashboardCaseDetail | None:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            return None
        cve_rows = connection.execute(
            """
            SELECT cves.* FROM cves
            JOIN case_cves ON case_cves.cve_id = cves.cve_id
            WHERE case_cves.case_id = ?
            ORDER BY cves.cvss DESC, cves.cve_id ASC
            """,
            (case_id,),
        ).fetchall()
        mitre_rows = connection.execute(
            """
            SELECT mitre_techniques.* FROM mitre_techniques
            JOIN case_mitre ON case_mitre.technique_id = mitre_techniques.external_id
            WHERE case_mitre.case_id = ?
            ORDER BY mitre_techniques.external_id ASC
            """,
            (case_id,),
        ).fetchall()

    result_payload = json.loads(row["result_payload"])
    return DashboardCaseDetail(
        id=row["id"],
        case_name=row["case_name"],
        iris_case_name=row["iris_case_name"],
        asset_name=row["asset_name"],
        severity=row["severity"],
        score=row["score"],
        decision=row["decision"],
        summary=row["summary"],
        recommendation_subject=row["recommendation_subject"],
        recommendation_body=row["recommendation_body"],
        workflow_playbook=result_payload.get("workflow_playbook") or "Security playbook pending",
        score_model=result_payload.get("score_model") or "hbrain-banking-v1",
        created_at=row["created_at"],
        iocs=result_payload.get("iocs", []),
        pkis=result_payload.get("pkis", []),
        cves=[_cve_row_to_dict(item) for item in cve_rows],
        mitre_attacks=[
            {
                "external_id": item["external_id"],
                "name": item["name"],
                "description": item["description"],
                "tactics": json.loads(item["tactics_json"]),
                "platforms": json.loads(item["platforms_json"]),
                "url": item["url"],
                "detection": item["detection"],
            }
            for item in mitre_rows
        ],
        raw_payload=json.loads(row["raw_payload"]),
        normalized_payload=json.loads(row["normalized_payload"]),
        result_payload=result_payload,
        email_payload=json.loads(row["email_payload"]),
    )


def list_cves(page: int, page_size: int, search: str | None) -> tuple[list[dict[str, Any]], int]:
    filters = ["1=1"]
    params: list[Any] = []
    if search:
        filters.append("(cve_id LIKE ? OR summary LIKE ?)")
        token = f"%{search}%"
        params.extend([token, token])
    where_clause = " AND ".join(filters)
    offset = (page - 1) * page_size
    with get_connection() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM cves WHERE {where_clause}", params).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM cves
            WHERE {where_clause}
            ORDER BY cvss DESC, datetime(cached_at) DESC
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()
    return ([_cve_row_to_dict(row) for row in rows], int(total))


def dashboard_overview() -> DashboardOverview:
    latest_cases, _ = list_cases(page=1, page_size=5, severity=None, decision=None, min_score=None, search=None)
    with get_connection() as connection:
        stats = connection.execute(
            """
            SELECT
                COUNT(*) AS total_cases,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_cases,
                AVG(score) AS average_score,
                SUM(CASE WHEN decision = 'stop' THEN 1 ELSE 0 END) AS open_stop_cases,
                (SELECT COUNT(*) FROM case_cves) AS cve_matches
            FROM cases
            """
        ).fetchone()

    return DashboardOverview(
        total_cases=int(stats["total_cases"] or 0),
        critical_cases=int(stats["critical_cases"] or 0),
        average_score=round(float(stats["average_score"] or 0.0), 1),
        open_stop_cases=int(stats["open_stop_cases"] or 0),
        cve_matches=int(stats["cve_matches"] or 0),
        unread_notifications=0,
        latest_cases=latest_cases,
    )


def seed_demo_case() -> None:
    with get_connection() as connection:
        existing = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    if existing:
        return

    sample_request = ScoringRequest(
        title="IRIS gold image compromise review",
        asset_name="srv-hanicar-core-01",
        workflow_id="wf-seed-001",
        notes="Seeded starter case for Hanicar Security dashboard.",
    )
    sample_result = RecommendationResponse(
        score=91,
        decision="stop",
        allow_workflow_to_continue=False,
        summary="Multiple sources indicate a high-confidence exploitation attempt tied to a known external CVE.",
        ai_generated=False,
        ai_provider="file-agent",
        recommendation_subject="[STOP] Security recommendation for srv-hanicar-core-01 (91/100)",
        recommendation_body="Stop the workflow, contain the host, and escalate to incident response.",
        breakdown=[
            ScoreBreakdown(category="Wazuh alert", score=44.0, rationale="Critical Wazuh rule level detected."),
            ScoreBreakdown(category="MISP enrichment", score=28.0, rationale="Known-bad threat intel matched."),
            ScoreBreakdown(category="Cortex analysis", score=19.0, rationale="Analyzer verdict returned malicious."),
        ],
        evidence=[
            EvidenceItem(source="Wazuh", title="CVE-2024-3400 exploitation pattern", severity="15", value=44.0, details="Seeded demo alert"),
            EvidenceItem(source="MISP", title="Known exploitation infrastructure", severity="threat-level-1", value=28.0, details="Seeded demo event"),
            EvidenceItem(source="Cortex", title="VirusTotal verdict", severity="malicious", value=19.0, details="Seeded demo analysis"),
        ],
        iocs=[
            IOCItem(type="ip", value="198.51.100.10", source="$.wazuh_alert.data.srcip"),
            IOCItem(type="domain", value="malicious.hanicar-demo.net", source="$.misp_event.Event.Attribute[0].value"),
        ],
        pkis=[
            PKIMetric(name="source_coverage", value=3, description="All three telemetry sources contributed."),
            PKIMetric(name="ioc_count", value=2, description="Two unique IOCs were extracted."),
            PKIMetric(name="malicious_signal_count", value=3, description="All contributing sources indicated malicious activity."),
            PKIMetric(name="high_confidence_case", value=1, description="Multiple signals support the case."),
        ],
    )
    sample_email = EmailContentResponse(
        subject=sample_result.recommendation_subject,
        html="<html><body><h1>Seed Case</h1><p>Hanicar Security seeded dashboard case.</p></body></html>",
        text=sample_result.recommendation_body,
        ai_generated=False,
        ai_provider="file-agent",
    )
    sample_raw = {
        "title": sample_request.title,
        "iris_case_name": "IRIS-SEED-001",
        "asset_name": sample_request.asset_name,
        "workflow_id": sample_request.workflow_id,
        "wazuh_alert": {"rule": {"level": 15, "description": "CVE-2024-3400 exploitation pattern"}, "data": {"srcip": "198.51.100.10"}},
        "misp_event": {"Event": {"info": "Known exploitation infrastructure", "Attribute": [{"value": "malicious.hanicar-demo.net"}]}},
        "cortex_analysis": {"analyzerName": "VirusTotal", "summary": {"taxonomies": [{"namespace": "VT", "predicate": "malicious", "value": "high"}]}},
    }
    ensure_cves(["CVE-2024-3400"])
    store_case(sample_raw, sample_request, sample_result, sample_email, ["CVE-2024-3400"], "IRIS-SEED-001")


def _summary_from_row(row: sqlite3.Row) -> DashboardCaseSummary:
    result_payload = json.loads(row["result_payload"])
    return DashboardCaseSummary(
        id=row["id"],
        case_name=row["case_name"],
        iris_case_name=row["iris_case_name"],
        asset_name=row["asset_name"],
        severity=row["severity"],
        score=row["score"],
        decision=row["decision"],
        workflow_playbook=result_payload.get("workflow_playbook") or "Security playbook pending",
        mitre_count=int(row["mitre_count"] or 0),
        created_at=row["created_at"],
        cve_count=int(row["cve_count"] or 0),
        ioc_count=int(row["ioc_count"] or 0),
        ai_provider=row["ai_provider"],
    )


def _cve_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "cve_id": row["cve_id"],
        "summary": row["summary"],
        "cvss": row["cvss"],
        "severity": row["severity"],
        "published": row["published"],
        "modified": row["modified"],
        "references": json.loads(row["references_json"] or "[]"),
    }


def severity_from_case(score: int, decision: str) -> str:
    if decision == "stop" or score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future(hours: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
