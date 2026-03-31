from __future__ import annotations

import json
from typing import Any

from .connectors import fetch_cortex_jobs, fetch_iris_cases, fetch_misp_events
from .db import _now, get_connection
from .mitre import fetch_mitre_bundle
from .models import ExternalItemResponse, NotificationItem, SettingsResponse
from .security import hash_password, verify_password


def init_hbrain_store() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wazuh_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cortex_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS misp_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mitre_techniques (
                external_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                tactics_json TEXT NOT NULL,
                platforms_json TEXT NOT NULL,
                url TEXT NOT NULL,
                detection TEXT NOT NULL,
                cached_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_mitre (
                case_id INTEGER NOT NULL,
                technique_id TEXT NOT NULL,
                PRIMARY KEY(case_id, technique_id)
            );

            CREATE TABLE IF NOT EXISTS iris_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        defaults = {
            "misp_base_url": "",
            "misp_api_key": "",
            "cortex_base_url": "",
            "cortex_api_key": "",
            "iris_base_url": "",
            "iris_api_key": "",
            "notification_email": "admin@hanicar.tn",
            "dashboard_email": "admin@hanicar.tn",
            "ollama_model": "llama3.1:8b",
            "ollama_base_url": "http://ollama:11434",
        }
        for key, value in defaults.items():
            connection.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
        connection.commit()


def get_settings() -> SettingsResponse:
    with get_connection() as connection:
        rows = connection.execute("SELECT key, value FROM settings").fetchall()
    payload = {row["key"]: row["value"] for row in rows}
    return SettingsResponse(**payload)


def update_settings(user_email: str, updates: dict[str, Any]) -> SettingsResponse:
    with get_connection() as connection:
        for key in (
            "misp_base_url",
            "misp_api_key",
            "cortex_base_url",
            "cortex_api_key",
            "iris_base_url",
            "iris_api_key",
            "notification_email",
            "dashboard_email",
            "ollama_model",
            "ollama_base_url",
        ):
            if key in updates and updates[key] is not None:
                connection.execute(
                    """
                    INSERT INTO settings (key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (key, updates[key]),
                )

        if updates.get("dashboard_email"):
            connection.execute("UPDATE users SET email = ? WHERE email = ?", (updates["dashboard_email"], user_email))
            user_email = updates["dashboard_email"]

        if updates.get("current_password") and updates.get("new_password"):
            row = connection.execute("SELECT password_salt, password_hash FROM users WHERE email = ?", (user_email,)).fetchone()
            if not row or not verify_password(updates["current_password"], row["password_salt"], row["password_hash"]):
                raise ValueError("Current password is invalid")
            salt, password_hash = hash_password(updates["new_password"])
            connection.execute("UPDATE users SET password_salt = ?, password_hash = ? WHERE email = ?", (salt, password_hash, user_email))

        connection.commit()
    return get_settings()


def create_notification(case_id: int | None, title: str, severity: str, body: str) -> None:
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO notifications (case_id, title, severity, body, is_read, created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (case_id, title, severity, body, _now()),
        )
        connection.commit()


def list_notifications() -> tuple[list[NotificationItem], int]:
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM notifications ORDER BY is_read ASC, datetime(created_at) DESC LIMIT 40").fetchall()
        unread = connection.execute("SELECT COUNT(*) FROM notifications WHERE is_read = 0").fetchone()[0]
    return (
        [
            NotificationItem(
                id=row["id"],
                title=row["title"],
                severity=row["severity"],
                created_at=row["created_at"],
                case_id=row["case_id"],
                is_read=bool(row["is_read"]),
                body=row["body"],
            )
            for row in rows
        ],
        int(unread),
    )


def mark_notification_read(notification_id: int) -> None:
    with get_connection() as connection:
        connection.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
        connection.commit()


def mark_all_notifications_read() -> None:
    with get_connection() as connection:
        connection.execute("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
        connection.commit()


def store_wazuh_alert(source_id: str, title: str, severity: str, raw_payload: dict[str, Any]) -> int:
    with get_connection() as connection:
        existing = connection.execute("SELECT id FROM wazuh_alerts WHERE source_id = ? ORDER BY id DESC LIMIT 1", (source_id,)).fetchone()
        if existing:
            connection.execute(
                "UPDATE wazuh_alerts SET title = ?, severity = ?, raw_payload = ?, created_at = ? WHERE id = ?",
                (title, severity, json.dumps(raw_payload), _now(), existing["id"]),
            )
            connection.commit()
            return int(existing["id"])
        cursor = connection.execute(
            "INSERT INTO wazuh_alerts (source_id, title, severity, raw_payload, created_at) VALUES (?, ?, ?, ?, ?)",
            (source_id, title, severity, json.dumps(raw_payload), _now()),
        )
        connection.commit()
        return int(cursor.lastrowid)


def store_misp_event(source_id: str, title: str, severity: str, raw_payload: dict[str, Any]) -> int:
    return _store_external_item("misp_events", source_id, title, severity, raw_payload)


def store_cortex_job(source_id: str, title: str, severity: str, raw_payload: dict[str, Any]) -> int:
    return _store_external_item("cortex_jobs", source_id, title, severity, raw_payload)


def list_external_items(table_name: str, page: int, page_size: int, severity: str | None = None) -> tuple[list[ExternalItemResponse], int]:
    filters = ["1=1"]
    params: list[Any] = []
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    where_clause = " AND ".join(filters)
    offset = (page - 1) * page_size
    with get_connection() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM {table_name} WHERE {where_clause}", params).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM {table_name} WHERE {where_clause} ORDER BY datetime(created_at) DESC LIMIT ? OFFSET ?",
            (*params, page_size, offset),
        ).fetchall()
    return (
        [
            ExternalItemResponse(
                id=row["id"],
                source_id=row["source_id"],
                title=row["title"],
                severity=row["severity"],
                created_at=row["created_at"],
                raw_payload=json.loads(row["raw_payload"]),
            )
            for row in rows
        ],
        int(total),
    )


def list_iris_cases(page: int, page_size: int, severity: str | None = None) -> tuple[list[ExternalItemResponse], int]:
    return list_external_items("iris_cases", page=page, page_size=page_size, severity=severity)


def sync_misp_from_settings() -> None:
    settings = get_settings()
    items = fetch_misp_events(settings.misp_base_url, settings.misp_api_key, limit=50)
    with get_connection() as connection:
        for item in items:
            connection.execute(
                """
                INSERT INTO misp_events (source_id, title, severity, raw_payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    raw_payload = excluded.raw_payload,
                    created_at = excluded.created_at
                """,
                (item["source_id"], item["title"], item["severity"], json.dumps(item["raw_payload"]), item["created_at"] or _now()),
            )
        connection.commit()


def sync_cortex_from_settings() -> None:
    settings = get_settings()
    items = fetch_cortex_jobs(settings.cortex_base_url, settings.cortex_api_key, limit=50)
    with get_connection() as connection:
        for item in items:
            connection.execute(
                """
                INSERT INTO cortex_jobs (source_id, title, severity, raw_payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    raw_payload = excluded.raw_payload,
                    created_at = excluded.created_at
                """,
                (item["source_id"], item["title"], item["severity"], json.dumps(item["raw_payload"]), item["created_at"] or _now()),
            )
        connection.commit()


def sync_iris_from_settings() -> None:
    settings = get_settings()
    items = fetch_iris_cases(settings.iris_base_url, settings.iris_api_key, limit=100)
    with get_connection() as connection:
        for item in items:
            connection.execute(
                """
                INSERT INTO iris_cases (source_id, title, severity, raw_payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    title = excluded.title,
                    severity = excluded.severity,
                    raw_payload = excluded.raw_payload,
                    created_at = excluded.created_at
                """,
                (item["source_id"], item["title"], item["severity"], json.dumps(item["raw_payload"]), item["created_at"] or _now()),
            )
        connection.commit()


def sync_mitre_techniques() -> None:
    with get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0]
    if count:
        return
    techniques = fetch_mitre_bundle()
    with get_connection() as connection:
        for item in techniques:
            connection.execute(
                """
                INSERT OR REPLACE INTO mitre_techniques (
                    external_id, name, description, tactics_json, platforms_json, url, detection, cached_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["external_id"],
                    item["name"],
                    item["description"],
                    json.dumps(item["tactics"]),
                    json.dumps(item["platforms"]),
                    item["url"],
                    item["detection"],
                    _now(),
                ),
            )
        connection.commit()


def list_mitre(page: int, page_size: int, search: str | None = None) -> tuple[list[dict[str, Any]], int]:
    filters = ["1=1"]
    params: list[Any] = []
    if search:
        token = f"%{search}%"
        filters.append("(external_id LIKE ? OR name LIKE ? OR description LIKE ?)")
        params.extend([token, token, token])
    where_clause = " AND ".join(filters)
    offset = (page - 1) * page_size
    with get_connection() as connection:
        total = connection.execute(f"SELECT COUNT(*) FROM mitre_techniques WHERE {where_clause}", params).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM mitre_techniques WHERE {where_clause} ORDER BY external_id ASC LIMIT ? OFFSET ?",
            (*params, page_size, offset),
        ).fetchall()
    return (
        [
            {
                "external_id": row["external_id"],
                "name": row["name"],
                "tactics": json.loads(row["tactics_json"]),
                "platforms": json.loads(row["platforms_json"]),
                "url": row["url"],
                "description": row["description"],
                "detection": row["detection"],
            }
            for row in rows
        ],
        int(total),
    )


def link_case_mitre(case_id: int, technique_ids: list[str]) -> None:
    with get_connection() as connection:
        for technique_id in technique_ids:
            connection.execute("INSERT OR IGNORE INTO case_mitre (case_id, technique_id) VALUES (?, ?)", (case_id, technique_id))
        connection.commit()


def get_case_mitre(case_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT mitre_techniques.* FROM mitre_techniques
            JOIN case_mitre ON case_mitre.technique_id = mitre_techniques.external_id
            WHERE case_mitre.case_id = ?
            ORDER BY mitre_techniques.external_id ASC
            """,
            (case_id,),
        ).fetchall()
    return [
        {
            "external_id": row["external_id"],
            "name": row["name"],
            "tactics": json.loads(row["tactics_json"]),
            "platforms": json.loads(row["platforms_json"]),
            "url": row["url"],
            "description": row["description"],
            "detection": row["detection"],
        }
        for row in rows
    ]


def _store_external_item(table_name: str, source_id: str, title: str, severity: str, raw_payload: dict[str, Any]) -> int:
    with get_connection() as connection:
        existing = connection.execute(f"SELECT id FROM {table_name} WHERE source_id = ? ORDER BY id DESC LIMIT 1", (source_id,)).fetchone()
        if existing:
            connection.execute(
                f"UPDATE {table_name} SET title = ?, severity = ?, raw_payload = ?, created_at = ? WHERE id = ?",
                (title, severity, json.dumps(raw_payload), _now(), existing["id"]),
            )
            connection.commit()
            return int(existing["id"])
        cursor = connection.execute(
            f"INSERT INTO {table_name} (source_id, title, severity, raw_payload, created_at) VALUES (?, ?, ?, ?, ?)",
            (source_id, title, severity, json.dumps(raw_payload), _now()),
        )
        connection.commit()
        return int(cursor.lastrowid)
