from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
_db_env = os.environ.get("RAGBIM_DB_PATH", "")
DB_PATH = Path(_db_env) if _db_env else BASE_DIR / "control_center.db"
SESSION_TTL_HOURS = 12


def get_database_url() -> str:
    return (
        os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_URL")
        or os.environ.get("RAGBIM_DATABASE_URL")
        or ""
    ).strip()


def uses_postgres() -> bool:
    return bool(get_database_url())


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


class ControlStore:
    def __init__(self, db_path: Path | str | None = None, database_url: str | None = None):
        self.database_url = (database_url or get_database_url()).strip()
        self.db_path = Path(db_path) if db_path is not None else DB_PATH
        self.backend = "postgres" if self.database_url else "sqlite"
        self._connection: sqlite3.Connection | None = None
        self._initialize()

    def _sql(self, sql: str) -> str:
        if self.backend == "postgres":
            return sql.replace("?", "%s")
        return sql

    def _normalize_row(self, row: Any) -> dict[str, Any]:
        if row is None:
            return {}
        if isinstance(row, sqlite3.Row):
            return dict(row)
        if hasattr(row, "keys"):
            return dict(row)
        return row

    def _connect(self):
        if self.backend == "postgres":
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError(
                    "O backend PostgreSQL foi ativado, mas o pacote 'psycopg' não está instalado. "
                    "Instale com: pip install psycopg[binary]"
                ) from exc
            return psycopg.connect(self.database_url)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def close(self) -> None:
        if self.backend == "sqlite" and self._connection is not None:
            self._connection.close()
            self._connection = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _initialize(self) -> None:
        with self._connect() as connection:
            if self.backend == "postgres":
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        cellphone TEXT NOT NULL DEFAULT '',
                        document_number TEXT NOT NULL DEFAULT '',
                        document_type TEXT NOT NULL DEFAULT 'CPF',
                        address TEXT NOT NULL DEFAULT '',
                        state TEXT NOT NULL DEFAULT '',
                        country TEXT NOT NULL DEFAULT '',
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_login_at TEXT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        id BIGSERIAL PRIMARY KEY,
                        user_id BIGINT NOT NULL REFERENCES users(id),
                        access_token TEXT UNIQUE NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS installations (
                        id BIGSERIAL PRIMARY KEY,
                        user_id BIGINT NOT NULL REFERENCES users(id),
                        installation_code TEXT UNIQUE NOT NULL,
                        machine_fingerprint TEXT NOT NULL,
                        machine_name TEXT NOT NULL,
                        os_name TEXT NOT NULL,
                        app_version TEXT NOT NULL,
                        status TEXT NOT NULL,
                        activation_token TEXT NULL,
                        requested_at TEXT NOT NULL,
                        approved_at TEXT NULL,
                        last_seen_at TEXT NULL,
                        notes TEXT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id BIGSERIAL PRIMARY KEY,
                        user_id BIGINT NULL,
                        installation_code TEXT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id BIGSERIAL PRIMARY KEY,
                        email TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                for column_name in ("cellphone", "document_number", "document_type", "address", "state", "country"):
                    connection.execute(
                        f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {column_name} TEXT NOT NULL DEFAULT ''"
                    )
                return

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    cellphone TEXT NOT NULL DEFAULT '',
                    document_number TEXT NOT NULL DEFAULT '',
                    document_type TEXT NOT NULL DEFAULT 'CPF',
                    address TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT '',
                    country TEXT NOT NULL DEFAULT '',
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    access_token TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS installations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    installation_code TEXT UNIQUE NOT NULL,
                    machine_fingerprint TEXT NOT NULL,
                    machine_name TEXT NOT NULL,
                    os_name TEXT NOT NULL,
                    app_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    activation_token TEXT NULL,
                    requested_at TEXT NOT NULL,
                    approved_at TEXT NULL,
                    last_seen_at TEXT NULL,
                    notes TEXT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NULL,
                    installation_code TEXT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
            for column_name, definition in (
                ("cellphone", "TEXT NOT NULL DEFAULT ''"),
                ("document_number", "TEXT NOT NULL DEFAULT ''"),
                ("document_type", "TEXT NOT NULL DEFAULT 'CPF'"),
                ("address", "TEXT NOT NULL DEFAULT ''"),
                ("state", "TEXT NOT NULL DEFAULT ''"),
                ("country", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column_name not in columns:
                    connection.execute(f"ALTER TABLE users ADD COLUMN {column_name} {definition}")

    def has_admin_user(self) -> bool:
        with self._connect() as connection:
            sql = self._sql("SELECT id FROM users WHERE role = 'admin' AND status = 'active' LIMIT 1")
            row = connection.execute(sql).fetchone()
        return row is not None

    def create_first_admin(self, name: str, email: str, password: str) -> dict[str, Any]:
        if self.has_admin_user():
            raise ValueError("Já existe administrador cadastrado.")

        now = utc_now()
        normalized_email = email.lower().strip()
        with self._connect() as connection:
            if self.backend == "postgres":
                cursor = connection.execute(
                    self._sql(
                        """
                        INSERT INTO users (name, email, password_hash, role, status, created_at, updated_at)
                        VALUES (?, ?, ?, 'admin', 'active', ?, ?)
                        RETURNING id, name, email, role, status, created_at
                        """
                    ),
                    (name.strip(), normalized_email, generate_password_hash(password), now, now),
                )
                row = cursor.fetchone()
            else:
                connection.execute(
                    self._sql(
                        """
                        INSERT INTO users (name, email, password_hash, role, status, created_at, updated_at)
                        VALUES (?, ?, ?, 'admin', 'active', ?, ?)
                        """
                    ),
                    (name.strip(), normalized_email, generate_password_hash(password), now, now),
                )
                row = connection.execute(
                    self._sql("SELECT id, name, email, role, status, created_at FROM users WHERE email = ?"),
                    (normalized_email,),
                ).fetchone()

        if row is None:
            raise RuntimeError("Falha ao criar administrador inicial.")
        return self._normalize_row(row)

    def authenticate_user(self, email: str, password: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                self._sql("SELECT * FROM users WHERE email = ? AND status = 'active'"),
                (email.lower().strip(),),
            ).fetchone()
            if row is None:
                return None
            row_dict = self._normalize_row(row)
            if not check_password_hash(row_dict["password_hash"], password):
                return None

            now = utc_now()
            connection.execute(
                self._sql("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?"),
                (now, now, row_dict["id"]),
            )

        return row_dict

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        now = utc_now()
        expires_at = (datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)).replace(microsecond=0).isoformat(timespec="seconds")
        with self._connect() as connection:
            connection.execute(
                self._sql("INSERT INTO sessions (user_id, access_token, created_at, expires_at) VALUES (?, ?, ?, ?)"),
                (user_id, token, now, expires_at),
            )
        return token

    def revoke_session(self, token: str) -> None:
        with self._connect() as connection:
            connection.execute(self._sql("DELETE FROM sessions WHERE access_token = ?"), (token,))

    def purge_expired_sessions(self) -> int:
        now = utc_now()
        with self._connect() as connection:
            cursor = connection.execute(self._sql("DELETE FROM sessions WHERE expires_at <= ?"), (now,))
        return int(cursor.rowcount or 0)

    def get_user_by_token(self, token: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._connect() as connection:
            row = connection.execute(
                self._sql(
                    """
                    SELECT users.*
                    FROM sessions
                    JOIN users ON users.id = sessions.user_id
                    WHERE sessions.access_token = ?
                      AND sessions.expires_at > ?
                      AND users.status = 'active'
                    """
                ),
                (token, now),
            ).fetchone()
        return self._normalize_row(row) if row else None

    def record_audit_event(
        self,
        event_type: str,
        severity: str,
        payload: dict[str, Any],
        user_id: int | None = None,
        installation_code: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                self._sql(
                    """
                    INSERT INTO audit_events (user_id, installation_code, event_type, severity, payload_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """
                ),
                (
                    user_id,
                    installation_code,
                    event_type,
                    severity,
                    json.dumps(payload, ensure_ascii=False),
                    utc_now(),
                ),
            )

    def list_audit_events(
        self,
        event_type: str = "",
        start_date: str = "",
        end_date: str = "",
        limit: int = 300,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        normalized_event_type = event_type.strip()
        if normalized_event_type:
            clauses.append("event_type = ?")
            params.append(normalized_event_type)
        normalized_start_date = start_date.strip()
        if normalized_start_date:
            clauses.append("created_at >= ?")
            params.append(normalized_start_date)
        normalized_end_date = end_date.strip()
        if normalized_end_date:
            clauses.append("created_at <= ?")
            params.append(normalized_end_date)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_limit = max(1, min(int(limit or 300), 1000))

        with self._connect() as connection:
            rows = connection.execute(
                self._sql(
                    f"""
                    SELECT id, user_id, installation_code, event_type, severity, payload_json, created_at
                    FROM audit_events
                    {where_sql}
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                    """
                ),
                (*params, safe_limit),
            ).fetchall()

        items: list[dict[str, Any]] = []
        for row in rows:
            row_map = self._normalize_row(row)
            payload = {}
            try:
                payload = json.loads(row_map.get("payload_json") or "{}")
            except Exception:
                payload = {}
            items.append(
                {
                    "id": row_map["id"],
                    "user_id": row_map["user_id"],
                    "installation_code": row_map["installation_code"],
                    "event_type": row_map["event_type"],
                    "severity": row_map["severity"],
                    "payload": payload,
                    "created_at": row_map["created_at"],
                }
            )
        return items

    def count_recent_failed_login_attempts(self, email: str, ip_address: str, since: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                self._sql(
                    "SELECT COUNT(*) AS c FROM login_attempts WHERE email = ? AND ip_address = ? AND success = 0 AND created_at >= ?"
                ),
                (email.lower().strip(), ip_address, since),
            ).fetchone()
        row_map = self._normalize_row(row)
        return int(row_map.get("c") if row_map else 0)

    def record_login_attempt(self, email: str, ip_address: str, success: bool) -> None:
        with self._connect() as connection:
            connection.execute(
                self._sql("INSERT INTO login_attempts (email, ip_address, success, created_at) VALUES (?, ?, ?, ?)"),
                (email.lower().strip(), ip_address, 1 if success else 0, utc_now()),
            )

    def purge_old_login_attempts(self, cutoff_iso: str) -> int:
        with self._connect() as connection:
            cursor = connection.execute(self._sql("DELETE FROM login_attempts WHERE created_at <= ?"), (cutoff_iso,))
        return int(cursor.rowcount or 0)

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(self._sql("SELECT id, name, email, cellphone, document_number, document_type, address, state, country, role, status, created_at, last_login_at FROM users ORDER BY id ASC")).fetchall()
        return [self._normalize_row(row) for row in rows]

    def create_user(self, name: str, email: str, password: str, role: str = "user", cellphone: str = "", document_number: str = "", document_type: str = "CPF", address: str = "", state: str = "", country: str = "") -> dict[str, Any]:
        normalized_email = email.lower().strip()
        if not name.strip() or not normalized_email or not password:
            raise ValueError("Nome, email e senha são obrigatórios.")
        if len(password) < 8:
            raise ValueError("A senha deve ter no mínimo 8 caracteres.")
        now = utc_now()
        with self._connect() as connection:
            if self.backend == "postgres":
                cursor = connection.execute(
                    self._sql(
                        """
                        INSERT INTO users (name, email, cellphone, document_number, document_type, address, state, country, password_hash, role, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                        RETURNING id, name, email, cellphone, document_number, document_type, address, state, country, role, status, created_at
                        """
                    ),
                    (name.strip(), normalized_email, cellphone.strip(), document_number.strip(), document_type, address.strip(), state.strip(), country.strip(), generate_password_hash(password), role.strip().lower() or "user", now, now),
                )
                row = cursor.fetchone()
            else:
                cursor = connection.execute(
                    self._sql(
                        """
                        INSERT INTO users (name, email, cellphone, document_number, document_type, address, state, country, password_hash, role, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                        """
                    ),
                    (name.strip(), normalized_email, cellphone.strip(), document_number.strip(), document_type, address.strip(), state.strip(), country.strip(), generate_password_hash(password), role.strip().lower() or "user", now, now),
                )
                row = connection.execute(
                    self._sql("SELECT id, name, email, cellphone, document_number, document_type, address, state, country, role, status, created_at FROM users WHERE id = ?"),
                    (cursor.lastrowid,),
                ).fetchone()
        return self._normalize_row(row) if row else {}

    def request_activation(
        self,
        user_id: int,
        installation_code: str,
        machine_fingerprint: str,
        machine_name: str,
        os_name: str,
        app_version: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self._connect() as connection:
            row = connection.execute(
                self._sql("SELECT id, status, activation_token FROM installations WHERE installation_code = ? AND machine_fingerprint = ?"),
                (installation_code, machine_fingerprint),
            ).fetchone()
            if row is None:
                connection.execute(
                    self._sql(
                        """
                        INSERT INTO installations (
                            user_id, installation_code, machine_fingerprint, machine_name, os_name,
                            app_version, status, activation_token, requested_at, approved_at, last_seen_at, notes
                        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, ?, NULL, ?, NULL)
                        """
                    ),
                    (user_id, installation_code, machine_fingerprint, machine_name, os_name, app_version, now, now),
                )
            else:
                row_map = self._normalize_row(row)
                connection.execute(
                    self._sql(
                        """
                        UPDATE installations
                        SET user_id = ?, machine_name = ?, os_name = ?, app_version = ?, last_seen_at = ?, status = 'pending'
                        WHERE id = ?
                        """
                    ),
                    (user_id, machine_name, os_name, app_version, now, row_map["id"]),
                )

            current = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? AND machine_fingerprint = ?"),
                (installation_code, machine_fingerprint),
            ).fetchone()
        return self._normalize_row(current) if current else {}

    def touch_installation(self, installation_code: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? ORDER BY id DESC LIMIT 1"),
                (installation_code,),
            ).fetchone()
        return self._normalize_row(row) if row else None

    def list_installations(
        self,
        status: str | None = None,
        user_id: int | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_limit = max(1, min(int(limit or 200), 1000))

        with self._connect() as connection:
            rows = connection.execute(
                self._sql(
                    f"""
                    SELECT * FROM installations
                    {where_sql}
                    ORDER BY requested_at DESC, id DESC
                    LIMIT ?
                    """
                ),
                (*params, safe_limit),
            ).fetchall()
        return [self._normalize_row(row) for row in rows]

    def approve_installation(self, installation_code: str, notes: str = "") -> dict[str, Any]:
        now = utc_now()
        token = secrets.token_urlsafe(24)
        with self._connect() as connection:
            row = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? ORDER BY id DESC LIMIT 1"),
                (installation_code,),
            ).fetchone()
            if row is None:
                raise ValueError("Instalação não encontrada.")
            connection.execute(
                self._sql(
                    """
                    UPDATE installations
                    SET status = 'approved', activation_token = ?, approved_at = ?, notes = ?, last_seen_at = ?
                    WHERE installation_code = ?
                    """
                ),
                (token, now, notes, now, installation_code),
            )
            updated = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? ORDER BY id DESC LIMIT 1"),
                (installation_code,),
            ).fetchone()
        return self._normalize_row(updated) if updated else {}

    def block_installation(self, installation_code: str, notes: str = "") -> dict[str, Any]:
        now = utc_now()
        with self._connect() as connection:
            row = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? ORDER BY id DESC LIMIT 1"),
                (installation_code,),
            ).fetchone()
            if row is None:
                raise ValueError("Instalação não encontrada.")
            connection.execute(
                self._sql(
                    """
                    UPDATE installations
                    SET status = 'blocked', activation_token = NULL, approved_at = NULL, notes = ?, last_seen_at = ?
                    WHERE installation_code = ?
                    """
                ),
                (notes, now, installation_code),
            )
            updated = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? ORDER BY id DESC LIMIT 1"),
                (installation_code,),
            ).fetchone()
        return self._normalize_row(updated) if updated else {}

    def get_installation_by_code(self, installation_code: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                self._sql("SELECT * FROM installations WHERE installation_code = ? ORDER BY id DESC LIMIT 1"),
                (installation_code,),
            ).fetchone()
        return self._normalize_row(row) if row else None
