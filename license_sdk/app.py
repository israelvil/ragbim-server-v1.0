from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, render_template, request

from .store import ControlStore


def issue_activation_token(installation_code: str, machine_fingerprint: str, app_version: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "installation_code": installation_code,
        "machine_fingerprint": machine_fingerprint,
        "app_version": app_version,
        "status": "approved",
        "kid": "v1",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=168)).timestamp()),
    }
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signing_secret = os.environ.get("RAGBIM_CONTROL_SIGNING_SECRET", "ragbim-local-dev-secret-change-me")
    signature = hmac.new(signing_secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')}"

app = Flask(__name__)
STORE = ControlStore()
BOOTSTRAP_KEY_ENV = "RAGBIM_BOOTSTRAP_KEY"
LOGIN_RATE_WINDOW_MINUTES = int(os.environ.get("RAGBIM_LOGIN_RATE_WINDOW_MINUTES", "10") or 10)
LOGIN_RATE_MAX_ATTEMPTS = int(os.environ.get("RAGBIM_LOGIN_RATE_MAX_ATTEMPTS", "5") or 5)


def _bootstrap_key() -> str:
    return os.environ.get(BOOTSTRAP_KEY_ENV, "").strip()


@app.get("/")
def root():
    if not STORE.has_admin_user():
        return render_template("admin_setup.html", bootstrap_key_env=BOOTSTRAP_KEY_ENV)
    return render_template("admin.html")


@app.get("/admin")
def admin_page():
    if not STORE.has_admin_user():
        return render_template("admin_setup.html", bootstrap_key_env=BOOTSTRAP_KEY_ENV)
    return render_template("admin.html")


def _extract_bearer_token() -> str:
    header = (request.headers.get("Authorization") or "").strip()
    if not header.lower().startswith("bearer "):
        return ""
    return header[7:].strip()


def require_auth(admin_only: bool = False):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return jsonify({"error": "Token de acesso ausente."}), 401

            user = STORE.get_user_by_token(token)
            if user is None:
                return jsonify({"error": "Token inválido."}), 401

            if admin_only and user.get("role") != "admin":
                return jsonify({"error": "Acesso administrativo obrigatório."}), 403

            request.current_user = user
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


@app.get("/health")
def health() -> tuple[dict, int]:
    return {"ok": True, "service": "ragbim-license-sdk"}, 200


@app.post("/api/auth/login")
def login():
    STORE.purge_expired_sessions()
    STORE.purge_old_login_attempts((datetime.utcnow() - timedelta(days=2)).isoformat(timespec="seconds"))

    if not STORE.has_admin_user():
        STORE.record_audit_event(
            event_type="login_blocked_no_admin",
            severity="warning",
            payload={"email": ""},
        )
        return jsonify({"error": "Bootstrap obrigatório: nenhum administrador ativo cadastrado."}), 403

    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    ip_address = str(request.remote_addr or "unknown")

    if not email or not password:
        return jsonify({"error": "Informe email e senha."}), 400

    window_start = (datetime.utcnow() - timedelta(minutes=max(1, LOGIN_RATE_WINDOW_MINUTES))).isoformat(timespec="seconds")
    failed_attempts = STORE.count_recent_failed_login_attempts(email=email, ip_address=ip_address, since=window_start)
    if failed_attempts >= max(1, LOGIN_RATE_MAX_ATTEMPTS):
        STORE.record_audit_event(
            event_type="login_rate_limited",
            severity="warning",
            payload={"email": email, "ip_address": ip_address, "window_minutes": LOGIN_RATE_WINDOW_MINUTES},
        )
        return jsonify(
            {
                "error": "Muitas tentativas de login. Aguarde alguns minutos para tentar novamente.",
                "retry_after_seconds": max(30, LOGIN_RATE_WINDOW_MINUTES * 60),
            }
        ), 429

    user = STORE.authenticate_user(email, password)
    if user is None:
        STORE.record_login_attempt(email=email, ip_address=ip_address, success=False)
        STORE.record_audit_event(
            event_type="login_failed",
            severity="warning",
            payload={"email": email, "ip_address": ip_address},
        )
        return jsonify({"error": "Credenciais inválidas."}), 401

    STORE.record_login_attempt(email=email, ip_address=ip_address, success=True)
    access_token = STORE.create_session(int(user["id"]))
    STORE.record_audit_event(
        event_type="login_success",
        severity="info",
        payload={"email": email, "ip_address": ip_address},
        user_id=int(user["id"]),
    )
    return jsonify(
        {
            "access_token": access_token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
            },
        }
    )


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    fields = {
        "name": str(body.get("name", "")).strip(),
        "email": str(body.get("email", "")).strip().lower(),
        "cellphone": str(body.get("cellphone", "")).strip(),
        "password": str(body.get("password", "")),
        "document_number": str(body.get("document_number", "")).strip(),
        "document_type": str(body.get("document_type", "")).strip().upper(),
        "address": str(body.get("address", "")).strip(),
        "state": str(body.get("state", "")).strip(),
        "country": str(body.get("country", "")).strip(),
    }
    if not all(fields.values()):
        return jsonify({"error": "Preencha todos os dados cadastrais."}), 400
    if fields["document_type"] not in ("CPF", "PASSAPORTE"):
        return jsonify({"error": "Tipo de documento inválido. Use CPF ou Passaporte."}), 400
    try:
        user = STORE.create_user(**fields)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    STORE.record_audit_event(
        event_type="user_registered",
        severity="info",
        payload={"email": fields["email"], "document_type": fields["document_type"]},
        user_id=int(user["id"]),
    )
    return jsonify({"ok": True, "user": user}), 201


@app.post("/api/auth/logout")
@require_auth()
def logout():
    token = _extract_bearer_token()
    user_id = int(request.current_user["id"])
    STORE.revoke_session(token)
    STORE.record_audit_event(
        event_type="logout",
        severity="info",
        payload={"email": str(request.current_user.get("email", ""))},
        user_id=user_id,
    )
    return jsonify({"ok": True})


@app.get("/api/bootstrap/status")
def bootstrap_status():
    has_admin = STORE.has_admin_user()
    return jsonify(
        {
            "has_admin": has_admin,
            "bootstrap_required": not has_admin,
            "bootstrap_key_configured": bool(_bootstrap_key()),
            "bootstrap_key_env": BOOTSTRAP_KEY_ENV,
        }
    )


@app.post("/api/bootstrap/admin")
def bootstrap_admin():
    if STORE.has_admin_user():
        return jsonify({"error": "Bootstrap já concluído. Administrador já existe."}), 409

    bootstrap_key = _bootstrap_key()
    if not bootstrap_key:
        return jsonify({"error": f"Defina a variável de ambiente {BOOTSTRAP_KEY_ENV} no servidor central."}), 500

    body = request.get_json(silent=True) or {}
    provided_key = str(body.get("bootstrap_key", "")).strip()
    name = str(body.get("name", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    if not provided_key or provided_key != bootstrap_key:
        STORE.record_audit_event(
            event_type="bootstrap_failed",
            severity="warning",
            payload={"reason": "invalid_bootstrap_key", "email": email},
        )
        return jsonify({"error": "Chave de bootstrap inválida."}), 401
    if not name or not email or not password:
        return jsonify({"error": "Informe nome, email e senha para criar o administrador."}), 400
    if len(password) < 8:
        return jsonify({"error": "A senha do administrador deve ter pelo menos 8 caracteres."}), 400

    try:
        user = STORE.create_first_admin(name=name, email=email, password=password)
        STORE.record_audit_event(
            event_type="bootstrap_admin_created",
            severity="info",
            payload={"email": email},
            user_id=int(user["id"]),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"ok": True, "user": user})


@app.post("/api/installations/request-activation")
@require_auth()
def request_activation():
    body = request.get_json(silent=True) or {}
    installation_code = str(body.get("installation_code", "")).strip()
    machine_fingerprint = str(body.get("machine_fingerprint", "")).strip()
    machine_name = str(body.get("machine_name", "")).strip() or platform.node()
    os_name = str(body.get("os_name", "")).strip() or platform.platform()
    app_version = str(body.get("app_version", "")).strip() or "1.0.0"

    if not installation_code or not machine_fingerprint:
        return jsonify({"error": "installation_code e machine_fingerprint são obrigatórios."}), 400

    installation = STORE.request_activation(
        user_id=int(request.current_user["id"]),
        installation_code=installation_code,
        machine_fingerprint=machine_fingerprint,
        machine_name=machine_name,
        os_name=os_name,
        app_version=app_version,
    )
    STORE.record_audit_event(
        event_type="activation_requested",
        severity="info",
        payload={
            "machine_name": machine_name,
            "os_name": os_name,
            "app_version": app_version,
        },
        user_id=int(request.current_user["id"]),
        installation_code=installation_code,
    )
    return jsonify(
        {
            "status": installation["status"],
            "message": "Solicitação de ativação registrada.",
            "installation": installation,
        }
    )


@app.post("/api/installations/validate")
@require_auth()
def validate_installation():
    body = request.get_json(silent=True) or {}
    installation_code = str(body.get("installation_code", "")).strip()
    installation = STORE.touch_installation(installation_code)
    if installation is None:
        return jsonify({"error": "Instalação não encontrada."}), 404

    if installation.get("status") == "approved":
        token = issue_activation_token(
            installation_code=installation_code,
            machine_fingerprint=str(installation.get("machine_fingerprint", "")),
            app_version=str(installation.get("app_version", "")),
        )
        return jsonify({
            "status": "approved",
            "message": "Instalação aprovada.",
            "activation_token": token,
            "next_validation_after_hours": 72,
        })

    return jsonify({
        "status": installation.get("status", "pending"),
        "message": "Instalação pendente ou bloqueada.",
        "next_validation_after_hours": 72,
    })


@app.get("/api/installations")
@require_auth(admin_only=True)
def list_installations():
    status = (request.args.get("status") or "").strip()
    rows = STORE.list_installations(status=status or None)
    return jsonify({"items": rows})


@app.post("/api/installations/<installation_code>/approve")
@require_auth(admin_only=True)
def approve_installation(installation_code: str):
    body = request.get_json(silent=True) or {}
    notes = str(body.get("notes", "")).strip()
    installation = STORE.approve_installation(installation_code, notes=notes)
    STORE.record_audit_event(
        event_type="installation_approved",
        severity="info",
        payload={"notes": notes},
        user_id=int(request.current_user["id"]),
        installation_code=installation_code,
    )
    return jsonify({"ok": True, "installation": installation})


@app.post("/api/installations/<installation_code>/block")
@require_auth(admin_only=True)
def block_installation(installation_code: str):
    body = request.get_json(silent=True) or {}
    notes = str(body.get("notes", "")).strip()
    installation = STORE.block_installation(installation_code, notes=notes)
    STORE.record_audit_event(
        event_type="installation_blocked",
        severity="warning",
        payload={"notes": notes},
        user_id=int(request.current_user["id"]),
        installation_code=installation_code,
    )
    return jsonify({"ok": True, "installation": installation})


@app.get("/api/audit")
@require_auth(admin_only=True)
def audit_events():
    event_type = (request.args.get("event_type") or "").strip()
    start_date = (request.args.get("start_date") or "").strip()
    end_date = (request.args.get("end_date") or "").strip()
    limit = int(request.args.get("limit") or 200)
    return jsonify({"items": STORE.list_audit_events(event_type=event_type, start_date=start_date, end_date=end_date, limit=limit)})


@app.get("/api/users")
@require_auth(admin_only=True)
def list_users():
    return jsonify({"items": STORE.list_users()})


@app.post("/api/users")
@require_auth(admin_only=True)
def create_user():
    body = request.get_json(silent=True) or {}
    user = STORE.create_user(
        name=str(body.get("name", "")).strip(),
        email=str(body.get("email", "")).strip(),
        password=str(body.get("password", "")),
        role=str(body.get("role", "user")).strip() or "user",
    )
    STORE.record_audit_event(
        event_type="user_created",
        severity="info",
        payload={"role": user.get("role", "user")},
        user_id=int(request.current_user["id"]),
    )
    return jsonify({"ok": True, "user": user})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
