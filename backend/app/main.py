from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import settings
from .database import connect, init_db, rows_to_dicts
from .ldap_client import ReadOnlyLdapClient
from .sync import DirectorySyncService


PERMISSION_KEYS = (
    "viewIdentities",
    "resetPassword",
    "lockUnlock",
    "manageGroups",
    "managePrivilegedGroups",
    "syncAd",
    "manageOperators",
    "viewAudit",
)
ALL_PERMISSIONS = {key: True for key in PERMISSION_KEYS}
BOOTSTRAP_FULL_PERMISSION_USERS = {"lucas.salomao"}

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins) if settings.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class LdapLoginRequest(BaseModel):
    username: str
    password: str


class OperatorPermissionsRequest(BaseModel):
    permissions: dict[str, bool]
    status: str | None = None


def db():
    connection = connect(settings.database_path)
    init_db(connection)
    return connection


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_session_token(user: dict) -> str:
    payload = {
        "username": user["username"],
        "display_name": user.get("display_name"),
        "email": user.get("email"),
        "upn": user.get("upn"),
        "exp": int(time.time()) + settings.session_ttl_seconds,
    }
    payload_raw = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(
        settings.session_secret.encode("utf-8"),
        payload_raw.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{payload_raw}.{_b64url(signature)}"


def read_session_token(token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    payload_raw, signature_raw = token.split(".", 1)
    expected_signature = hmac.new(
        settings.session_secret.encode("utf-8"),
        payload_raw.encode("ascii"),
        hashlib.sha256,
    ).digest()
    try:
        received_signature = _b64url_decode(signature_raw)
        if not hmac.compare_digest(expected_signature, received_signature):
            return None
        payload = json.loads(_b64url_decode(payload_raw))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload


def normalize_login(value: str | None) -> str:
    value = (value or "").strip().lower()
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]
    return value


def is_bootstrap_admin(username: str | None) -> bool:
    return normalize_login(username) in BOOTSTRAP_FULL_PERMISSION_USERS


def parse_permissions(raw: str | None) -> dict[str, bool]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return {key: bool(data.get(key)) for key in PERMISSION_KEYS}


def sanitize_permissions(permissions: dict[str, bool]) -> dict[str, bool]:
    return {key: bool(permissions.get(key)) for key in PERMISSION_KEYS}


def session_from_request(request: Request) -> dict:
    session = read_session_token(request.cookies.get(settings.session_cookie_name))
    if not session:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada.")
    return session


def find_operator_for_session(connection, session: dict) -> dict | None:
    identifiers = [
        normalize_login(session.get("username")),
        normalize_login(session.get("upn")),
        normalize_login(session.get("email")),
    ]
    identifiers = [identifier for identifier in identifiers if identifier]
    if not identifiers:
        return None

    placeholders = ",".join("?" for _ in identifiers)
    row = connection.execute(
        f"""
        SELECT
            o.*,
            i.department,
            i.title,
            i.status AS ad_status
        FROM iam_operators o
        LEFT JOIN identities i ON i.id = o.identity_id
        WHERE lower(o.username) IN ({placeholders})
           OR lower(o.email) IN ({placeholders})
        LIMIT 1
        """,
        (*identifiers, *identifiers),
    ).fetchone()
    return dict(row) if row else None


def operator_response(session: dict, operator: dict | None = None) -> dict:
    username = session.get("username")
    permissions = parse_permissions(operator.get("permissions_json") if operator else None)
    status = operator.get("status") if operator else "pending"

    if is_bootstrap_admin(username) or is_bootstrap_admin(operator.get("username") if operator else None):
        permissions = ALL_PERMISSIONS.copy()
        status = "active"

    return {
        **session,
        "identity_id": operator.get("identity_id") if operator else None,
        "status": status,
        "permissions": permissions,
        "is_admin": permissions.get("manageOperators", False),
    }


def require_permission(connection, request: Request, permission: str) -> dict:
    session = session_from_request(request)
    operator = find_operator_for_session(connection, session)
    current = operator_response(session, operator)

    if current["status"] != "active":
        raise HTTPException(status_code=403, detail="Operador pendente ou inativo no IAM.")
    if not current["permissions"].get(permission):
        raise HTTPException(status_code=403, detail="Operador sem permissão para esta ação.")
    return current


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "app": settings.app_name,
        "mode": "ad-read-only-sync",
    }


@app.post("/api/auth/ldap/login")
def ldap_login(payload: LdapLoginRequest, response: Response) -> dict:
    user = ReadOnlyLdapClient(settings).authenticate_operator(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciais LDAP inválidas ou usuário sem acesso ao IAM.")

    user_payload = {
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "upn": user.upn,
        "distinguished_name": user.distinguished_name,
    }
    token = create_session_token(user_payload)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
    )
    return {"ok": True, "user": user_payload}


@app.get("/api/auth/me")
def auth_me(request: Request) -> dict:
    session = session_from_request(request)
    with db() as connection:
        return operator_response(session, find_operator_for_session(connection, session))


@app.post("/api/auth/logout")
def auth_logout(response: Response) -> dict:
    response.delete_cookie(settings.session_cookie_name)
    return {"ok": True}


@app.post("/api/sync/ad")
def sync_ad(request: Request) -> dict:
    try:
        with db() as connection:
            require_permission(connection, request, "syncAd")
            return DirectorySyncService(settings, connection).sync_read_only()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/identities")
def identities() -> list[dict]:
    with db() as connection:
        rows = connection.execute(
            """
            SELECT
                i.*,
                COUNT(ig.group_dn) AS group_count,
                SUM(CASE WHEN ig.is_critical = 1 THEN 1 ELSE 0 END) AS critical_group_count
            FROM identities i
            LEFT JOIN identity_groups ig ON ig.identity_id = i.id
            GROUP BY i.id
            ORDER BY i.display_name COLLATE NOCASE
            """,
        ).fetchall()
        return rows_to_dicts(rows)


@app.get("/api/identities/{identity_id}/groups")
def identity_groups(identity_id: str) -> list[dict]:
    with db() as connection:
        rows = connection.execute(
            """
            SELECT group_name, group_dn, is_critical, synced_at
            FROM identity_groups
            WHERE identity_id = ?
            ORDER BY is_critical DESC, group_name COLLATE NOCASE
            """,
            (identity_id,),
        ).fetchall()
        return rows_to_dicts(rows)


@app.get("/api/groups")
def groups() -> list[dict]:
    with db() as connection:
        rows = connection.execute(
            """
            SELECT
                g.*,
                COUNT(ig.identity_id) AS member_count
            FROM ad_groups g
            LEFT JOIN identity_groups ig ON lower(ig.group_dn) = lower(g.distinguished_name)
            GROUP BY g.id
            ORDER BY g.is_critical DESC, g.name COLLATE NOCASE
            """,
        ).fetchall()
        return rows_to_dicts(rows)


@app.get("/api/operators")
def operators() -> list[dict]:
    with db() as connection:
        connection.execute(
            """
            UPDATE iam_operators
            SET status = 'active',
                permissions_json = ?
            WHERE lower(username) = ?
            """,
            (json.dumps(ALL_PERMISSIONS), "lucas.salomao"),
        )
        connection.commit()
        rows = connection.execute(
            """
            SELECT
                o.*,
                i.department,
                i.title,
                i.status AS ad_status
            FROM iam_operators o
            LEFT JOIN identities i ON i.id = o.identity_id
            ORDER BY o.status DESC, o.display_name COLLATE NOCASE
            """,
        ).fetchall()
        return rows_to_dicts(rows)


@app.post("/api/operators/{identity_id}/permissions")
def update_operator_permissions(identity_id: str, payload: OperatorPermissionsRequest, request: Request) -> dict:
    with db() as connection:
        require_permission(connection, request, "manageOperators")
        row = connection.execute(
            """
            SELECT
                o.*,
                i.department,
                i.title,
                i.status AS ad_status
            FROM iam_operators o
            LEFT JOIN identities i ON i.id = o.identity_id
            WHERE o.identity_id = ?
            """,
            (identity_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Operador não encontrado.")

        operator = dict(row)
        permissions = sanitize_permissions(payload.permissions)
        status = payload.status if payload.status in {"active", "pending", "disabled"} else operator["status"]

        if is_bootstrap_admin(operator.get("username")):
            permissions = ALL_PERMISSIONS.copy()
            status = "active"

        connection.execute(
            """
            UPDATE iam_operators
            SET permissions_json = ?,
                status = ?
            WHERE identity_id = ?
            """,
            (json.dumps(permissions), status, identity_id),
        )
        connection.commit()

        updated = connection.execute(
            """
            SELECT
                o.*,
                i.department,
                i.title,
                i.status AS ad_status
            FROM iam_operators o
            LEFT JOIN identities i ON i.id = o.identity_id
            WHERE o.identity_id = ?
            """,
            (identity_id,),
        ).fetchone()
        return dict(updated)


@app.get("/api/critical-permissions")
def critical_permissions() -> dict:
    with db() as connection:
        users = rows_to_dicts(
            connection.execute(
                """
                SELECT
                    i.id,
                    i.username,
                    i.display_name,
                    i.email,
                    i.department,
                    i.status,
                    GROUP_CONCAT(ig.group_name, ', ') AS critical_groups
                FROM identities i
                INNER JOIN identity_groups ig ON ig.identity_id = i.id
                WHERE ig.is_critical = 1
                GROUP BY i.id
                ORDER BY i.display_name COLLATE NOCASE
                """,
            ).fetchall(),
        )
        groups = rows_to_dicts(
            connection.execute(
                """
                SELECT
                    group_name,
                    COUNT(identity_id) AS member_count
                FROM identity_groups
                WHERE is_critical = 1
                GROUP BY group_name
                ORDER BY member_count DESC, group_name COLLATE NOCASE
                """,
            ).fetchall(),
        )

        return {
            "users_count": len(users),
            "groups_count": len(groups),
            "users": users,
            "groups": groups,
        }


@app.get("/api/sync-runs")
def sync_runs() -> list[dict]:
    with db() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM sync_runs
            ORDER BY id DESC
            LIMIT 20
            """,
        ).fetchall()
        return rows_to_dicts(rows)
