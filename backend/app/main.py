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
    session = read_session_token(request.cookies.get(settings.session_cookie_name))
    if not session:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada.")
    return session


@app.post("/api/auth/logout")
def auth_logout(response: Response) -> dict:
    response.delete_cookie(settings.session_cookie_name)
    return {"ok": True}


@app.post("/api/sync/ad")
def sync_ad() -> dict:
    try:
        with db() as connection:
            return DirectorySyncService(settings, connection).sync_read_only()
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
