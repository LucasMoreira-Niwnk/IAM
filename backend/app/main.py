from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Request, Response
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
NO_PERMISSIONS = {key: False for key in PERMISSION_KEYS}
VIEWONLY_PERMISSIONS = {
    **NO_PERMISSIONS,
    "viewIdentities": True,
    "viewAudit": True,
}

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


class CreateGroupRequest(BaseModel):
    name: str
    description: str | None = None
    target_ou: str
    scope: str
    group_type: str
    is_critical: bool = False


class CreateUserRequest(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: str = ""
    title: str = ""
    department: str = ""
    target_ou: str
    password: str
    must_change_password: bool = True


class ResetPasswordRequest(BaseModel):
    new_password: str
    must_change_password: bool = True


class GroupMembershipRequest(BaseModel):
    group_dn: str
    group_name: str | None = None
    is_critical: bool = False


class IdentityStatusRequest(BaseModel):
    action: str


def db():
    connection = connect(settings.database_path)
    init_db(connection)
    return connection


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        "access_level": user.get("access_level"),
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


def cn_from_dn(dn: str) -> str:
    first_part = str(dn).split(",", 1)[0]
    if first_part.upper().startswith("CN="):
        return first_part[3:]
    return str(dn)


def matches_group(group_dn: str, expected_group: str) -> bool:
    group_dn = str(group_dn or "").lower()
    expected_group = str(expected_group or "").lower()
    return bool(expected_group) and (group_dn == expected_group or cn_from_dn(group_dn) == expected_group)


def operator_group_names(connection, identity_id: str | None) -> list[str]:
    if not identity_id:
        return []
    rows = connection.execute(
        """
        SELECT group_dn, group_name
        FROM identity_groups
        WHERE identity_id = ?
        """,
        (identity_id,),
    ).fetchall()
    names = []
    for row in rows:
        names.extend([row["group_dn"], row["group_name"]])
    return names


def permissions_from_ad_groups(connection, operator: dict | None) -> tuple[dict[str, bool], str, str]:
    if not operator:
        return NO_PERMISSIONS.copy(), "pending", "none"

    memberships = operator_group_names(connection, operator.get("identity_id"))
    if any(matches_group(group, settings.ldap_operator_group) for group in memberships):
        return ALL_PERMISSIONS.copy(), "active", "ad-admin-full"
    if any(matches_group(group, settings.ldap_viewonly_group) for group in memberships):
        return VIEWONLY_PERMISSIONS.copy(), "active", "ad-view-only"
    return parse_permissions(operator.get("permissions_json")), operator.get("status") or "pending", "local"


def permissions_from_access_level(access_level: str | None) -> tuple[dict[str, bool], str, str] | None:
    if access_level == "admin_full":
        return ALL_PERMISSIONS.copy(), "active", "ldap-login-admin-full"
    if access_level == "view_only":
        return VIEWONLY_PERMISSIONS.copy(), "active", "ldap-login-view-only"
    return None


def enrich_operator(connection, operator: dict) -> dict:
    permissions, status, source = permissions_from_ad_groups(connection, operator)
    return {
        **operator,
        "status": status,
        "permissions_json": json.dumps(permissions),
        "permission_source": source,
    }


def operator_response(session: dict, operator: dict | None = None) -> dict:
    live_profile = permissions_from_access_level(session.get("access_level"))
    if live_profile:
        permissions, status, source = live_profile
    else:
        permissions = parse_permissions(operator.get("permissions_json") if operator else None)
        status = operator.get("status") if operator else "pending"
        source = operator.get("permission_source") if operator else "none"
    return {
        **session,
        "identity_id": operator.get("identity_id") if operator else None,
        "status": status,
        "permissions": permissions,
        "permission_source": source,
        "is_admin": permissions.get("manageOperators", False),
    }


def require_permission(connection, request: Request, permission: str) -> dict:
    session = session_from_request(request)
    operator = find_operator_for_session(connection, session)
    if operator:
        operator = enrich_operator(connection, operator)
    current = operator_response(session, operator)

    if current["status"] != "active":
        raise HTTPException(status_code=403, detail="Operador pendente ou inativo no IAM.")
    if not current["permissions"].get(permission):
        raise HTTPException(status_code=403, detail="Operador sem permissão para esta ação.")
    return current


def log_audit_event(
    connection,
    operator: dict | None,
    action: str,
    target_type: str | None = None,
    target_name: str | None = None,
    target_dn: str | None = None,
    status: str = "success",
    details: dict | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_events (
            occurred_at, operator_username, operator_display_name, action,
            target_type, target_name, target_dn, status, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now_iso(),
            operator.get("username") if operator else None,
            operator.get("display_name") if operator else None,
            action,
            target_type,
            target_name,
            target_dn,
            status,
            json.dumps(details or {}, ensure_ascii=False),
        ),
    )


def get_identity_or_404(connection, identity_id: str) -> dict:
    row = connection.execute(
        """
        SELECT *
        FROM identities
        WHERE id = ?
        """,
        (identity_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Identidade não encontrada.")
    return dict(row)


def cn_from_group_dn(group_dn: str) -> str:
    return cn_from_dn(group_dn)


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
        "access_level": user.access_level,
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
        operator = find_operator_for_session(connection, session)
        if operator:
            operator = enrich_operator(connection, operator)
        return operator_response(session, operator)


@app.post("/api/auth/logout")
def auth_logout(response: Response) -> dict:
    response.delete_cookie(settings.session_cookie_name)
    return {"ok": True}


@app.post("/api/sync/ad")
def sync_ad(request: Request) -> dict:
    try:
        with db() as connection:
            operator = require_permission(connection, request, "syncAd")
            result = DirectorySyncService(settings, connection).sync_read_only()
            log_audit_event(
                connection,
                operator,
                action="sync_ad",
                target_type="directory",
                target_name="Active Directory",
                status="success",
                details=result,
            )
            connection.commit()
            return result
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


@app.post("/api/identities")
def create_identity(payload: CreateUserRequest, request: Request) -> dict:
    with db() as connection:
        operator = require_permission(connection, request, "manageOperators")
        try:
            created = ReadOnlyLdapClient(settings).create_user(
                username=payload.username,
                first_name=payload.first_name,
                last_name=payload.last_name,
                email=payload.email,
                target_ou=payload.target_ou,
                password=payload.password,
                must_change_password=payload.must_change_password,
                title=payload.title,
                department=payload.department,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        synced_at = now_iso()
        identity_id = created["distinguished_name"]
        connection.execute(
            """
            INSERT INTO identities (
                id, username, display_name, email, upn, title, department, manager_dn,
                phone, location, distinguished_name, status, user_account_control,
                pwd_last_set, last_logon_timestamp, synced_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                display_name = excluded.display_name,
                email = excluded.email,
                upn = excluded.upn,
                title = excluded.title,
                department = excluded.department,
                distinguished_name = excluded.distinguished_name,
                status = excluded.status,
                user_account_control = excluded.user_account_control,
                pwd_last_set = excluded.pwd_last_set,
                last_logon_timestamp = excluded.last_logon_timestamp,
                synced_at = excluded.synced_at
            """,
            (
                identity_id,
                created["username"],
                created["display_name"],
                created["email"],
                created["upn"],
                created["title"],
                created["department"],
                None,
                None,
                None,
                created["distinguished_name"],
                "active",
                512,
                "0" if payload.must_change_password else "",
                "",
                synced_at,
            ),
        )
        log_audit_event(
            connection,
            operator,
            action="create_user",
            target_type="identity",
            target_name=created["display_name"],
            target_dn=created["distinguished_name"],
            status="success",
            details={"username": created["username"], "must_change_password": payload.must_change_password},
        )
        connection.commit()
        return {"ok": True, "identity": get_identity_or_404(connection, identity_id)}


@app.post("/api/identities/{identity_id}/password")
def reset_identity_password(identity_id: str, payload: ResetPasswordRequest, request: Request) -> dict:
    with db() as connection:
        operator = require_permission(connection, request, "resetPassword")
        identity = get_identity_or_404(connection, identity_id)
        try:
            ReadOnlyLdapClient(settings).reset_password(
                identity["distinguished_name"],
                payload.new_password,
                payload.must_change_password,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        connection.execute(
            """
            UPDATE identities
            SET pwd_last_set = ?,
                synced_at = ?
            WHERE id = ?
            """,
            ("0" if payload.must_change_password else now_iso(), now_iso(), identity_id),
        )
        log_audit_event(
            connection,
            operator,
            action="reset_password",
            target_type="identity",
            target_name=identity.get("display_name") or identity.get("username"),
            target_dn=identity["distinguished_name"],
            status="success",
            details={"must_change_password": payload.must_change_password},
        )
        connection.commit()
        return {"ok": True}


@app.post("/api/identities/{identity_id}/status")
def update_identity_status(identity_id: str, payload: IdentityStatusRequest, request: Request) -> dict:
    with db() as connection:
        operator = require_permission(connection, request, "lockUnlock")
        identity = get_identity_or_404(connection, identity_id)
        action = payload.action
        client = ReadOnlyLdapClient(settings)

        try:
            if action == "unlock":
                client.unlock_user(identity["distinguished_name"])
                new_status = "active"
                new_uac = identity.get("user_account_control") or 512
            elif action in {"disable", "block"}:
                new_uac = client.set_user_enabled(
                    identity["distinguished_name"],
                    identity.get("user_account_control") or 512,
                    enabled=False,
                )
                new_status = "disabled" if action == "disable" else "blocked"
            elif action == "enable":
                new_uac = client.set_user_enabled(
                    identity["distinguished_name"],
                    identity.get("user_account_control") or 512,
                    enabled=True,
                )
                new_status = "active"
            else:
                raise ValueError("Ação de status inválida.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        connection.execute(
            """
            UPDATE identities
            SET status = ?,
                user_account_control = ?,
                synced_at = ?
            WHERE id = ?
            """,
            (new_status, int(new_uac), now_iso(), identity_id),
        )
        log_audit_event(
            connection,
            operator,
            action=f"{action}_identity",
            target_type="identity",
            target_name=identity.get("display_name") or identity.get("username"),
            target_dn=identity["distinguished_name"],
            status="success",
            details={"new_status": new_status},
        )
        connection.commit()
        return {"ok": True, "identity": get_identity_or_404(connection, identity_id)}


@app.post("/api/identities/{identity_id}/groups/add")
def add_identity_group(identity_id: str, payload: GroupMembershipRequest, request: Request) -> dict:
    with db() as connection:
        operator = require_permission(connection, request, "manageGroups")
        identity = get_identity_or_404(connection, identity_id)
        group_name = payload.group_name or cn_from_group_dn(payload.group_dn)
        try:
            ReadOnlyLdapClient(settings).add_user_to_group(identity["distinguished_name"], payload.group_dn)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        connection.execute(
            """
            INSERT OR REPLACE INTO identity_groups (
                identity_id, group_dn, group_name, is_critical, synced_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (identity_id, payload.group_dn, group_name, 1 if payload.is_critical else 0, now_iso()),
        )
        log_audit_event(
            connection,
            operator,
            action="add_group_member",
            target_type="identity",
            target_name=identity.get("display_name") or identity.get("username"),
            target_dn=identity["distinguished_name"],
            status="success",
            details={"group": group_name, "group_dn": payload.group_dn},
        )
        connection.commit()
        return {"ok": True}


@app.post("/api/identities/{identity_id}/groups/remove")
def remove_identity_group(identity_id: str, payload: GroupMembershipRequest, request: Request) -> dict:
    with db() as connection:
        operator = require_permission(connection, request, "manageGroups")
        identity = get_identity_or_404(connection, identity_id)
        group_name = payload.group_name or cn_from_group_dn(payload.group_dn)
        try:
            ReadOnlyLdapClient(settings).remove_user_from_group(identity["distinguished_name"], payload.group_dn)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        connection.execute(
            """
            DELETE FROM identity_groups
            WHERE identity_id = ?
              AND lower(group_dn) = lower(?)
            """,
            (identity_id, payload.group_dn),
        )
        log_audit_event(
            connection,
            operator,
            action="remove_group_member",
            target_type="identity",
            target_name=identity.get("display_name") or identity.get("username"),
            target_dn=identity["distinguished_name"],
            status="success",
            details={"group": group_name, "group_dn": payload.group_dn},
        )
        connection.commit()
        return {"ok": True}


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


@app.get("/api/group-members")
def group_members(group_dn: str = Query(..., min_length=1)) -> list[dict]:
    with db() as connection:
        rows = connection.execute(
            """
            SELECT
                i.id,
                i.username,
                i.display_name,
                i.email,
                i.upn,
                i.department,
                i.title,
                i.status,
                i.distinguished_name,
                ig.group_name,
                ig.group_dn,
                ig.is_critical,
                ig.synced_at
            FROM identity_groups ig
            INNER JOIN identities i ON i.id = ig.identity_id
            WHERE lower(ig.group_dn) = lower(?)
            ORDER BY i.display_name COLLATE NOCASE, i.username COLLATE NOCASE
            """,
            (group_dn,),
        ).fetchall()
        return rows_to_dicts(rows)


@app.post("/api/groups")
def create_group(payload: CreateGroupRequest, request: Request) -> dict:
    with db() as connection:
        operator = require_permission(connection, request, "manageGroups")
        existing = connection.execute(
            """
            SELECT id
            FROM ad_groups
            WHERE lower(name) = lower(?)
               OR lower(distinguished_name) = lower(?)
            LIMIT 1
            """,
            (payload.name.strip(), f"CN={payload.name.strip()},{payload.target_ou.strip()}"),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Grupo ja existe no cache local.")

        try:
            created = ReadOnlyLdapClient(settings).create_group(
                name=payload.name,
                target_ou=payload.target_ou,
                description=payload.description,
                scope=payload.scope,
                group_type=payload.group_type,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        synced_at = now_iso()
        connection.execute(
            """
            INSERT INTO ad_groups (
                id, name, description, distinguished_name, is_critical, synced_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                distinguished_name = excluded.distinguished_name,
                is_critical = excluded.is_critical,
                synced_at = excluded.synced_at
            """,
            (
                created["distinguished_name"],
                created["name"],
                created["description"],
                created["distinguished_name"],
                1 if payload.is_critical else 0,
                synced_at,
            ),
        )
        log_audit_event(
            connection,
            operator,
            action="create_group",
            target_type="group",
            target_name=created["name"],
            target_dn=created["distinguished_name"],
            status="success",
            details={
                "description": created["description"],
                "scope": created["scope"],
                "type": created["type"],
                "is_critical": payload.is_critical,
            },
        )
        connection.commit()

        return {
            "ok": True,
            "group": {
                "id": created["distinguished_name"],
                "name": created["name"],
                "description": created["description"],
                "distinguished_name": created["distinguished_name"],
                "is_critical": 1 if payload.is_critical else 0,
                "member_count": 0,
                "synced_at": synced_at,
            },
        }


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
        return [enrich_operator(connection, dict(row)) for row in rows]


@app.post("/api/operators/{identity_id}/permissions")
def update_operator_permissions(identity_id: str, payload: OperatorPermissionsRequest, request: Request) -> dict:
    with db() as connection:
        current_operator = require_permission(connection, request, "manageOperators")
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
        _, _, source = permissions_from_ad_groups(connection, operator)
        if source.startswith("ad-"):
            raise HTTPException(
                status_code=409,
                detail="Permissões deste operador são controladas por grupo do AD.",
            )

        permissions = sanitize_permissions(payload.permissions)
        status = payload.status if payload.status in {"active", "pending", "disabled"} else operator["status"]

        connection.execute(
            """
            UPDATE iam_operators
            SET permissions_json = ?,
                status = ?
            WHERE identity_id = ?
            """,
            (json.dumps(permissions), status, identity_id),
        )
        log_audit_event(
            connection,
            current_operator,
            action="update_operator_permissions",
            target_type="operator",
            target_name=operator.get("display_name") or operator.get("username"),
            status="success",
            details={
                "target_username": operator.get("username"),
                "status": status,
                "permissions": permissions,
            },
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
        return enrich_operator(connection, dict(updated))


@app.post("/api/operators/{identity_id}/remove")
def remove_operator(identity_id: str, request: Request) -> dict:
    with db() as connection:
        current_operator = require_permission(connection, request, "manageOperators")
        row = connection.execute(
            """
            SELECT *
            FROM iam_operators
            WHERE identity_id = ?
            """,
            (identity_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Operador não encontrado.")

        operator = dict(row)
        same_identity = current_operator.get("identity_id") and current_operator.get("identity_id") == identity_id
        same_username = (
            current_operator.get("username")
            and operator.get("username")
            and current_operator.get("username").lower() == operator.get("username").lower()
        )
        if same_identity or same_username:
            raise HTTPException(status_code=400, detail="Você não pode remover o próprio operador logado.")

        connection.execute(
            """
            DELETE FROM iam_operators
            WHERE identity_id = ?
            """,
            (identity_id,),
        )
        log_audit_event(
            connection,
            current_operator,
            action="remove_operator",
            target_type="operator",
            target_name=operator.get("display_name") or operator.get("username"),
            status="success",
            details={"target_username": operator.get("username")},
        )
        connection.commit()
        return {"ok": True}


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


@app.get("/api/audit-events")
def audit_events(request: Request, operator: str | None = None) -> list[dict]:
    with db() as connection:
        require_permission(connection, request, "viewAudit")
        params: list[str] = []
        where = ""
        if operator:
            params.append(f"%{operator.strip().lower()}%")
            where = """
            WHERE lower(coalesce(operator_username, '') || ' ' || coalesce(operator_display_name, '')) LIKE ?
            """

        rows = connection.execute(
            f"""
            SELECT *
            FROM audit_events
            {where}
            ORDER BY id DESC
            LIMIT 200
            """,
            params,
        ).fetchall()
        return rows_to_dicts(rows)
