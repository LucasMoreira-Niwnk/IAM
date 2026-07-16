from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
import json
from typing import Any
from uuid import UUID

from .config import Settings
from .database import init_db
from .ldap_client import ReadOnlyLdapClient


ACCOUNT_DISABLED_FLAG = 0x0002
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def list_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def object_guid(value: Any) -> str:
    raw = first(value)
    if isinstance(raw, UUID):
        return str(raw)
    return str(raw or "")


def cn_from_dn(dn: str) -> str:
    first_part = dn.split(",", 1)[0]
    if first_part.upper().startswith("CN="):
        return first_part[3:]
    return dn


def is_account_disabled(user_account_control: Any) -> bool:
    try:
        return bool(int(first(user_account_control) or 0) & ACCOUNT_DISABLED_FLAG)
    except (TypeError, ValueError):
        return False


def matches_group(group_dn: str, expected_group: str) -> bool:
    if not expected_group:
        return False
    group_dn = group_dn.lower()
    expected_group = expected_group.lower()
    return group_dn == expected_group or cn_from_dn(group_dn) == expected_group


def operator_profile_from_groups(groups: list[Any], settings: Settings) -> tuple[bool, str, dict[str, bool]]:
    group_dns = [str(group_dn) for group_dn in groups]
    if any(matches_group(group_dn, settings.ldap_operator_group) for group_dn in group_dns):
        return True, "active", ALL_PERMISSIONS.copy()
    if any(matches_group(group_dn, settings.ldap_viewonly_group) for group_dn in group_dns):
        return True, "active", VIEWONLY_PERMISSIONS.copy()
    return False, "pending", {}


def merge_identity_by_username(connection: sqlite3.Connection, username: str, identity_id: str, synced_at: str) -> None:
    if not username:
        return

    duplicate_rows = connection.execute(
        """
        SELECT id
        FROM identities
        WHERE lower(username) = lower(?)
          AND id <> ?
        """,
        (username, identity_id),
    ).fetchall()

    for row in duplicate_rows:
        old_id = row["id"]
        target_operator = connection.execute(
            "SELECT 1 FROM iam_operators WHERE identity_id = ?",
            (identity_id,),
        ).fetchone()
        if target_operator:
            connection.execute("DELETE FROM iam_operators WHERE identity_id = ?", (old_id,))
        else:
            connection.execute(
                """
                UPDATE iam_operators
                SET identity_id = ?, username = ?, last_seen_at = ?
                WHERE identity_id = ?
                """,
                (identity_id, username, synced_at, old_id),
            )

        connection.execute("DELETE FROM identity_groups WHERE identity_id = ?", (old_id,))
        connection.execute("DELETE FROM identities WHERE id = ?", (old_id,))


class DirectorySyncService:
    def __init__(self, settings: Settings, connection: sqlite3.Connection):
        self.settings = settings
        self.connection = connection
        init_db(connection)

    def sync_read_only(self) -> dict[str, Any]:
        started_at = now_iso()
        cursor = self.connection.execute(
            "INSERT INTO sync_runs (started_at, status) VALUES (?, ?)",
            (started_at, "running"),
        )
        sync_run_id = cursor.lastrowid
        self.connection.commit()

        try:
            result = ReadOnlyLdapClient(self.settings).fetch_directory()
            synced_at = now_iso()
            critical_names = {name.lower() for name in self.settings.critical_groups}
            critical_dns: set[str] = set()

            for group in result.groups:
                group_id = object_guid(group.get("objectGUID")) or str(first(group.get("distinguishedName")))
                name = str(first(group.get("cn")) or cn_from_dn(str(first(group.get("distinguishedName")))))
                dn = str(first(group.get("distinguishedName")) or "")
                is_critical = name.lower() in critical_names
                if is_critical:
                    critical_dns.add(dn.lower())

                self.connection.execute(
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
                        group_id,
                        name,
                        first(group.get("description")),
                        dn,
                        1 if is_critical else 0,
                        synced_at,
                    ),
                )

            self.connection.execute("DELETE FROM identity_groups")
            synced_operator_ids: set[str] = set()

            for user in result.users:
                identity_id = object_guid(user.get("objectGUID")) or str(first(user.get("sAMAccountName")))
                username = str(first(user.get("sAMAccountName")) or "")
                dn = str(first(user.get("distinguishedName")) or "")
                uac = first(user.get("userAccountControl"))
                status = "disabled" if is_account_disabled(uac) else "active"
                merge_identity_by_username(self.connection, username, identity_id, synced_at)

                self.connection.execute(
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
                        manager_dn = excluded.manager_dn,
                        phone = excluded.phone,
                        location = excluded.location,
                        distinguished_name = excluded.distinguished_name,
                        status = excluded.status,
                        user_account_control = excluded.user_account_control,
                        pwd_last_set = excluded.pwd_last_set,
                        last_logon_timestamp = excluded.last_logon_timestamp,
                        synced_at = excluded.synced_at
                    """,
                    (
                        identity_id,
                        username,
                        first(user.get("displayName")),
                        first(user.get("mail")),
                        first(user.get("userPrincipalName")),
                        first(user.get("title")),
                        first(user.get("department")),
                        first(user.get("manager")),
                        first(user.get("telephoneNumber")),
                        first(user.get("l")),
                        dn,
                        status,
                        int(uac or 0),
                        str(first(user.get("pwdLastSet")) or ""),
                        str(first(user.get("lastLogonTimestamp")) or ""),
                        synced_at,
                    ),
                )

                for group_dn in list_value(user.get("memberOf")):
                    group_dn = str(group_dn)
                    group_name = cn_from_dn(group_dn)
                    is_critical = (
                        group_name.lower() in critical_names or group_dn.lower() in critical_dns
                    )
                    self.connection.execute(
                        """
                        INSERT INTO identity_groups (
                            identity_id, group_dn, group_name, is_critical, synced_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            identity_id,
                            group_dn,
                            group_name,
                            1 if is_critical else 0,
                            synced_at,
                        ),
                    )

                is_operator, operator_status, operator_permissions = operator_profile_from_groups(
                    list_value(user.get("memberOf")),
                    self.settings,
                )
                if is_operator:
                    synced_operator_ids.add(identity_id)
                    self.connection.execute(
                        """
                        INSERT INTO iam_operators (
                            identity_id, username, display_name, email, status,
                            permissions_json, first_seen_at, last_seen_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(identity_id) DO UPDATE SET
                            username = excluded.username,
                            display_name = excluded.display_name,
                            email = excluded.email,
                            status = excluded.status,
                            permissions_json = excluded.permissions_json,
                            last_seen_at = excluded.last_seen_at
                        """,
                        (
                            identity_id,
                            username,
                            first(user.get("displayName")),
                            first(user.get("mail")),
                            operator_status,
                            json.dumps(operator_permissions),
                            synced_at,
                            synced_at,
                        ),
                    )

            if synced_operator_ids:
                placeholders = ",".join("?" for _ in synced_operator_ids)
                self.connection.execute(
                    f"DELETE FROM iam_operators WHERE identity_id NOT IN ({placeholders})",
                    tuple(synced_operator_ids),
                )
            else:
                self.connection.execute("DELETE FROM iam_operators")

            self.connection.execute(
                """
                UPDATE sync_runs
                SET finished_at = ?, status = ?, users_synced = ?, groups_synced = ?
                WHERE id = ?
                """,
                (now_iso(), "success", len(result.users), len(result.groups), sync_run_id),
            )
            self.connection.commit()

            return {
                "sync_run_id": sync_run_id,
                "status": "success",
                "users_synced": len(result.users),
                "groups_synced": len(result.groups),
                "write_scope": "local-cache-only",
            }
        except Exception as exc:
            self.connection.execute(
                """
                UPDATE sync_runs
                SET finished_at = ?, status = ?, error_message = ?
                WHERE id = ?
                """,
                (now_iso(), "failed", str(exc), sync_run_id),
            )
            self.connection.commit()
            raise
