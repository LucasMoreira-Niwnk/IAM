from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import connect, init_db, rows_to_dicts
from .sync import DirectorySyncService


app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins) if settings.cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def db():
    connection = connect(settings.database_path)
    init_db(connection)
    return connection


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "app": settings.app_name,
        "mode": "ad-read-only-sync",
    }


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
