from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "Casa & Terra IAM")
    app_env: str = os.getenv("APP_ENV", "development")
    cors_origins: tuple[str, ...] = tuple(_csv_env("CORS_ORIGINS"))
    database_path: Path = Path(os.getenv("DATABASE_PATH", "./data/iam.sqlite3"))

    ldap_server: str = os.getenv("LDAP_SERVER", "")
    ldap_bind_dn: str = os.getenv("LDAP_BIND_DN", "")
    ldap_bind_password: str = os.getenv("LDAP_BIND_PASSWORD", "")
    ldap_base_dn: str = os.getenv("LDAP_BASE_DN", "")
    ldap_user_base_dn: str = os.getenv("LDAP_USER_BASE_DN", os.getenv("LDAP_BASE_DN", ""))
    ldap_group_base_dn: str = os.getenv("LDAP_GROUP_BASE_DN", os.getenv("LDAP_BASE_DN", ""))
    ldap_operator_group: str = os.getenv("LDAP_OPERATOR_GROUP", "GG-IAM-OPERADORES")
    ldap_page_size: int = int(os.getenv("LDAP_PAGE_SIZE", "500"))
    ldap_use_ssl: bool = _bool_env("LDAP_USE_SSL", True)
    critical_groups: tuple[str, ...] = tuple(_csv_env("CRITICAL_GROUPS"))


settings = Settings()
