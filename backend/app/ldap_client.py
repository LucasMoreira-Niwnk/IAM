from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ldap3 import ALL, Connection, Server, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from .config import Settings


USER_ATTRIBUTES = [
    "objectGUID",
    "sAMAccountName",
    "displayName",
    "mail",
    "userPrincipalName",
    "title",
    "department",
    "manager",
    "telephoneNumber",
    "l",
    "distinguishedName",
    "userAccountControl",
    "pwdLastSet",
    "lastLogonTimestamp",
    "memberOf",
]

GROUP_ATTRIBUTES = [
    "objectGUID",
    "cn",
    "description",
    "distinguishedName",
    "member",
]


@dataclass
class LdapSearchResult:
    users: list[dict[str, Any]]
    groups: list[dict[str, Any]]


@dataclass
class LdapAuthenticatedUser:
    username: str
    display_name: str | None
    email: str | None
    upn: str | None
    distinguished_name: str


class ReadOnlyLdapClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _connection(self) -> Connection:
        if not self.settings.ldap_server:
            raise RuntimeError("LDAP_SERVER nao configurado.")

        server = Server(
            self.settings.ldap_server,
            use_ssl=self.settings.ldap_use_ssl,
            get_info=ALL,
        )
        return Connection(
            server,
            user=self.settings.ldap_bind_dn,
            password=self.settings.ldap_bind_password,
            auto_bind=True,
            read_only=True,
            raise_exceptions=True,
        )

    def fetch_directory(self) -> LdapSearchResult:
        with self._connection() as connection:
            users = list(
                self._paged_search(
                    connection=connection,
                    search_base=self.settings.ldap_user_base_dn,
                    search_filter="(&(objectCategory=person)(objectClass=user))",
                    attributes=USER_ATTRIBUTES,
                ),
            )
            groups = list(
                self._paged_search(
                    connection=connection,
                    search_base=self.settings.ldap_group_base_dn,
                    search_filter="(objectClass=group)",
                    attributes=GROUP_ATTRIBUTES,
                ),
            )

        return LdapSearchResult(users=users, groups=groups)

    def authenticate_operator(self, username: str, password: str) -> LdapAuthenticatedUser | None:
        username = username.strip()
        if not username or not password:
            return None

        user = self._find_user(username)
        if not user:
            return None

        if not self._is_operator(user):
            return None

        user_dn = str(self._first(user.get("distinguishedName")) or "")
        user_upn = str(self._first(user.get("userPrincipalName")) or username)
        bind_user = user_dn or user_upn

        try:
            server = Server(
                self.settings.ldap_server,
                use_ssl=self.settings.ldap_use_ssl,
                get_info=ALL,
            )
            with Connection(
                server,
                user=bind_user,
                password=password,
                auto_bind=True,
                read_only=True,
                raise_exceptions=True,
            ):
                return LdapAuthenticatedUser(
                    username=str(self._first(user.get("sAMAccountName")) or username),
                    display_name=self._first(user.get("displayName")),
                    email=self._first(user.get("mail")),
                    upn=self._first(user.get("userPrincipalName")),
                    distinguished_name=user_dn,
                )
        except (LDAPBindError, LDAPException):
            return None

    def _find_user(self, username: str) -> dict[str, Any] | None:
        escaped = escape_filter_chars(username)
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            f"(|(sAMAccountName={escaped})(userPrincipalName={escaped})(mail={escaped})))"
        )

        with self._connection() as connection:
            connection.search(
                search_base=self.settings.ldap_user_base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=USER_ATTRIBUTES,
                size_limit=1,
            )
            if not connection.entries:
                return None
            return connection.entries[0].entry_attributes_as_dict

    def _is_operator(self, user: dict[str, Any]) -> bool:
        expected = self.settings.ldap_operator_group.strip().lower()
        if not expected:
            return True

        for group_dn in self._list_value(user.get("memberOf")):
            group_dn = str(group_dn)
            if group_dn.lower() == expected or self._cn_from_dn(group_dn).lower() == expected:
                return True
        return False

    @staticmethod
    def _first(value: Any) -> Any:
        if isinstance(value, list):
            return value[0] if value else None
        return value

    @staticmethod
    def _list_value(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _cn_from_dn(dn: str) -> str:
        first_part = dn.split(",", 1)[0]
        if first_part.upper().startswith("CN="):
            return first_part[3:]
        return dn

    def _paged_search(
        self,
        connection: Connection,
        search_base: str,
        search_filter: str,
        attributes: list[str],
    ) -> Iterable[dict[str, Any]]:
        cookie = None
        while True:
            connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=self.settings.ldap_page_size,
                paged_cookie=cookie,
            )

            for entry in connection.entries:
                yield entry.entry_attributes_as_dict

            controls = connection.result.get("controls", {})
            page_control = controls.get("1.2.840.113556.1.4.319", {})
            cookie = page_control.get("value", {}).get("cookie")
            if not cookie:
                break
