from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ldap3 import ALL, Connection, Server, SUBTREE

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
