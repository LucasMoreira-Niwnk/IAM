from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ldap3 import ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection, Server, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

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

GROUP_SCOPE_TYPES = {
    "global": 0x00000002,
    "domain_local": 0x00000004,
    "universal": 0x00000008,
}
SECURITY_ENABLED = 0x80000000
ACCOUNT_DISABLED_FLAG = 0x0002
NORMAL_ACCOUNT_FLAG = 0x0200


def normalize_dn(dn: str) -> str:
    return ",".join(part.strip().lower() for part in str(dn).split(",") if part.strip())


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
    access_level: str


class ReadOnlyLdapClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _connection(self, read_only: bool = True) -> Connection:
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
            read_only=read_only,
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
        login = username.strip()
        lookup_username = self._normalize_login(login)
        if not lookup_username or not password:
            return None

        user = self._find_user(lookup_username)
        if not user:
            return None

        user_dn = str(self._first(user.get("distinguishedName")) or "")
        user_upn = str(self._first(user.get("userPrincipalName")) or "")

        if not self._bind_as_user(login, password, user_dn, user_upn):
            return None

        access_level = self._iam_access_level(user)
        if not access_level:
            return None

        return LdapAuthenticatedUser(
            username=str(self._first(user.get("sAMAccountName")) or lookup_username),
            display_name=self._first(user.get("displayName")),
            email=self._first(user.get("mail")),
            upn=self._first(user.get("userPrincipalName")),
            distinguished_name=user_dn,
            access_level=access_level,
        )

    def create_group(
        self,
        name: str,
        target_ou: str,
        description: str | None,
        scope: str,
        group_type: str,
    ) -> dict[str, str]:
        group_name = name.strip()
        ou_dn = target_ou.strip()
        if not group_name:
            raise ValueError("Nome do grupo obrigatorio.")
        self._validate_target_ou(ou_dn)

        group_dn = f"CN={escape_rdn(group_name)},{ou_dn}"
        group_type_value = self._group_type_value(scope, group_type)
        attributes = {
            "cn": group_name,
            "sAMAccountName": group_name[:256],
            "groupType": group_type_value,
        }
        if description:
            attributes["description"] = description.strip()

        with self._connection(read_only=False) as connection:
            created = connection.add(
                dn=group_dn,
                object_class=["top", "group"],
                attributes=attributes,
            )
            if not created:
                self._raise_ldap_write_error(connection, "Falha LDAP ao criar grupo.")

        return {
            "name": group_name,
            "distinguished_name": group_dn,
            "description": description or "",
            "scope": scope,
            "type": group_type,
        }

    def _validate_target_ou(self, ou_dn: str) -> None:
        if not ou_dn.upper().startswith("OU="):
            raise ValueError("OU de destino invalida.")
        if not normalize_dn(ou_dn).endswith(normalize_dn(self.settings.ldap_base_dn)):
            raise ValueError(
                f"OU de destino fora da base LDAP configurada. Base esperada: {self.settings.ldap_base_dn}"
            )

    @staticmethod
    def _raise_ldap_write_error(connection: Connection, fallback: str) -> None:
        result_code = connection.result.get("result")
        description_result = connection.result.get("description")
        message = str(connection.result.get("message") or "")
        if result_code == 68 or description_result == "entryAlreadyExists":
            raise ValueError("Ja existe um objeto com esse nome na OU selecionada.")
        if result_code == 53 and "problem 5003" in message.lower():
            raise ValueError(
                "O AD recusou a operação porque a conta não possui uma senha válida. "
                "Defina uma senha que atenda à política do domínio antes de habilitar."
            )
        if result_code == 53 and "problem 5005" in message.lower():
            raise ValueError("O AD recusou a senha informada. Verifique complexidade, histórico e tamanho mínimo.")
        raise RuntimeError(message or str(description_result or fallback))

    def create_user(
        self,
        username: str,
        first_name: str,
        last_name: str,
        email: str,
        target_ou: str,
        password: str,
        must_change_password: bool,
        title: str | None = None,
        department: str | None = None,
    ) -> dict[str, str]:
        username = username.strip()
        first_name = first_name.strip()
        last_name = last_name.strip()
        email = email.strip()
        ou_dn = target_ou.strip()
        display_name = " ".join(part for part in [first_name, last_name] if part).strip() or username

        if not username or not first_name or not last_name:
            raise ValueError("Nome, sobrenome e usuario sao obrigatorios.")
        if not password:
            raise ValueError("Senha inicial obrigatoria.")
        self._validate_target_ou(ou_dn)

        user_dn = f"CN={escape_rdn(display_name)},{ou_dn}"
        attributes = {
            "cn": display_name,
            "givenName": first_name,
            "sn": last_name,
            "displayName": display_name,
            "sAMAccountName": username,
            "userPrincipalName": email or username,
            "userAccountControl": NORMAL_ACCOUNT_FLAG | ACCOUNT_DISABLED_FLAG,
        }
        if email:
            attributes["mail"] = email
        if title:
            attributes["title"] = title.strip()
        if department:
            attributes["department"] = department.strip()

        with self._connection(read_only=False) as connection:
            if not connection.add(
                dn=user_dn,
                object_class=["top", "person", "organizationalPerson", "user"],
                attributes=attributes,
            ):
                self._raise_ldap_write_error(connection, "Falha LDAP ao criar usuario.")

            self._replace_password(connection, user_dn, password)
            changes = {"userAccountControl": [(MODIFY_REPLACE, [NORMAL_ACCOUNT_FLAG])]}
            if must_change_password:
                changes["pwdLastSet"] = [(MODIFY_REPLACE, [0])]
            if not connection.modify(user_dn, changes):
                self._raise_ldap_write_error(connection, "Usuario criado, mas falha ao habilitar conta.")

        return {
            "username": username,
            "display_name": display_name,
            "email": email,
            "upn": email or username,
            "title": title or "",
            "department": department or "",
            "distinguished_name": user_dn,
        }

    def reset_password(self, user_dn: str, new_password: str, must_change_password: bool) -> None:
        if not new_password:
            raise ValueError("Nova senha obrigatoria.")
        with self._connection(read_only=False) as connection:
            self._replace_password(connection, user_dn, new_password)
            pwd_last_set = 0 if must_change_password else -1
            if not connection.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, [pwd_last_set])]}):
                self._raise_ldap_write_error(connection, "Senha alterada, mas falha ao atualizar pwdLastSet.")

    def unlock_user(self, user_dn: str) -> None:
        with self._connection(read_only=False) as connection:
            if not connection.modify(user_dn, {"lockoutTime": [(MODIFY_REPLACE, [0])]}):
                self._raise_ldap_write_error(connection, "Falha LDAP ao desbloquear usuario.")

    def set_user_enabled(self, user_dn: str, current_uac: int, enabled: bool) -> int:
        new_uac = int(current_uac or NORMAL_ACCOUNT_FLAG)
        if enabled:
            new_uac &= ~ACCOUNT_DISABLED_FLAG
        else:
            new_uac |= ACCOUNT_DISABLED_FLAG
        with self._connection(read_only=False) as connection:
            if not connection.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]}):
                self._raise_ldap_write_error(connection, "Falha LDAP ao alterar status do usuario.")
        return new_uac

    def move_user_to_ou(self, user_dn: str, target_ou: str) -> str:
        destination_ou = target_ou.strip()
        self._validate_target_ou(destination_ou)
        parts = str(user_dn or "").split(",", 1)
        if len(parts) != 2 or not parts[0].upper().startswith("CN="):
            raise ValueError("DN do usuario invalido para movimentacao.")

        relative_dn, current_parent = parts[0], parts[1]
        if normalize_dn(current_parent) == normalize_dn(destination_ou):
            raise ValueError("O usuario ja esta na OU selecionada.")

        new_dn = f"{relative_dn},{destination_ou}"
        with self._connection(read_only=False) as connection:
            moved = connection.modify_dn(
                dn=user_dn,
                relative_dn=relative_dn,
                delete_old_dn=True,
                new_superior=destination_ou,
            )
            if not moved:
                self._raise_ldap_write_error(connection, "Falha LDAP ao mover usuario para a OU selecionada.")
        return new_dn

    def add_user_to_group(self, user_dn: str, group_dn: str) -> None:
        with self._connection(read_only=False) as connection:
            if not connection.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]}):
                self._raise_ldap_write_error(connection, "Falha LDAP ao adicionar usuario ao grupo.")

    def remove_user_from_group(self, user_dn: str, group_dn: str) -> None:
        with self._connection(read_only=False) as connection:
            if not connection.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]}):
                self._raise_ldap_write_error(connection, "Falha LDAP ao remover usuario do grupo.")

    @staticmethod
    def _encoded_ad_password(password: str) -> bytes:
        return f'"{password}"'.encode("utf-16-le")

    def _replace_password(self, connection: Connection, user_dn: str, password: str) -> None:
        if not connection.modify(
            user_dn,
            {"unicodePwd": [(MODIFY_REPLACE, [self._encoded_ad_password(password)])]},
        ):
            self._raise_ldap_write_error(connection, "Falha LDAP ao definir senha.")

    @staticmethod
    def _group_type_value(scope: str, group_type: str) -> int:
        scope_value = GROUP_SCOPE_TYPES.get(scope)
        if not scope_value:
            raise ValueError("Escopo de grupo invalido.")

        if group_type == "security":
            unsigned_value = scope_value | SECURITY_ENABLED
            return unsigned_value - 0x100000000
        if group_type == "distribution":
            return scope_value
        raise ValueError("Tipo de grupo invalido.")

    def _bind_as_user(self, login: str, password: str, user_dn: str, user_upn: str) -> bool:
        bind_candidates = []
        for candidate in (user_upn, user_dn, login):
            if candidate and candidate not in bind_candidates:
                bind_candidates.append(candidate)

        for bind_user in bind_candidates:
            if self._try_bind(bind_user, password):
                return True
        return False

    def _try_bind(self, bind_user: str, password: str) -> bool:
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
                return True
        except (LDAPBindError, LDAPException):
            return False

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

    def _has_iam_access(self, user: dict[str, Any]) -> bool:
        return self._iam_access_level(user) is not None

    def _iam_access_level(self, user: dict[str, Any]) -> str | None:
        if self.settings.ldap_operator_group.strip() and self._is_member_of_group(user, self.settings.ldap_operator_group):
            return "admin_full"
        if self.settings.ldap_viewonly_group.strip() and self._is_member_of_group(user, self.settings.ldap_viewonly_group):
            return "view_only"
        return None

    def _is_member_of_group(self, user: dict[str, Any], expected_group: str) -> bool:
        expected = expected_group.strip().lower()
        if not expected:
            return True

        for group_dn in self._list_value(user.get("memberOf")):
            group_dn = str(group_dn)
            if group_dn.lower() == expected or self._cn_from_dn(group_dn).lower() == expected:
                return True

        user_dn = str(self._first(user.get("distinguishedName")) or "")
        if not user_dn:
            return False

        escaped_group = escape_filter_chars(expected_group.strip())
        escaped_user_dn = escape_filter_chars(user_dn)
        if expected_group.upper().startswith("CN="):
            group_filter = f"(distinguishedName={escaped_group})"
        else:
            group_filter = f"(|(cn={escaped_group})(sAMAccountName={escaped_group}))"

        search_filter = (
            "(&(objectClass=group)"
            f"{group_filter}"
            f"(member:1.2.840.113556.1.4.1941:={escaped_user_dn}))"
        )

        with self._connection() as connection:
            connection.search(
                search_base=self.settings.ldap_group_base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            return bool(connection.entries)

    @staticmethod
    def _normalize_login(login: str) -> str:
        if "\\" in login:
            return login.rsplit("\\", 1)[-1]
        return login

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
