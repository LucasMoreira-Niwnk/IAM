const API_BASE_URL = window.IAM_API_BASE_URL || localStorage.getItem("IAM_API_BASE_URL") || "";
const SESSION_TIMEOUT_MS =
  Number(window.IAM_SESSION_TIMEOUT_MS || localStorage.getItem("IAM_SESSION_TIMEOUT_MS")) || 30 * 60 * 1000;
const DISMISSED_NOTIFICATIONS_KEY = "IAM_DISMISSED_NOTIFICATIONS";
let sessionTimeoutId = null;
let sessionExpiryTimeoutId = null;

const state = {
  identities: [],
  groups: [],
  operators: [],
  critical: { users_count: 0, groups_count: 0, users: [], groups: [] },
  governance: { workspace_disabled_members: { groups: [], total: 0, by_group: {}, users: [] } },
  syncRuns: [],
  auditEvents: [],
  currentUser: null,
  selectedIdentityId: null,
  selectedIdentityGroups: [],
  selectedGroupDn: null,
  selectedGroupMembers: [],
  groupMemberSearch: "",
  copyGroupsSourceIdentityId: null,
  copyGroupsSourceGroups: [],
  selectedOperatorId: null,
  activeFilter: "all",
  identityPage: 1,
  identityPageSize: 10,
  groupPage: 1,
  groupPageSize: 10,
  dashboardRangeDays: 1,
  auditOperatorFilter: "",
  workspaceGovernanceSearch: "",
  loading: true,
  apiOnline: false,
  dismissedNotifications: loadDismissedNotifications(),
};

function loadDismissedNotifications() {
  try {
    const value = JSON.parse(localStorage.getItem(DISMISSED_NOTIFICATIONS_KEY) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function saveDismissedNotifications() {
  localStorage.setItem(DISMISSED_NOTIFICATIONS_KEY, JSON.stringify(state.dismissedNotifications.slice(-200)));
}

function notificationId(notification) {
  return [notification.type, notification.title, notification.description, notification.time].join("|");
}

function dismissNotification(id) {
  if (!id || state.dismissedNotifications.includes(id)) return;
  state.dismissedNotifications.push(id);
  saveDismissedNotifications();
  renderNotifications();
}

function dismissVisibleNotifications() {
  const ids = dashboardNotifications().map(notificationId);
  state.dismissedNotifications = Array.from(new Set([...state.dismissedNotifications, ...ids]));
  saveDismissedNotifications();
  renderNotifications();
}

const statusLabels = {
  active: "Ativo",
  pending: "Pendente",
  review: "Em revisão",
  blocked: "Bloqueado",
  disabled: "Desabilitado",
  success: "Sucesso",
  failed: "Falha",
  running: "Em execução",
  failure: "Falha",
  error: "Erro",
};

const riskLabels = {
  low: "Baixo",
  medium: "Médio",
  high: "Alto",
};

const permissions = [
  {
    key: "viewIdentities",
    title: "Consultar identidades",
    description: "Pesquisar usuários e visualizar atributos importados do AD.",
  },
  {
    key: "resetPassword",
    title: "Alterar senha",
    description: "Redefinir senha e exigir troca no próximo logon.",
  },
  {
    key: "lockUnlock",
    title: "Bloquear ou desbloquear",
    description: "Bloquear, desbloquear e encerrar sessões do usuário.",
  },
  {
    key: "manageGroups",
    title: "Editar grupos",
    description: "Adicionar ou remover o usuário de grupos permitidos.",
  },
  {
    key: "managePrivilegedGroups",
    title: "Editar grupos privilegiados",
    description: "Alterar grupos administrativos como VPN-Admin e M365-Admin.",
  },
  {
    key: "syncAd",
    title: "Sincronizar AD",
    description: "Executar leitura manual do diretório e atualizar cache.",
  },
  {
    key: "manageOperators",
    title: "Gerenciar operadores",
    description: "Criar usuários internos e alterar permissões do IAM.",
  },
  {
    key: "viewAudit",
    title: "Auditoria",
    description: "Consultar logs das alterações feitas via conta de serviço.",
  },
];

function apiUrl(path) {
  return `${API_BASE_URL}${path}`;
}

async function apiGet(path) {
  const response = await fetch(apiUrl(path), {
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    if (response.status === 401) {
      await logout("expired");
      throw new Error("Sessao expirada.");
    }
    throw new Error(`GET ${path} retornou ${response.status}`);
  }
  return response.json();
}

async function apiPost(path, payload = null) {
  const csrfToken = sessionStorage.getItem("IAM_CSRF_TOKEN");
  const options = {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json" },
  };
  if (csrfToken) {
    options.headers["X-CSRF-Token"] = csrfToken;
  }
  if (payload !== null) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }

  const response = await fetch(apiUrl(path), {
    ...options,
  });
  if (!response.ok) {
    if (response.status === 401) {
      await logout("expired");
      throw new Error("Sessao expirada.");
    }
    const detail = await response.text();
    let message = detail || `POST ${path} retornou ${response.status}`;
    try {
      const parsed = JSON.parse(detail);
      message = parsed.detail || message;
    } catch {
      // Mantem a mensagem de texto original quando a resposta nao for JSON.
    }
    throw new Error(message);
  }
  return response.json();
}

async function apiGetOptional(path) {
  try {
    return await apiGet(path);
  } catch {
    return null;
  }
}

async function logout(reason = "manual") {
  try {
    await apiPost("/api/auth/logout");
  } catch {
    // O backend atual ainda pode não ter autenticação. Mesmo assim, limpamos o estado local.
  }

  sessionStorage.removeItem("IAM_CSRF_TOKEN");
  sessionStorage.removeItem("IAM_SESSION_EXPIRES_AT");
  if (reason === "timeout") {
    sessionStorage.setItem("IAM_LOGOUT_REASON", "Sua sessão expirou por inatividade.");
  }
  if (reason === "expired") {
    sessionStorage.setItem("IAM_LOGOUT_REASON", "Sua sessao expirou. Entre novamente.");
  }

  window.location.href = "/login.html";
}

function resetSessionTimer() {
  window.clearTimeout(sessionTimeoutId);
  sessionTimeoutId = window.setTimeout(() => {
    logout("timeout");
  }, SESSION_TIMEOUT_MS);
}

function scheduleSessionExpiry(expiresAt) {
  window.clearTimeout(sessionExpiryTimeoutId);
  const expiresAtMs = Number(expiresAt || sessionStorage.getItem("IAM_SESSION_EXPIRES_AT")) * 1000;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return;

  const delay = expiresAtMs - Date.now();
  if (delay <= 0) {
    logout("expired");
    return;
  }

  sessionExpiryTimeoutId = window.setTimeout(() => {
    logout("expired");
  }, delay);
}

function startSessionTimer() {
  ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach((eventName) => {
    document.addEventListener(eventName, resetSessionTimer, { passive: true });
  });
  resetSessionTimer();
  scheduleSessionExpiry();
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => toast.classList.remove("is-visible"), 3200);
}

function initials(name = "") {
  const base = name || "?";
  return base
    .split(" ")
    .filter(Boolean)
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

function identityName(identity) {
  return identity.display_name || identity.username || identity.upn || "Usuário sem nome";
}

function identityEmail(identity) {
  return identity.email || identity.upn || "";
}

function statusLabel(status) {
  return statusLabels[status] || status || "Indefinido";
}

function statusClass(status) {
  const classes = {
    success: "success",
    failed: "high",
    failure: "high",
    error: "high",
    running: "review",
  };
  return classes[status] || status || "review";
}

function criticality(identity) {
  const count = Number(identity.critical_group_count || 0);
  if (count >= 2) return "high";
  if (count === 1) return "medium";
  return "low";
}

function criticalityLabel(identity) {
  return riskLabels[criticality(identity)];
}

function parsePermissions(raw) {
  if (!raw) return {};
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function permissionSourceLabel(source) {
  const labels = {
    "ad-admin-full": "Grupo AD: Admin full",
    "ad-view-only": "Grupo AD: Visualização",
    "ad-view-only-custom": "Grupo AD: Visualização customizada",
    "ldap-login-admin-full": "Login LDAP: Admin full",
    "ldap-login-view-only": "Login LDAP: Visualização",
    local: "Permissões locais",
  };
  return labels[source] || "Sem grupo de permissão";
}

function auditActionLabel(action) {
  const labels = {
    create_group: "Criação de grupo",
    create_user: "Criação de usuário",
    reset_password: "Alteração de senha",
    unlock_identity: "Desbloqueio de identidade",
    block_identity: "Bloqueio de identidade",
    disable_identity: "Desabilitação de identidade",
    enable_identity: "Habilitação de identidade",
    move_identity_ou: "Movimentação de OU",
    add_group_member: "Adição em grupo",
    remove_group_member: "Remoção de grupo",
    update_operator_permissions: "Alteração de permissões",
    remove_operator: "Remoção de operador",
    sync_ad: "Sincronização AD",
    sync_google_workspace: "Sync Google Workspace",
  };
  return labels[action] || action || "Evento";
}

function auditDetails(event) {
  if (!event?.details_json) return {};
  try {
    return JSON.parse(event.details_json);
  } catch {
    return {};
  }
}

function auditEventDescription(event) {
  const details = auditDetails(event);
  const operator = event.operator_display_name || event.operator_username || "Sistema";
  const target = event.target_name || event.target_dn || event.target_type || "-";
  const parts = [`Operador: ${operator}`, `Objeto: ${target}`];

  if (event.action === "add_group_member" || event.action === "remove_group_member") {
    parts.push(`Grupo: ${details.group || details.group_name || "Não informado"}`);
  }
  if (event.action === "create_user" && details.username) {
    parts.push(`Usuário criado: ${details.username}`);
  }
  if (event.action === "create_group") {
    parts.push(`Grupo criado: ${target}`);
  }
  if (event.action === "move_identity_ou") {
    parts.push(`Nova OU: ${details.target_ou || details.new_dn || "Não informado"}`);
  }
  if (event.action === "sync_ad") {
    parts.push(`${details.users_synced || 0} usuários, ${details.groups_synced || 0} grupos`);
  }
  if (event.action === "sync_google_workspace") {
    parts.push(`Retorno: ${details.return_code ?? "-"}`);
  }

  return parts.join(" - ");
}

function isAdChangeEvent(event) {
  return [
    "create_group",
    "create_user",
    "reset_password",
    "unlock_identity",
    "block_identity",
    "disable_identity",
    "enable_identity",
    "move_identity_ou",
    "add_group_member",
    "remove_group_member",
  ].includes(event?.action);
}

function criticalGroupNames() {
  return new Set(
    state.groups
      .filter((group) => Number(group.is_critical) === 1)
      .map((group) => String(group.name || "").toLowerCase()),
  );
}

function eventTargetsCriticalGroup(event) {
  const details = auditDetails(event);
  const groupName = String(details.group || details.group_name || "").toLowerCase();
  if (!groupName) return false;
  return criticalGroupNames().has(groupName);
}

function currentPermissions() {
  return parsePermissions(state.currentUser?.permissions);
}

function hasPermission(permissionKey) {
  return Boolean(currentPermissions()[permissionKey]);
}

function disableByPermission(selector, permissionKey) {
  document.querySelectorAll(selector).forEach((element) => {
    element.disabled = !hasPermission(permissionKey);
    element.classList.toggle("is-permission-disabled", !hasPermission(permissionKey));
  });
}

function selectedIdentity() {
  return state.identities.find((identity) => identity.id === state.selectedIdentityId) || state.identities[0];
}

function selectedOperator() {
  return state.operators.find((operator) => operator.identity_id === state.selectedOperatorId) || state.operators[0];
}

function formatSyncTime(value) {
  if (!value) return "Sem registro";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("pt-BR");
}

function dateFromValue(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function isWithinDashboardRange(value) {
  const date = dateFromValue(value);
  if (!date) return false;
  const cutoff = Date.now() - state.dashboardRangeDays * 24 * 60 * 60 * 1000;
  return date.getTime() >= cutoff;
}

function dashboardAuditEvents() {
  return state.auditEvents.filter((event) => isWithinDashboardRange(event.occurred_at));
}

function dashboardSyncRuns() {
  return state.syncRuns.filter((run) => isWithinDashboardRange(run.finished_at || run.started_at));
}

function latestSyncRun() {
  return state.syncRuns[0] || null;
}

function renderEmpty(targetSelector, message) {
  document.querySelector(targetSelector).innerHTML = `<div class="empty-state">${message}</div>`;
}

function renderMetrics() {
  const activeUsers = state.identities.filter((identity) => identity.status === "active").length;
  const operationsToday = state.syncRuns.filter((run) => {
    if (!run.started_at) return false;
    const started = new Date(run.started_at);
    const today = new Date();
    return started.toDateString() === today.toDateString();
  }).length;

  document.querySelector("#metric-users").textContent = activeUsers;
  document.querySelector("#metric-privileged").textContent = state.critical.users_count || 0;
  document.querySelector("#metric-operations").textContent = operationsToday;
  document.querySelector("#metric-operators").textContent = state.operators.length;
  document.querySelector("#metric-gw-users").textContent =
    state.governance.workspace_disabled_members?.members_total || 0;
}

function currentUserName() {
  if (state.currentUser?.display_name) return state.currentUser.display_name;
  if (state.currentUser?.name) return state.currentUser.name;
  if (state.currentUser?.username) return state.currentUser.username;
  if (state.operators[0]?.display_name) return state.operators[0].display_name;
  if (state.operators[0]?.username) return state.operators[0].username;
  return "Operador IAM";
}

function renderCurrentUser() {
  const name = currentUserName();
  const role =
    state.currentUser?.title ||
    state.operators.find((operator) => operator.display_name === name || operator.username === name)?.title ||
    "";
  const roleElement = document.querySelector("#current-user-role");

  document.querySelector("#current-user-avatar").textContent = initials(name);
  document.querySelector("#current-user-name").textContent = name;
  roleElement.textContent = role;
  roleElement.hidden = !role;
}

function renderReviews() {
  const reviewList = document.querySelector("#review-list");
  const latestChanges = dashboardAuditEvents().filter(isAdChangeEvent).slice(0, 6);

  if (!latestChanges.length) {
    renderEmpty("#review-list", "Nenhuma alteração registrada no período selecionado.");
    return;
  }

  reviewList.innerHTML = latestChanges
    .map((event) => {
      const operator = event.operator_display_name || event.operator_username || "Sistema";
      const target = event.target_name || event.target_type || "Objeto do AD";
      const isCritical = event.action === "add_group_member" && eventTargetsCriticalGroup(event);
      return `
        <article class="review-item">
          <div>
            <strong>${auditActionLabel(event.action)}</strong>
            <span>${formatSyncTime(event.occurred_at)} - ${operator} em ${target}</span>
          </div>
          <span class="badge ${isCritical ? "high" : statusClass(event.status)}">
            ${isCritical ? "Crítico" : statusLabel(event.status)}
          </span>
        </article>
      `;
    })
    .join("");
}

function renderSidebarSyncStatus() {
  const latest = latestSyncRun();
  const statusEl = document.querySelector("#sidebar-sync-status");
  const lastSyncEl = document.querySelector("#sidebar-last-sync");

  if (!latest) {
    statusEl.textContent = "Sincronização pendente";
    lastSyncEl.textContent = "Última leitura: sem registro";
    return;
  }

  statusEl.textContent =
    latest.status === "success" ? "Sincronização concluída" : `Sincronização ${statusLabel(latest.status)}`;
  lastSyncEl.textContent = `Última leitura: ${formatSyncTime(latest.finished_at || latest.started_at)}`;
}

function renderDirectoryIndicators() {
  const riskyUsers = [...state.identities]
    .filter((identity) => Number(identity.critical_group_count || 0) > 0)
    .sort((a, b) => Number(b.critical_group_count || 0) - Number(a.critical_group_count || 0))
    .slice(0, 5);

  document.querySelector("#risk-bars").innerHTML = riskyUsers.length
    ? riskyUsers
        .map((identity) => {
          const criticalCount = Number(identity.critical_group_count || 0);
          const width = Math.min(100, criticalCount * 25);
          return `
            <article class="risk-row risk-user" data-dashboard-identity="${identity.id}">
              <div class="risk-meta">
                <span>${identityName(identity)}</span>
                <span>${criticalCount} grupo(s)</span>
              </div>
              <small>${identity.username || identityEmail(identity) || "-"}</small>
              <div class="bar" aria-hidden="true"><span style="width: ${width}%"></span></div>
            </article>
          `;
        })
        .join("")
    : `<div class="empty-state">Nenhum usuário em grupo crítico no cache atual.</div>`;

  const operatorStats = dashboardAuditEvents().filter(isAdChangeEvent).reduce((acc, event) => {
    const key = event.operator_username || event.operator_display_name || "Sistema";
    if (!acc[key]) {
      acc[key] = {
        name: event.operator_display_name || event.operator_username || "Sistema",
        count: 0,
      };
    }
    acc[key].count += 1;
    return acc;
  }, {});
  const topOperators = Object.values(operatorStats).sort((a, b) => b.count - a.count).slice(0, 5);
  const maxOperatorChanges = Math.max(...topOperators.map((operator) => operator.count), 1);

  document.querySelector("#operator-ranking").innerHTML = topOperators.length
    ? topOperators
        .map(
          (operator) => `
            <article class="risk-row">
              <div class="risk-meta">
                <span>${operator.name}</span>
                <span>${operator.count}</span>
              </div>
              <small>alterações registradas</small>
              <div class="bar" aria-hidden="true"><span style="width: ${Math.round((operator.count / maxOperatorChanges) * 100)}%"></span></div>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhuma alteração de operador registrada.</div>`;
}

function renderWorkspaceGovernance() {
  const data = state.governance.workspace_disabled_members || { total: 0, users: [] };
  const users = data.users || [];
  const groupCounts = data.by_group || {};
  const groups = data.groups?.length ? data.groups : ["GW-Business Standard", "GW-Enterprise Starter"];
  document.querySelector("#workspace-disabled-summary").innerHTML = groups
    .map(
      (groupName) => `
        <article class="governance-summary-card">
          <span>${groupName}</span>
          <strong>${groupCounts[groupName] || 0}</strong>
          <small>usuário(s) desabilitado(s)</small>
        </article>
      `,
    )
    .join("");

  document.querySelector("#workspace-disabled-list").innerHTML = users.length
    ? users
        .slice(0, 5)
        .map(
          (identity) => `
            <article class="governance-item" data-governance-identity="${identity.id}">
              <div>
                <strong>${identityName(identity)}</strong>
                <span>${identity.username || identity.email || "-"}</span>
              </div>
              <div>
                <span class="badge disabled">Desabilitado</span>
                <small>${identity.group_name}</small>
              </div>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum usuário desabilitado nos grupos GW-Business Standard ou GW-Enterprise Starter.</div>`;
}

function filteredWorkspaceGovernanceUsers() {
  const data = state.governance.workspace_disabled_members || { users: [] };
  const searchTerm = state.workspaceGovernanceSearch.trim().toLowerCase();
  return (data.users || []).filter((identity) => {
    if (!searchTerm) return true;
    return [identityName(identity), identity.username, identity.email, identity.department, identity.group_name]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(searchTerm);
  });
}

function renderWorkspaceGovernanceModal() {
  const data = state.governance.workspace_disabled_members || { total: 0, users: [] };
  const users = filteredWorkspaceGovernanceUsers();
  document.querySelector("#workspace-governance-total").textContent = `${data.total || 0} alerta(s)`;
  document.querySelector("#workspace-governance-list").innerHTML = users.length
    ? users
        .map(
          (identity) => `
            <article class="governance-item governance-item-full" data-governance-identity="${identity.id}">
              <div>
                <strong>${identityName(identity)}</strong>
                <span>${identity.username || identity.email || "-"}</span>
                <small>${identity.department || "Sem departamento informado"}</small>
              </div>
              <div>
                <span class="badge disabled">Desabilitado</span>
                <small>${identity.group_name}</small>
              </div>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum resultado encontrado para a busca atual.</div>`;
}

function openWorkspaceGovernanceModal() {
  state.workspaceGovernanceSearch = "";
  document.querySelector("#workspace-governance-search").value = "";
  renderWorkspaceGovernanceModal();
  openModal("#workspace-governance-modal");
  window.setTimeout(() => document.querySelector("#workspace-governance-search").focus(), 0);
}

function dashboardNotifications() {
  const failedSyncs = dashboardSyncRuns().filter((run) => run.status && run.status !== "success").slice(0, 3);
  const criticalAdds = dashboardAuditEvents()
    .filter((event) => event.action === "add_group_member" && eventTargetsCriticalGroup(event))
    .slice(0, 5);

  const notifications = [
    ...failedSyncs.map((run) => ({
      type: "Falha no sync",
      title: `Sincronização ${statusLabel(run.status)}`,
      description: run.error_message || `Execução iniciada em ${formatSyncTime(run.started_at)}`,
      severity: "high",
      time: run.finished_at || run.started_at,
    })),
    ...criticalAdds.map((event) => {
      const details = auditDetails(event);
      return {
        type: "Grupo crítico",
        title: event.target_name || "Usuário alterado",
        description: `Inserido em ${details.group || "grupo crítico"} por ${event.operator_display_name || event.operator_username || "operador"}`,
        severity: "high",
        time: event.occurred_at,
      };
    }),
  ].sort((a, b) => new Date(b.time || 0) - new Date(a.time || 0));

  return notifications.filter((notification) => !state.dismissedNotifications.includes(notificationId(notification)));
}

function renderNotifications() {
  const notifications = dashboardNotifications();
  const button = document.querySelector("#notification-button");
  const count = document.querySelector("#notification-count");
  const panel = document.querySelector("#notification-panel");

  count.textContent = notifications.length;
  button.classList.toggle("has-notifications", notifications.length > 0);
  if (!notifications.length) {
    panel.innerHTML = `
      <div class="notification-header">
        <strong>Notificações</strong>
        <span>0 alerta</span>
      </div>
      <div class="empty-state">Sem alertas de sync ou grupos críticos.</div>
    `;
    return;
  }

  panel.innerHTML = `
    <div class="notification-header">
      <strong>Notificações</strong>
      <button class="text-button notification-clear" type="button" data-notification-clear>Limpar todas</button>
    </div>
    ${notifications
      .map(
        (notification) => `
          <article class="notification-item">
            <div class="notification-item-head">
              <span class="badge ${notification.severity}">${notification.type}</span>
              <button class="icon-button notification-dismiss" type="button" title="Remover notificação" aria-label="Remover notificação" data-notification-dismiss="${encodeURIComponent(notificationId(notification))}">x</button>
            </div>
            <strong>${notification.title}</strong>
            <small>${notification.description}</small>
            <small>${formatSyncTime(notification.time)}</small>
          </article>
        `,
      )
      .join("")}
  `;
}

function renderIdentities() {
  const searchTerm = globalSearchTerm();
  const users = state.identities.filter((identity) => {
    const matchesFilter = state.activeFilter === "all" || identity.status === state.activeFilter;
    const searchable = [
      identityName(identity),
      identityEmail(identity),
      identity.username,
      identity.department,
      identity.distinguished_name,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return matchesFilter && searchable.includes(searchTerm);
  });

  if (!users.length) {
    document.querySelector("#identity-table").innerHTML = `
      <tr><td colspan="7">Nenhuma identidade encontrada. Execute a sincronização com o AD.</td></tr>
    `;
    document.querySelector("#identity-pagination").innerHTML = "";
    return;
  }

  const totalPages = Math.max(1, Math.ceil(users.length / state.identityPageSize));
  state.identityPage = Math.min(Math.max(1, state.identityPage), totalPages);
  const start = (state.identityPage - 1) * state.identityPageSize;
  const visibleUsers = users.slice(start, start + state.identityPageSize);

  document.querySelector("#identity-table").innerHTML = visibleUsers
    .map(
      (identity) => `
        <tr class="clickable-row" data-identity-id="${identity.id}">
          <td>
            <div class="user-cell">
              <span class="avatar">${initials(identityName(identity))}</span>
              <div>
                <strong>${identityName(identity)}</strong><br />
                <small>${identityEmail(identity)}</small>
              </div>
            </div>
          </td>
          <td>${identity.department || "-"}</td>
          <td>AD</td>
          <td><span class="badge ${statusClass(identity.status)}">${statusLabel(identity.status)}</span></td>
          <td><span class="badge ${criticality(identity)}">${criticalityLabel(identity)}</span></td>
          <td>${identity.group_count || 0}</td>
          <td><button class="text-button" type="button" data-open-identity="${identity.id}">Detalhes</button></td>
        </tr>
      `,
    )
    .join("");

  const firstItem = start + 1;
  const lastItem = Math.min(start + state.identityPageSize, users.length);
  document.querySelector("#identity-pagination").innerHTML = `
    <span>Mostrando ${firstItem}-${lastItem} de ${users.length}</span>
    <div class="pagination-actions">
      <button class="ghost-button" type="button" data-page-action="prev" ${state.identityPage === 1 ? "disabled" : ""}>Anterior</button>
      <strong>Página ${state.identityPage} de ${totalPages}</strong>
      <button class="ghost-button" type="button" data-page-action="next" ${state.identityPage === totalPages ? "disabled" : ""}>Próxima</button>
    </div>
  `;
}

function globalSearchTerm() {
  return document.querySelector("#global-search").value.trim().toLowerCase();
}

function normalizeText(value) {
  return String(value || "").trim().toLowerCase();
}

function groupMatchesSearch(group, searchTerm) {
  if (!searchTerm) return true;
  return [group.name, group.description, group.distinguished_name]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(searchTerm);
}

function identityMatchesSearch(identity, searchTerm) {
  if (!searchTerm) return true;
  return [identityName(identity), identityEmail(identity), identity.username, identity.department, identity.distinguished_name]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(searchTerm);
}

function isAdLocked(identity) {
  return Number(identity.lockout_time || 0) > 0 || identity.status === "blocked";
}

async function renderIdentityDetail(identityId) {
  if (identityId) state.selectedIdentityId = identityId;
  const identity = selectedIdentity();
  if (!identity) {
    renderEmpty("#identity-hero", "Nenhuma identidade selecionada.");
    return;
  }

  try {
    state.selectedIdentityGroups = await apiGet(`/api/identities/${identity.id}/groups`);
  } catch {
    state.selectedIdentityGroups = [];
    showToast("Não foi possível carregar os grupos desta identidade.");
  }

  const blockButton = document.querySelector("[data-identity-action='block']");
  const unlockButton = document.querySelector("[data-identity-action='unlock']");
  const disableButton = document.querySelector("[data-identity-action='disable']");

  blockButton.disabled = identity.status === "blocked" || identity.status === "disabled";
  unlockButton.disabled = identity.status !== "blocked";
  disableButton.textContent = identity.status === "disabled" ? "Habilitar" : "Desabilitar";

  document.querySelector("#identity-hero").innerHTML = `
    <div class="identity-avatar">${initials(identityName(identity))}</div>
    <div>
      <p class="eyebrow">${identity.department || "Diretório"}</p>
      <h2>${identityName(identity)}</h2>
      <span>${identity.title || "Sem cargo informado"} - ${identityEmail(identity)}</span>
    </div>
    <div class="identity-badges">
      <span class="badge ${statusClass(identity.status)}">${statusLabel(identity.status)}</span>
      <span class="badge ${criticality(identity)}">Criticidade ${criticalityLabel(identity)}</span>
    </div>
  `;

  const info = [
    ["Usuário", identity.username],
    ["UPN", identity.upn],
    ["Telefone", identity.phone],
    ["Localidade", identity.location],
    ["Distinguished Name", identity.distinguished_name],
    ["Última sincronização", formatSyncTime(identity.synced_at)],
  ];

  document.querySelector("#identity-info").innerHTML = info
    .map(([label, value]) => `<div><dt>${label}</dt><dd>${value || "-"}</dd></div>`)
    .join("");

  document.querySelector("#identity-security").innerHTML = `
    <article>
      <span>Bloqueio no AD</span>
      <strong>${isAdLocked(identity) ? "Bloqueada" : "Nao bloqueada"}</strong>
    </article>
    <article>
      <span>lockoutTime</span>
      <strong>${identity.lockout_time || "0"}</strong>
    </article>
    <article>
      <span>pwdLastSet</span>
      <strong>${identity.pwd_last_set || "-"}</strong>
    </article>
    <article>
      <span>lastLogonTimestamp</span>
      <strong>${identity.last_logon_timestamp || "-"}</strong>
    </article>
  `;

  const groups = state.selectedIdentityGroups;
  document.querySelector("#identity-groups").innerHTML = groups.length
    ? groups
        .map(
          (group) => `
            <article class="group-item" data-edit-group="${encodeURIComponent(group.group_name)}">
              <div>
                <strong>${group.group_name}</strong>
                <span>${group.is_critical ? "Crítico" : "Padrão"}</span>
              </div>
              <button class="text-button" type="button" data-edit-group="${encodeURIComponent(group.group_name)}">Editar</button>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum grupo retornado pela API.</div>`;

  document.querySelector("#identity-apps").innerHTML = groups.length
    ? groups
        .filter((group) => group.is_critical)
        .map((group) => `<article><strong>${group.group_name}</strong><span>Grupo crítico no AD</span></article>`)
        .join("") || `<div class="empty-state">Nenhum grupo crítico associado.</div>`
    : `<div class="empty-state">Sem dados de grupos para avaliar impacto.</div>`;

  document.querySelector("#identity-events").innerHTML = `
    <li>Dados sincronizados do AD em ${formatSyncTime(identity.synced_at)}</li>
    <li>Conta atualmente marcada como ${statusLabel(identity.status)}</li>
    <li>${identity.critical_group_count || 0} grupo(s) crítico(s) associado(s)</li>
  `;
}

function renderAccess() {
  const searchTerm = globalSearchTerm();
  const groups = state.groups.filter((group) => groupMatchesSearch(group, searchTerm));

  if (!groups.length) {
    renderEmpty(
      "#access-grid",
      searchTerm ? "Nenhum grupo encontrado para a busca atual." : "Nenhum grupo sincronizado ainda.",
    );
    document.querySelector("#group-pagination").innerHTML = "";
    return;
  }

  const totalPages = Math.max(1, Math.ceil(groups.length / state.groupPageSize));
  state.groupPage = Math.min(Math.max(1, state.groupPage), totalPages);
  const start = (state.groupPage - 1) * state.groupPageSize;
  const visibleGroups = groups.slice(start, start + state.groupPageSize);

  document.querySelector("#access-grid").innerHTML = visibleGroups
    .map(
      (group) => `
        <article class="access-card clickable-card" data-group-open="${encodeURIComponent(group.distinguished_name)}">
          <div>
            <strong>${group.name}</strong>
            <span>${group.description || "Sem descrição"}</span>
          </div>
          <span class="badge ${group.is_critical ? "high" : "low"}">${group.is_critical ? "Crítico" : "Padrão"}</span>
          <footer>
            <span>${group.member_count || 0} membros</span>
            <span>AD</span>
          </footer>
        </article>
      `,
    )
    .join("");

  const firstItem = start + 1;
  const lastItem = Math.min(start + state.groupPageSize, groups.length);
  document.querySelector("#group-pagination").innerHTML = `
    <span>Mostrando ${firstItem}-${lastItem} de ${groups.length}</span>
    <div class="pagination-actions">
      <button class="ghost-button" type="button" data-group-page-action="prev" ${state.groupPage === 1 ? "disabled" : ""}>Anterior</button>
      <strong>Página ${state.groupPage} de ${totalPages}</strong>
      <button class="ghost-button" type="button" data-group-page-action="next" ${state.groupPage === totalPages ? "disabled" : ""}>Próxima</button>
    </div>
  `;
}

function selectedGroup() {
  return state.groups.find((group) => group.distinguished_name === state.selectedGroupDn) || null;
}

function groupMemberIds() {
  return new Set(state.selectedGroupMembers.map((member) => member.id));
}

function renderGroupDetail() {
  const group = selectedGroup();
  if (!group) {
    renderEmpty("#group-member-list", "Selecione um grupo para visualizar os membros.");
    renderEmpty("#group-candidate-list", "");
    return;
  }

  document.querySelector("#group-hero").innerHTML = `
    <div class="identity-avatar">G</div>
    <div>
      <p class="eyebrow">Active Directory</p>
      <h2>${group.name}</h2>
      <span>${group.description || "Sem descrição"} - ${group.member_count || 0} membro(s)</span>
      <span>${group.distinguished_name}</span>
    </div>
    <div class="identity-badges">
      <span class="badge ${group.is_critical ? "high" : "low"}">${group.is_critical ? "Crítico" : "Padrão"}</span>
    </div>
  `;

  document.querySelector("#group-member-list").innerHTML = state.selectedGroupMembers.length
    ? state.selectedGroupMembers
        .map(
          (member) => `
            <article class="group-member-card">
              <span class="avatar">${initials(identityName(member))}</span>
              <div>
                <strong>${identityName(member)}</strong>
                <small>${member.username || identityEmail(member) || "-"}</small>
              </div>
              <button class="text-button danger-text" type="button" data-group-member-remove="${member.id}">Remover</button>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum membro retornado pelo último sync.</div>`;

  renderGroupCandidates();
}

function renderGroupCandidates() {
  const group = selectedGroup();
  if (!group) return;

  const searchTerm = state.groupMemberSearch.trim().toLowerCase();
  const currentMembers = groupMemberIds();
  const candidates = state.identities
    .filter((identity) => !currentMembers.has(identity.id))
    .filter((identity) => {
      if (!searchTerm) return true;
      return [identityName(identity), identityEmail(identity), identity.username, identity.department]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(searchTerm);
    })
    .slice(0, 20);

  document.querySelector("#group-candidate-list").innerHTML = candidates.length
    ? candidates
        .map(
          (identity) => `
            <article class="group-member-card">
              <span class="avatar">${initials(identityName(identity))}</span>
              <div>
                <strong>${identityName(identity)}</strong>
                <small>${identity.username || identityEmail(identity) || "-"}</small>
              </div>
              <button class="text-button" type="button" data-group-member-add="${identity.id}">Adicionar</button>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum usuário disponível para a busca atual.</div>`;
}

async function openGroupDetail(groupDn) {
  state.selectedGroupDn = groupDn;
  state.groupMemberSearch = "";
  document.querySelector("#group-member-search").value = "";
  await refreshSelectedGroupMembers();
  switchView("group-detail");
}

async function refreshSelectedGroupMembers() {
  if (!state.selectedGroupDn) return;
  state.selectedGroupMembers = await apiGet(`/api/group-members?group_dn=${encodeURIComponent(state.selectedGroupDn)}`);
  const group = selectedGroup();
  if (group) group.member_count = state.selectedGroupMembers.length;
  renderGroupDetail();
  applyPermissionState();
}

function renderGlobalSearchResults() {
  const panel = document.querySelector("#global-search-results");
  const searchTerm = globalSearchTerm();

  if (!searchTerm) {
    panel.classList.remove("is-visible");
    panel.innerHTML = "";
    return;
  }

  const matchedUsers = state.identities.filter((identity) => identityMatchesSearch(identity, searchTerm)).slice(0, 6);
  const matchedGroups = state.groups.filter((group) => groupMatchesSearch(group, searchTerm)).slice(0, 6);

  if (!matchedUsers.length && !matchedGroups.length) {
    panel.innerHTML = `<div class="search-empty">Nenhum usuário ou grupo encontrado.</div>`;
    panel.classList.add("is-visible");
    return;
  }

  panel.innerHTML = `
    ${
      matchedUsers.length
        ? `<section>
            <strong>Usuários</strong>
            ${matchedUsers
              .map(
                (identity) => `
                  <button type="button" data-search-identity="${identity.id}">
                    <span class="avatar">${initials(identityName(identity))}</span>
                    <span>
                      <b>${identityName(identity)}</b>
                      <small>${identityEmail(identity) || identity.username || ""}</small>
                    </span>
                  </button>
                `,
              )
              .join("")}
          </section>`
        : ""
    }
    ${
      matchedGroups.length
        ? `<section>
            <strong>Grupos</strong>
            ${matchedGroups
              .map(
                (group) => `
                  <button type="button" data-search-group="${encodeURIComponent(group.distinguished_name)}">
                    <span class="avatar">G</span>
                    <span>
                      <b>${group.name}</b>
                      <small>${group.member_count || 0} membros</small>
                    </span>
                  </button>
                `,
              )
              .join("")}
          </section>`
        : ""
    }
  `;
  panel.classList.add("is-visible");
}

function renderCriticalPermissions() {
  document.querySelector("#critical-user-count").textContent = state.critical.users_count || 0;
  document.querySelector("#critical-group-count").textContent = state.critical.groups_count || 0;
  document.querySelector("#critical-disabled-count").textContent = (state.critical.users || []).filter(
    (identity) => identity.status === "disabled" || identity.status === "blocked",
  ).length;

  document.querySelector("#critical-groups").innerHTML = state.critical.groups?.length
    ? state.critical.groups
        .map(
          (group) => `
            <article class="critical-group-row">
              <div>
                <strong>${group.group_name}</strong>
                <span>${group.member_count} usuário${group.member_count > 1 ? "s" : ""}</span>
              </div>
              <div class="bar" aria-hidden="true"><span style="width: ${Math.min(group.member_count * 12, 100)}%"></span></div>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum grupo crítico encontrado.</div>`;

  document.querySelector("#critical-table").innerHTML = state.critical.users?.length
    ? state.critical.users
        .map(
          (identity) => `
            <tr class="clickable-row" data-critical-identity-id="${identity.id}">
              <td>
                <div class="user-cell">
                  <span class="avatar">${initials(identityName(identity))}</span>
                  <div>
                    <strong>${identityName(identity)}</strong><br />
                    <small>${identity.email || identity.username || ""}</small>
                  </div>
                </div>
              </td>
              <td>${identity.department || "-"}</td>
              <td><span class="badge ${statusClass(identity.status)}">${statusLabel(identity.status)}</span></td>
              <td>${String(identity.critical_groups || "")
                .split(",")
                .filter(Boolean)
                .map((group) => `<span class="inline-pill">${group.trim()}</span>`)
                .join("")}</td>
              <td><button class="text-button" type="button" data-open-critical="${identity.id}">Detalhes</button></td>
            </tr>
          `,
        )
        .join("")
    : `<tr><td colspan="5">Nenhuma permissão crítica encontrada.</td></tr>`;
}

function renderOperators() {
  if (!state.operators.length) {
    renderEmpty("#operator-list", "Nenhum operador importado dos grupos IAM do AD.");
    renderEmpty("#operator-profile", "Aguardando sincronização de operadores.");
    renderEmpty("#permission-grid", "");
    return;
  }

  if (!state.selectedOperatorId) state.selectedOperatorId = state.operators[0].identity_id;

  document.querySelector("#operator-list").innerHTML = state.operators
    .map(
      (operator) => `
        <button class="operator-card ${operator.identity_id === state.selectedOperatorId ? "is-selected" : ""}" type="button" data-operator-id="${operator.identity_id}">
          <span class="avatar">${initials(operator.display_name || operator.username)}</span>
          <span>
            <strong>${operator.display_name || operator.username}</strong>
            <small>${operator.title || "Operador IAM"}</small>
          </span>
          <span class="badge ${operator.status === "pending" ? "review" : "active"}">${statusLabel(operator.status)}</span>
        </button>
      `,
    )
    .join("");

  renderOperatorDetail();
}

function renderOperatorDetail() {
  const operator = selectedOperator();
  if (!operator) return;

  const operatorPermissions = parsePermissions(operator.permissions_json);
  const enabledCount = permissions.filter((permission) => operatorPermissions[permission.key]).length;
  const isAdManagedPermission = String(operator.permission_source || "") === "ad-admin-full";

  document.querySelector("#operator-profile").innerHTML = `
    <div class="identity-avatar">${initials(operator.display_name || operator.username)}</div>
    <div>
      <p class="eyebrow">${operator.title || "Operador IAM"}</p>
      <h3>${operator.display_name || operator.username}</h3>
      <span>${operator.email || ""}</span>
      <span>Departamento: ${operator.department || "-"}</span>
      <span>${permissionSourceLabel(operator.permission_source)}</span>
    </div>
    <div class="operator-stats">
      <span class="badge ${operator.status === "pending" ? "review" : "active"}">${statusLabel(operator.status)}</span>
      <strong>${enabledCount}/${permissions.length}</strong>
      <small>permissões ativas</small>
    </div>
  `;

  document.querySelector("#permission-grid").innerHTML = permissions
    .map(
      (permission) => `
        <label class="permission-item">
          <input type="checkbox" data-permission-key="${permission.key}" ${operatorPermissions[permission.key] ? "checked" : ""} ${isAdManagedPermission ? "disabled" : ""} />
          <span>
            <strong>${permission.title}</strong>
            <small>${permission.description}</small>
          </span>
        </label>
      `,
    )
    .join("");
}

function renderAudit() {
  const events = filteredAuditEvents();

  document.querySelector("#audit-feed").innerHTML = events.length
    ? events
        .map((event) => {
          return `
            <li>
              <span class="audit-time">${formatSyncTime(event.occurred_at)}</span>
              <div>
                <strong>${auditActionLabel(event.action)}</strong>
                <small>${auditEventDescription(event)}</small>
              </div>
              <span class="badge sync-status ${statusClass(event.status)}">${statusLabel(event.status)}</span>
            </li>
          `;
        })
        .join("")
    : `<li><span class="audit-time">-</span><strong>Nenhum evento encontrado</strong><span class="badge review">Pendente</span></li>`;
}

function filteredAuditEvents() {
  const filter = state.auditOperatorFilter.trim().toLowerCase();
  return state.auditEvents.filter((event) =>
    [event.operator_username, event.operator_display_name].filter(Boolean).join(" ").toLowerCase().includes(filter),
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function reportRows(events) {
  return events
    .map(
      (event) => `
        <tr>
          <td>${escapeHtml(formatSyncTime(event.occurred_at))}</td>
          <td>${escapeHtml(auditActionLabel(event.action))}</td>
          <td>${escapeHtml(event.operator_display_name || event.operator_username || "Sistema")}</td>
          <td>${escapeHtml(event.target_name || event.target_dn || event.target_type || "-")}</td>
          <td>${escapeHtml(auditEventDescription(event))}</td>
          <td>${escapeHtml(statusLabel(event.status))}</td>
        </tr>
      `,
    )
    .join("");
}

function openHtmlReport(html, filename) {
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const report = window.open(url, "_blank");
  if (!report) {
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast("O navegador bloqueou a abertura. O relatório foi baixado como HTML.");
    window.setTimeout(() => URL.revokeObjectURL(url), 30000);
    return;
  }
  window.setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function exportAuditReport() {
  const events = filteredAuditEvents();
  const successCount = events.filter((event) => event.status === "success").length;
  const failureCount = events.length - successCount;
  const operatorCount = new Set(events.map((event) => event.operator_username || event.operator_display_name).filter(Boolean)).size;
  const generatedAt = formatSyncTime(new Date().toISOString());
  const filter = state.auditOperatorFilter.trim();

  const html = `
    <!doctype html>
    <html lang="pt-BR">
      <head>
        <meta charset="utf-8" />
        <title>Relatório de auditoria IAM</title>
        <style>
          body { margin: 0; padding: 32px; color: #101827; font-family: Arial, sans-serif; background: #f4f7fb; }
          .report { max-width: 1180px; margin: 0 auto; padding: 28px; border: 1px solid #d9e2ef; border-radius: 10px; background: #fff; }
          header { display: flex; justify-content: space-between; gap: 24px; border-bottom: 2px solid #16202b; padding-bottom: 18px; }
          h1 { margin: 0 0 6px; font-size: 28px; }
          p { margin: 4px 0; color: #546179; }
          .actions { text-align: right; }
          button { min-height: 38px; padding: 0 16px; border: 0; border-radius: 8px; color: white; background: #16202b; font-weight: 700; cursor: pointer; }
          .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 22px 0; }
          .summary article { padding: 14px; border: 1px solid #d9e2ef; border-radius: 8px; background: #fbfdff; }
          .summary span { display: block; color: #546179; font-size: 13px; }
          .summary strong { display: block; margin-top: 8px; font-size: 24px; }
          table { width: 100%; border-collapse: collapse; font-size: 13px; }
          th, td { padding: 10px; border-bottom: 1px solid #d9e2ef; text-align: left; vertical-align: top; }
          th { color: #16202b; background: #eef3f8; }
          @media print { body { padding: 0; background: #fff; } .report { border: 0; } .actions { display: none; } }
        </style>
      </head>
      <body>
        <main class="report">
          <header>
            <div>
              <p>Casa & Terra IAM</p>
              <h1>Relatório de auditoria</h1>
              <p>Gerado em ${escapeHtml(generatedAt)}${filter ? ` - Filtro de operador: ${escapeHtml(filter)}` : ""}</p>
            </div>
            <div class="actions"><button onclick="window.print()">Imprimir / salvar PDF</button></div>
          </header>
          <section class="summary">
            <article><span>Total de eventos</span><strong>${events.length}</strong></article>
            <article><span>Eventos com sucesso</span><strong>${successCount}</strong></article>
            <article><span>Eventos com falha</span><strong>${failureCount}</strong></article>
            <article><span>Operadores envolvidos</span><strong>${operatorCount}</strong></article>
          </section>
          <table>
            <thead>
              <tr>
                <th>Data</th>
                <th>Ação</th>
                <th>Operador</th>
                <th>Objeto</th>
                <th>Detalhes</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>${reportRows(events) || `<tr><td colspan="6">Nenhum evento encontrado.</td></tr>`}</tbody>
          </table>
        </main>
      </body>
    </html>
  `;

  openHtmlReport(html, "relatorio-auditoria-iam.html");
}

function criticalReportRows() {
  return (state.critical.users || [])
    .map(
      (identity) => `
        <tr>
          <td>${escapeHtml(identity.display_name || identity.username || "-")}</td>
          <td>${escapeHtml(identity.username || "-")}</td>
          <td>${escapeHtml(identity.department || "-")}</td>
          <td>${escapeHtml(statusLabel(identity.status))}</td>
          <td>${escapeHtml(String(identity.critical_groups || ""))}</td>
        </tr>
      `,
    )
    .join("");
}

function criticalGroupReportRows() {
  return (state.critical.groups || [])
    .map(
      (group) => `
        <tr>
          <td>${escapeHtml(group.group_name || "-")}</td>
          <td>${escapeHtml(group.member_count || 0)}</td>
        </tr>
      `,
    )
    .join("");
}

function exportCriticalReport() {
  const generatedAt = formatSyncTime(new Date().toISOString());
  const disabledCount = (state.critical.users || []).filter(
    (identity) => identity.status === "disabled" || identity.status === "blocked",
  ).length;

  const html = `
    <!doctype html>
    <html lang="pt-BR">
      <head>
        <meta charset="utf-8" />
        <title>Relatório de permissões críticas</title>
        <style>
          body { margin: 0; padding: 32px; color: #101827; font-family: Arial, sans-serif; background: #f4f7fb; }
          .report { max-width: 1180px; margin: 0 auto; padding: 28px; border: 1px solid #d9e2ef; border-radius: 10px; background: #fff; }
          header { display: flex; justify-content: space-between; gap: 24px; border-bottom: 2px solid #16202b; padding-bottom: 18px; }
          h1 { margin: 0 0 6px; font-size: 28px; }
          h2 { margin: 26px 0 12px; font-size: 18px; }
          p { margin: 4px 0; color: #546179; }
          .actions { text-align: right; }
          button { min-height: 38px; padding: 0 16px; border: 0; border-radius: 8px; color: white; background: #16202b; font-weight: 700; cursor: pointer; }
          .summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 22px 0; }
          .summary article { padding: 14px; border: 1px solid #d9e2ef; border-radius: 8px; background: #fbfdff; }
          .summary span { display: block; color: #546179; font-size: 13px; }
          .summary strong { display: block; margin-top: 8px; font-size: 24px; }
          table { width: 100%; border-collapse: collapse; font-size: 13px; }
          th, td { padding: 10px; border-bottom: 1px solid #d9e2ef; text-align: left; vertical-align: top; }
          th { color: #16202b; background: #eef3f8; }
          @media print { body { padding: 0; background: #fff; } .report { border: 0; } .actions { display: none; } }
        </style>
      </head>
      <body>
        <main class="report">
          <header>
            <div>
              <p>Casa & Terra IAM</p>
              <h1>Relatório de permissões críticas</h1>
              <p>Gerado em ${escapeHtml(generatedAt)}</p>
            </div>
            <div class="actions"><button onclick="window.print()">Imprimir / salvar PDF</button></div>
          </header>
          <section class="summary">
            <article><span>Usuários com permissão crítica</span><strong>${state.critical.users_count || 0}</strong></article>
            <article><span>Grupos críticos mapeados</span><strong>${state.critical.groups_count || 0}</strong></article>
            <article><span>Contas desabilitadas/bloqueadas</span><strong>${disabledCount}</strong></article>
          </section>
          <h2>Distribuição por grupo crítico</h2>
          <table>
            <thead><tr><th>Grupo</th><th>Membros</th></tr></thead>
            <tbody>${criticalGroupReportRows() || `<tr><td colspan="2">Nenhum grupo crítico encontrado.</td></tr>`}</tbody>
          </table>
          <h2>Usuários com permissões críticas</h2>
          <table>
            <thead>
              <tr>
                <th>Usuário</th>
                <th>Login</th>
                <th>Departamento</th>
                <th>Status</th>
                <th>Grupos críticos</th>
              </tr>
            </thead>
            <tbody>${criticalReportRows() || `<tr><td colspan="5">Nenhum usuário crítico encontrado.</td></tr>`}</tbody>
          </table>
        </main>
      </body>
    </html>
  `;

  openHtmlReport(html, "relatorio-permissoes-criticas.html");
}

function applyPermissionState() {
  disableByPermission("[data-action='sync'], [data-action='sync-google-workspace']", "syncAd");
  disableByPermission("[data-action='invite-user']", "manageOperators");
  disableByPermission("[data-action='map-app']", "manageGroups");
  disableByPermission("[data-identity-action='password']", "resetPassword");
  disableByPermission("[data-identity-action='move-ou']", "manageOperators");
  disableByPermission("[data-identity-action='add-group'], [data-identity-action='revoke']", "manageGroups");
  disableByPermission("[data-group-member-action], [data-group-member-add], [data-group-member-remove]", "manageGroups");
  disableByPermission("[data-identity-action='block'], [data-identity-action='unlock'], [data-identity-action='disable'], [data-identity-action='sessions']", "lockUnlock");
  disableByPermission("[data-view='operators'], [data-operator-action], #permission-grid input", "manageOperators");
  disableByPermission("[data-action='export-audit']", "viewAudit");
}

function renderAll() {
  renderMetrics();
  renderCurrentUser();
  renderSidebarSyncStatus();
  renderReviews();
  renderDirectoryIndicators();
  renderWorkspaceGovernance();
  renderNotifications();
  renderIdentities();
  renderAccess();
  renderGroupDetail();
  renderGlobalSearchResults();
  renderCriticalPermissions();
  renderOperators();
  renderAudit();
  applyPermissionState();
}

async function loadData() {
  state.loading = true;
  try {
    const [identities, groups, operators, critical, governanceWorkspace, syncRuns, auditEvents, currentUser] = await Promise.all([
      apiGet("/api/identities"),
      apiGet("/api/groups"),
      apiGet("/api/operators"),
      apiGet("/api/critical-permissions"),
      apiGet("/api/governance/workspace-disabled-members"),
      apiGet("/api/sync-runs"),
      apiGet("/api/audit-events"),
      apiGetOptional("/api/auth/me"),
    ]);

    state.identities = identities;
    state.groups = groups;
    state.operators = operators;
    state.critical = critical;
    state.governance.workspace_disabled_members = governanceWorkspace;
    state.syncRuns = syncRuns;
    state.auditEvents = auditEvents;
    state.currentUser = currentUser;
    if (currentUser?.csrf_token) {
      sessionStorage.setItem("IAM_CSRF_TOKEN", currentUser.csrf_token);
    }
    if (currentUser?.session_expires_at) {
      sessionStorage.setItem("IAM_SESSION_EXPIRES_AT", String(currentUser.session_expires_at));
      scheduleSessionExpiry(currentUser.session_expires_at);
    }
    state.selectedIdentityId = identities[0]?.id || null;
    state.selectedOperatorId = operators[0]?.identity_id || null;
    state.apiOnline = true;
    renderAll();
  } catch (error) {
    state.apiOnline = false;
    renderAll();
    showToast(`API indisponível: ${error.message}`);
  } finally {
    state.loading = false;
  }
}

function switchView(viewName) {
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.classList.toggle("is-hidden", panel.dataset.panel !== viewName);
  });
  document.querySelectorAll(".nav-item").forEach((item) => {
    const activeView = viewName === "identity-detail" ? "identities" : viewName === "group-detail" ? "access" : viewName;
    item.classList.toggle("is-active", item.dataset.view === activeView);
  });
}

async function openIdentityDetail(identityId) {
  await renderIdentityDetail(identityId);
  switchView("identity-detail");
}

function readonlyNotice(action) {
  showToast(`${action} será liberado em uma próxima etapa. O backend atual está em modo somente leitura.`);
}

function modalIdentityMarkup(identity) {
  return `
    <span class="modal-avatar">${initials(identityName(identity))}</span>
    <div>
      <strong>${identityName(identity)}</strong>
      <span>${identity.username || identity.upn || "-"}${identity.department ? ` - ${identity.department}` : ""}</span>
    </div>
  `;
}

function openModal(modalId) {
  const modal = document.querySelector(modalId);
  modal.classList.add("is-visible");
  modal.setAttribute("aria-hidden", "false");
}

function closeModals() {
  document.querySelectorAll(".modal-backdrop").forEach((modal) => {
    modal.classList.remove("is-visible");
    modal.setAttribute("aria-hidden", "true");
  });
}

function openPasswordModal() {
  const identity = selectedIdentity();
  if (!identity) return;
  document.querySelector("#password-new").value = "";
  document.querySelector("#password-confirm").value = "";
  document.querySelector("#password-must-change").checked = true;
  document.querySelector("#password-modal-identity").innerHTML = modalIdentityMarkup(identity);
  openModal("#password-modal");
}

function groupAlreadyAssigned(groupName) {
  return state.selectedIdentityGroups.some(
    (group) => String(group.group_name || "").toLowerCase() === String(groupName || "").toLowerCase(),
  );
}

function renderGroupEditor(searchTerm = "") {
  const identity = selectedIdentity();
  if (!identity) return;

  const normalizedSearch = searchTerm.trim().toLowerCase();
  const currentGroups = state.selectedIdentityGroups;
  const availableGroups = state.groups
    .filter((group) => !groupAlreadyAssigned(group.name))
    .filter((group) =>
      [group.name, group.description, group.distinguished_name]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalizedSearch),
    )
    .slice(0, 12);

  document.querySelector("#groups-modal-identity").innerHTML = modalIdentityMarkup(identity);
  document.querySelector("#current-group-count").textContent = `${currentGroups.length} grupo(s)`;
  document.querySelector("#current-group-list").innerHTML = currentGroups.length
    ? currentGroups
        .map(
          (group) => `
            <article class="editable-group-card">
              <div>
                <strong>${group.group_name}</strong>
                <span>${group.is_critical ? "Crítico" : "Padrão"}</span>
              </div>
              <button class="text-button danger-text" type="button" data-group-remove="${encodeURIComponent(group.group_dn)}" data-group-name="${encodeURIComponent(group.group_name)}">Remover</button>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum grupo retornado pela API.</div>`;

  document.querySelector("#available-group-list").innerHTML = availableGroups.length
    ? availableGroups
        .map(
          (group) => `
            <article class="editable-group-card available">
              <div>
                <strong>${group.name}</strong>
                <span>${group.description || "Sem descrição"}</span>
              </div>
              <button class="text-button" type="button" data-group-add="${encodeURIComponent(group.distinguished_name)}" data-group-name="${encodeURIComponent(group.name)}" data-group-critical="${group.is_critical ? "1" : "0"}">Adicionar</button>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum grupo disponível para a busca.</div>`;
}

function openGroupsModal(groupName = "") {
  const searchInput = document.querySelector("#group-picker-search");
  searchInput.value = groupName;
  renderGroupEditor(groupName);
  openModal("#groups-modal");
  window.setTimeout(() => searchInput.focus(), 0);
}

function ouFromDistinguishedName(dn = "") {
  const parts = String(dn)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  const ouParts = parts.filter((part) => part.toUpperCase().startsWith("OU="));
  const domainParts = parts.filter((part) => part.toUpperCase().startsWith("DC="));
  if (!ouParts.length) return "";
  return [...ouParts, ...domainParts].join(",");
}

function ouDisplayName(ouDn) {
  return ouDn
    .split(",")
    .map((part) => part.replace(/^OU=/i, ""))
    .join(" / ");
}

function ouNameParts(ouDn) {
  return String(ouDn)
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.toUpperCase().startsWith("OU="))
    .map((part) => part.replace(/^OU=/i, ""));
}

function ouFolderName(ouDn) {
  return ouNameParts(ouDn)[0] || ouDisplayName(ouDn);
}

function ouParentName(ouDn) {
  return ouNameParts(ouDn)[1] || "";
}

function isAllowedDestinationOu(ouDn) {
  const blockedNames = new Set(["service account", "staging-gpo"]);
  return !blockedNames.has(ouFolderName(ouDn).toLowerCase());
}

function ouListTitle(ouDn, duplicateNames) {
  const folderName = ouFolderName(ouDn);
  const parentName = ouParentName(ouDn);
  return duplicateNames.has(folderName.toLowerCase()) && parentName ? `${folderName} (${parentName})` : folderName;
}

function uniqueOus(records) {
  const ous = records
    .map((record) => ouFromDistinguishedName(record.distinguished_name))
    .filter(Boolean)
    .filter(isAllowedDestinationOu);
  return [...new Set(ous)].sort((a, b) =>
    `${ouFolderName(a)} ${a}`.localeCompare(`${ouFolderName(b)} ${b}`, "pt-BR"),
  );
}

function renderOuList({ records, listSelector, countSelector, searchTerm = "", emptyText }) {
  const normalizedSearch = searchTerm.trim().toLowerCase();
  const ous = uniqueOus(records).filter((ou) =>
    `${ouFolderName(ou)} ${ouDisplayName(ou)} ${ou}`.toLowerCase().includes(normalizedSearch),
  );
  const folderCounts = ous.reduce((acc, ou) => {
    const key = ouFolderName(ou).toLowerCase();
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const duplicateNames = new Set(Object.entries(folderCounts).filter(([, count]) => count > 1).map(([name]) => name));
  document.querySelector(countSelector).textContent = `${ous.length} OU(s)`;
  document.querySelector(listSelector).innerHTML = ous.length
    ? ous
        .slice(0, 40)
        .map(
          (ou, index) => `
            <label class="ou-card">
              <input type="radio" name="${listSelector.replace("#", "")}" value="${ou}" ${index === 0 ? "checked" : ""} />
              <span>
                <strong>${ouListTitle(ou, duplicateNames)}</strong>
                <small>${ou}</small>
              </span>
            </label>
          `,
        )
        .join("")
    : `<div class="empty-state">${emptyText}</div>`;
}

function renderUserOuList(searchTerm = "") {
  renderOuList({
    records: state.identities,
    listSelector: "#user-ou-list",
    countSelector: "#user-ou-count",
    searchTerm,
    emptyText: "Nenhuma OU de usuários encontrada no cache sincronizado.",
  });
}

function renderMoveOuList(searchTerm = "") {
  const identity = selectedIdentity();
  const currentOu = ouFromDistinguishedName(identity?.distinguished_name || "");
  const records = state.identities.filter(
    (record) => ouFromDistinguishedName(record.distinguished_name).toLowerCase() !== currentOu.toLowerCase(),
  );
  renderOuList({
    records,
    listSelector: "#move-ou-list",
    countSelector: "#move-ou-count",
    searchTerm,
    emptyText: "Nenhuma OU alternativa encontrada no cache sincronizado.",
  });
}

function renderGroupOuList(searchTerm = "") {
  renderOuList({
    records: state.groups,
    listSelector: "#group-ou-list",
    countSelector: "#group-ou-count",
    searchTerm,
    emptyText: "Nenhuma OU de grupos encontrada no cache sincronizado.",
  });
}

function renderCopyGroupsPreview() {
  const preview = document.querySelector("#copy-groups-preview");
  if (!preview) return;

  if (!state.copyGroupsSourceIdentityId) {
    preview.innerHTML = "Nenhum usuario base selecionado.";
    return;
  }

  if (!state.copyGroupsSourceGroups.length) {
    preview.innerHTML = "O usuario base selecionado nao possui grupos retornados pelo ultimo sync.";
    return;
  }

  const visibleGroups = state.copyGroupsSourceGroups.slice(0, 8);
  const remaining = state.copyGroupsSourceGroups.length - visibleGroups.length;
  preview.innerHTML = `
    <strong>${state.copyGroupsSourceGroups.length} grupo(s) serao copiados</strong>
    <div class="copy-group-tags">
      ${visibleGroups.map((group) => `<span>${escapeHtml(group.group_name)}</span>`).join("")}
      ${remaining > 0 ? `<span>+${remaining}</span>` : ""}
    </div>
  `;
}

function renderCopyUserList(searchTerm = "") {
  const list = document.querySelector("#copy-groups-user-list");
  if (!list) return;

  const term = normalizeText(searchTerm);
  const matches = state.identities
    .filter((identity) => {
      const name = `${identity.display_name || ""} ${identity.username || ""} ${identity.email || ""}`;
      return !term || normalizeText(name).includes(term);
    })
    .slice(0, 6);

  list.innerHTML = matches.length
    ? matches
        .map(
          (identity) => `
            <button class="copy-user-card ${identity.id === state.copyGroupsSourceIdentityId ? "is-selected" : ""}" type="button" data-copy-user-id="${escapeHtml(identity.id)}">
              <span class="avatar">${initials(identity.display_name || identity.username)}</span>
              <span>
                <strong>${escapeHtml(identity.display_name || identity.username)}</strong>
                <small>${escapeHtml(identity.username || "-")} - ${Number(identity.group_count || 0)} grupo(s)</small>
              </span>
            </button>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum usuario encontrado.</div>`;

  renderCopyGroupsPreview();
}

function openCreateUserModal() {
  const searchInput = document.querySelector("#user-ou-search");
  const copySearchInput = document.querySelector("#copy-groups-user-search");
  searchInput.value = "";
  copySearchInput.value = "";
  state.copyGroupsSourceIdentityId = null;
  state.copyGroupsSourceGroups = [];
  [
    "#create-user-first-name",
    "#create-user-last-name",
    "#create-user-username",
    "#create-user-email",
    "#create-user-title",
    "#create-user-department",
    "#create-user-password",
    "#create-user-password-confirm",
  ].forEach((selector) => {
    document.querySelector(selector).value = "";
  });
  document.querySelector("#create-user-must-change").checked = true;
  renderUserOuList();
  renderCopyUserList();
  openModal("#create-user-modal");
  window.setTimeout(() => document.querySelector("#create-user-modal input").focus(), 0);
}

function openMoveOuModal() {
  const identity = selectedIdentity();
  if (!identity) return;
  const searchInput = document.querySelector("#move-ou-search");
  searchInput.value = "";
  document.querySelector("#move-ou-modal-identity").innerHTML = modalIdentityMarkup(identity);
  renderMoveOuList();
  openModal("#move-ou-modal");
  window.setTimeout(() => searchInput.focus(), 0);
}

function openCreateGroupModal() {
  const searchInput = document.querySelector("#group-ou-search");
  searchInput.value = "";
  document.querySelector("#create-group-name").value = "";
  document.querySelector("#create-group-description").value = "";
  document.querySelector("#create-group-scope").value = "global";
  document.querySelector("#create-group-type").value = "security";
  document.querySelector("#create-group-critical").checked = false;
  renderGroupOuList();
  openModal("#create-group-modal");
  window.setTimeout(() => document.querySelector("#create-group-name").focus(), 0);
}

function selectedGroupOu() {
  return document.querySelector("#group-ou-list input[type='radio']:checked")?.value || "";
}

function selectedUserOu() {
  return document.querySelector("#user-ou-list input[type='radio']:checked")?.value || "";
}

function selectedMoveOu() {
  return document.querySelector("#move-ou-list input[type='radio']:checked")?.value || "";
}

async function refreshAudit() {
  state.auditEvents = await apiGet("/api/audit-events");
  renderAudit();
  renderReviews();
  renderDirectoryIndicators();
  renderNotifications();
}

async function refreshSelectedIdentity() {
  const identityId = state.selectedIdentityId;
  const identities = await apiGet("/api/identities");
  state.identities = identities;
  if (identityId) {
    await renderIdentityDetail(identityId);
  }
  renderIdentities();
  renderMetrics();
}

async function submitCreateGroup() {
  const submitButton = document.querySelector("#create-group-submit");
  const payload = {
    name: document.querySelector("#create-group-name").value.trim(),
    description: document.querySelector("#create-group-description").value.trim(),
    target_ou: selectedGroupOu(),
    scope: document.querySelector("#create-group-scope").value,
    group_type: document.querySelector("#create-group-type").value,
    is_critical: document.querySelector("#create-group-critical").checked,
  };

  if (!payload.name || !payload.target_ou) {
    showToast("Informe o nome do grupo e selecione uma OU de destino.");
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "Criando...";
  try {
    const result = await apiPost("/api/groups", payload);
    state.groups = [result.group, ...state.groups.filter((group) => group.id !== result.group.id)];
    state.auditEvents = await apiGet("/api/audit-events");
    state.groupPage = 1;
    renderAccess();
    renderAudit();
    closeModals();
    showToast(`Grupo ${result.group.name} criado no AD.`);
  } catch (error) {
    showToast(`Falha ao criar grupo: ${error.message}`);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Criar grupo";
  }
}

async function submitCreateUser() {
  const submitButton = document.querySelector("#create-user-submit");
  const password = document.querySelector("#create-user-password").value;
  const confirmPassword = document.querySelector("#create-user-password-confirm").value;
  const payload = {
    first_name: document.querySelector("#create-user-first-name").value.trim(),
    last_name: document.querySelector("#create-user-last-name").value.trim(),
    username: document.querySelector("#create-user-username").value.trim(),
    email: document.querySelector("#create-user-email").value.trim(),
    title: document.querySelector("#create-user-title").value.trim(),
    department: document.querySelector("#create-user-department").value.trim(),
    target_ou: selectedUserOu(),
    password,
    must_change_password: document.querySelector("#create-user-must-change").checked,
    copy_groups_from_identity_id: state.copyGroupsSourceIdentityId || null,
  };

  if (!payload.first_name || !payload.last_name || !payload.username || !payload.password || !payload.target_ou) {
    showToast("Informe nome, sobrenome, usuário, senha e OU de destino.");
    return;
  }
  if (password !== confirmPassword) {
    showToast("A confirmação da senha não confere.");
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "Criando...";
  try {
    const result = await apiPost("/api/identities", payload);
    state.identities = [result.identity, ...state.identities.filter((identity) => identity.id !== result.identity.id)];
    state.identityPage = 1;
    renderIdentities();
    renderMetrics();
    await refreshAudit();
    closeModals();
    const copiedCount = result.copied_groups?.length || 0;
    const failedCount = result.failed_groups?.length || 0;
    const groupSummary = state.copyGroupsSourceIdentityId
      ? ` ${copiedCount} grupo(s) copiados${failedCount ? `, ${failedCount} falharam` : ""}.`
      : "";
    showToast(`Usuário ${result.identity.username} criado no AD.${groupSummary}`);
  } catch (error) {
    showToast(`Falha ao criar usuário: ${error.message}`);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Criar usuário";
  }
}

async function submitPasswordReset() {
  const identity = selectedIdentity();
  const submitButton = document.querySelector("#password-submit");
  const newPassword = document.querySelector("#password-new").value;
  const confirmPassword = document.querySelector("#password-confirm").value;
  if (!identity || !newPassword) {
    showToast("Informe a nova senha.");
    return;
  }
  if (newPassword !== confirmPassword) {
    showToast("A confirmação da senha não confere.");
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "Alterando...";
  try {
    await apiPost(`/api/identities/${identity.id}/password`, {
      new_password: newPassword,
      must_change_password: document.querySelector("#password-must-change").checked,
    });
    await refreshSelectedIdentity();
    await refreshAudit();
    closeModals();
    showToast("Senha alterada no AD.");
  } catch (error) {
    showToast(`Falha ao alterar senha: ${error.message}`);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Alterar senha";
  }
}

async function submitMoveOu() {
  const identity = selectedIdentity();
  const submitButton = document.querySelector("#move-ou-submit");
  const targetOu = selectedMoveOu();
  if (!identity || !targetOu) {
    showToast("Selecione a OU de destino.");
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "Movendo...";
  try {
    const result = await apiPost(`/api/identities/${identity.id}/move-ou`, { target_ou: targetOu });
    state.identities = state.identities.map((item) =>
      item.id === identity.id || item.username === result.identity.username ? result.identity : item,
    );
    state.selectedIdentityId = result.identity.id;
    await renderIdentityDetail(result.identity.id);
    renderIdentities();
    await refreshAudit();
    closeModals();
    showToast("Usuário movido para a OU selecionada.");
  } catch (error) {
    showToast(`Falha ao mover usuário: ${error.message}`);
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "Mover usuário";
  }
}

async function updateIdentityStatus(action) {
  const identity = selectedIdentity();
  if (!identity) return;
  try {
    const result = await apiPost(`/api/identities/${identity.id}/status`, { action });
    state.identities = state.identities.map((item) => (item.id === result.identity.id ? result.identity : item));
    await renderIdentityDetail(result.identity.id);
    renderIdentities();
    renderMetrics();
    await refreshAudit();
    showToast("Status da identidade atualizado no AD.");
  } catch (error) {
    if (action === "enable" && error.message.toLowerCase().includes("senha válida")) {
      openPasswordModal();
    }
    showToast(`Falha ao atualizar status: ${error.message}`);
  }
}

async function changeIdentityGroup(action, groupDn, groupName, isCritical = false) {
  const identity = selectedIdentity();
  if (!identity) return;
  try {
    await apiPost(`/api/identities/${identity.id}/groups/${action}`, {
      group_dn: groupDn,
      group_name: groupName,
      is_critical: isCritical,
    });
    await renderIdentityDetail(identity.id);
    renderIdentities();
    renderGroupEditor(document.querySelector("#group-picker-search")?.value || "");
    await refreshAudit();
    showToast(action === "add" ? "Grupo adicionado no AD." : "Grupo removido no AD.");
  } catch (error) {
    showToast(`Falha ao alterar grupo: ${error.message}`);
  }
}

async function changeGroupDetailMembership(action, identityId) {
  const group = selectedGroup();
  const identity = state.identities.find((item) => item.id === identityId);
  if (!group || !identity) return;

  try {
    await apiPost(`/api/identities/${identity.id}/groups/${action}`, {
      group_dn: group.distinguished_name,
      group_name: group.name,
      is_critical: Boolean(group.is_critical),
    });
    await refreshSelectedGroupMembers();
    await refreshAudit();
    showToast(action === "add" ? "Usuário adicionado ao grupo no AD." : "Usuário removido do grupo no AD.");
  } catch (error) {
    showToast(`Falha ao alterar membros do grupo: ${error.message}`);
  }
}

async function removeSelectedOperator() {
  const operator = selectedOperator();
  if (!operator) return;

  const operatorName = operator.display_name || operator.username || "operador selecionado";
  const confirmed = window.confirm(
    `Remover ${operatorName} da lista de operadores do IAM?\n\nPara remoção definitiva, retire o usuário dos grupos IAM no AD e execute uma sincronização.`,
  );
  if (!confirmed) return;

  try {
    await apiPost(`/api/operators/${operator.identity_id}/remove`);
    state.operators = state.operators.filter((item) => item.identity_id !== operator.identity_id);
    state.selectedOperatorId = state.operators[0]?.identity_id || null;
    await refreshAudit();
    renderOperators();
    renderMetrics();
    showToast("Operador removido do IAM local.");
  } catch (error) {
    showToast(`Falha ao remover operador: ${error.message}`);
  }
}

function bindEvents() {
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.view));
  });

  document.querySelectorAll("[data-view-link]").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.viewLink));
  });

  document.querySelectorAll(".chip").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeFilter = button.dataset.filter;
      state.identityPage = 1;
      document.querySelectorAll(".chip").forEach((chip) => chip.classList.remove("is-active"));
      button.classList.add("is-active");
      renderIdentities();
    });
  });

  document.querySelectorAll("[data-dashboard-range]").forEach((button) => {
    button.addEventListener("click", () => {
      state.dashboardRangeDays = Number(button.dataset.dashboardRange || 1);
      document.querySelectorAll("[data-dashboard-range]").forEach((rangeButton) => {
        rangeButton.classList.toggle("is-selected", rangeButton === button);
      });
      renderReviews();
      renderDirectoryIndicators();
      renderNotifications();
    });
  });

  document.querySelector("#global-search").addEventListener("input", () => {
    state.identityPage = 1;
    state.groupPage = 1;
    renderIdentities();
    renderAccess();
    renderGlobalSearchResults();
  });

  document.querySelector("#global-search").addEventListener("focus", renderGlobalSearchResults);

  document.querySelector("#global-search-results").addEventListener("click", (event) => {
    const identityButton = event.target.closest("[data-search-identity]");
    const groupButton = event.target.closest("[data-search-group]");

    if (identityButton) {
      document.querySelector("#global-search-results").classList.remove("is-visible");
      openIdentityDetail(identityButton.dataset.searchIdentity);
      return;
    }

    if (groupButton) {
      document.querySelector("#global-search-results").classList.remove("is-visible");
      openGroupDetail(decodeURIComponent(groupButton.dataset.searchGroup));
    }
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".topbar-actions")) {
      document.querySelector("#global-search-results").classList.remove("is-visible");
    }
  });

  document.querySelector("#identity-pagination").addEventListener("click", (event) => {
    const button = event.target.closest("[data-page-action]");
    if (!button) return;

    if (button.dataset.pageAction === "prev") {
      state.identityPage -= 1;
    }
    if (button.dataset.pageAction === "next") {
      state.identityPage += 1;
    }
    renderIdentities();
  });

  document.querySelector("#group-pagination").addEventListener("click", (event) => {
    const button = event.target.closest("[data-group-page-action]");
    if (!button) return;

    if (button.dataset.groupPageAction === "prev") {
      state.groupPage -= 1;
    }
    if (button.dataset.groupPageAction === "next") {
      state.groupPage += 1;
    }
    renderAccess();
  });

  document.querySelector("#access-grid").addEventListener("click", (event) => {
    const card = event.target.closest("[data-group-open]");
    if (!card) return;
    openGroupDetail(decodeURIComponent(card.dataset.groupOpen));
  });

  document.querySelector("#group-member-search").addEventListener("input", (event) => {
    state.groupMemberSearch = event.target.value;
    renderGroupCandidates();
    applyPermissionState();
  });

  document.querySelector("#group-member-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-group-member-remove]");
    if (!button) return;
    changeGroupDetailMembership("remove", button.dataset.groupMemberRemove);
  });

  document.querySelector("#group-candidate-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-group-member-add]");
    if (!button) return;
    changeGroupDetailMembership("add", button.dataset.groupMemberAdd);
  });

  document.querySelector("[data-group-member-action='add']").addEventListener("click", () => {
    document.querySelector("#group-member-search").focus();
  });

  document.querySelector("#identity-table").addEventListener("click", (event) => {
    const openButton = event.target.closest("[data-open-identity]");
    const row = event.target.closest("[data-identity-id]");
    const identityId = openButton?.dataset.openIdentity || row?.dataset.identityId;

    if (identityId) openIdentityDetail(identityId);
  });

  document.querySelector("#critical-table").addEventListener("click", (event) => {
    const openButton = event.target.closest("[data-open-critical]");
    const row = event.target.closest("[data-critical-identity-id]");
    const identityId = openButton?.dataset.openCritical || row?.dataset.criticalIdentityId;

    if (identityId) openIdentityDetail(identityId);
  });

  document.querySelector("#risk-bars").addEventListener("click", (event) => {
    const riskUser = event.target.closest("[data-dashboard-identity]");
    if (riskUser?.dataset.dashboardIdentity) openIdentityDetail(riskUser.dataset.dashboardIdentity);
  });

  document.querySelector("#workspace-disabled-list").addEventListener("click", (event) => {
    const governanceUser = event.target.closest("[data-governance-identity]");
    if (governanceUser?.dataset.governanceIdentity) openIdentityDetail(governanceUser.dataset.governanceIdentity);
  });

  document.querySelector("#workspace-governance-list").addEventListener("click", (event) => {
    const governanceUser = event.target.closest("[data-governance-identity]");
    if (governanceUser?.dataset.governanceIdentity) {
      closeModals();
      openIdentityDetail(governanceUser.dataset.governanceIdentity);
    }
  });

  document.querySelector("#notification-button").addEventListener("click", () => {
    document.querySelector("#notification-panel").classList.toggle("is-visible");
  });

  document.querySelector("#notification-panel").addEventListener("click", (event) => {
    const dismissButton = event.target.closest("[data-notification-dismiss]");
    if (dismissButton) {
      dismissNotification(decodeURIComponent(dismissButton.dataset.notificationDismiss));
      return;
    }
    if (event.target.closest("[data-notification-clear]")) {
      dismissVisibleNotifications();
    }
  });

  document.addEventListener("click", (event) => {
    const panel = document.querySelector("#notification-panel");
    const button = document.querySelector("#notification-button");
    if (!panel.contains(event.target) && !button.contains(event.target)) {
      panel.classList.remove("is-visible");
    }
  });

  document.querySelector("#operator-list").addEventListener("click", (event) => {
    const operatorButton = event.target.closest("[data-operator-id]");
    if (!operatorButton) return;
    state.selectedOperatorId = operatorButton.dataset.operatorId;
    renderOperators();
  });

  document.querySelector("#permission-grid").addEventListener("change", async (event) => {
    const checkbox = event.target.closest("[data-permission-key]");
    if (!checkbox) return;

    if (!hasPermission("manageOperators")) {
      checkbox.checked = !checkbox.checked;
      showToast("Você não tem permissão para gerenciar operadores.");
      return;
    }

    const operator = selectedOperator();
    if (!operator) return;

    const updatedPermissions = parsePermissions(operator.permissions_json);
    updatedPermissions[checkbox.dataset.permissionKey] = checkbox.checked;
    checkbox.disabled = true;

    try {
      const updatedOperator = await apiPost(`/api/operators/${operator.identity_id}/permissions`, {
        permissions: updatedPermissions,
        status: operator.status === "pending" ? "active" : operator.status,
      });
      state.operators = state.operators.map((item) =>
        item.identity_id === updatedOperator.identity_id ? updatedOperator : item,
      );
      if (state.currentUser?.identity_id === updatedOperator.identity_id) {
        state.currentUser.permissions = parsePermissions(updatedOperator.permissions_json);
        state.currentUser.status = updatedOperator.status;
      }
      renderOperators();
      applyPermissionState();
      state.auditEvents = await apiGet("/api/audit-events");
      renderAudit();
      showToast("Permissões do operador atualizadas.");
    } catch (error) {
      checkbox.checked = !checkbox.checked;
      showToast(`Falha ao salvar permissões: ${error.message}`);
    } finally {
      checkbox.disabled = false;
    }
  });

  document.querySelector("#identity-groups").addEventListener("click", (event) => {
    const groupButton = event.target.closest("[data-edit-group]");
    if (groupButton) {
      openGroupsModal(decodeURIComponent(groupButton.dataset.editGroup || ""));
    }
  });

  document.querySelectorAll("[data-identity-action]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.identityAction === "password") {
        openPasswordModal();
        return;
      }

      if (button.dataset.identityAction === "move-ou") {
        openMoveOuModal();
        return;
      }

      if (button.dataset.identityAction === "add-group" || button.dataset.identityAction === "revoke") {
        openGroupsModal();
        return;
      }

      if (button.dataset.identityAction === "unlock") {
        updateIdentityStatus("unlock");
        return;
      }

      if (button.dataset.identityAction === "block") {
        updateIdentityStatus("block");
        return;
      }

      if (button.dataset.identityAction === "disable") {
        updateIdentityStatus(button.textContent.trim() === "Habilitar" ? "enable" : "disable");
        return;
      }

      readonlyNotice(button.textContent.trim());
    });
  });

  document.querySelectorAll("[data-modal-close]").forEach((button) => {
    button.addEventListener("click", closeModals);
  });

  document.querySelectorAll(".modal-backdrop").forEach((modal) => {
    modal.addEventListener("click", (event) => {
      if (event.target === modal) closeModals();
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeModals();
  });

  document.querySelector("#group-picker-search").addEventListener("input", (event) => {
    renderGroupEditor(event.target.value);
  });

  document.querySelector("#user-ou-search").addEventListener("input", (event) => {
    renderUserOuList(event.target.value);
  });

  document.querySelector("#copy-groups-user-search").addEventListener("input", (event) => {
    renderCopyUserList(event.target.value);
  });

  document.querySelector("#copy-groups-user-list").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy-user-id]");
    if (!button) return;

    state.copyGroupsSourceIdentityId = button.dataset.copyUserId;
    state.copyGroupsSourceGroups = [];
    renderCopyUserList(document.querySelector("#copy-groups-user-search").value);
    document.querySelector("#copy-groups-preview").textContent = "Carregando grupos do usuario base...";

    try {
      state.copyGroupsSourceGroups = await apiGet(`/api/identities/${encodeURIComponent(state.copyGroupsSourceIdentityId)}/groups`);
    } catch (error) {
      state.copyGroupsSourceGroups = [];
      showToast(`Falha ao carregar grupos do usuario base: ${error.message}`);
    }
    renderCopyUserList(document.querySelector("#copy-groups-user-search").value);
  });

  document.querySelector("#move-ou-search").addEventListener("input", (event) => {
    renderMoveOuList(event.target.value);
  });

  document.querySelector("#group-ou-search").addEventListener("input", (event) => {
    renderGroupOuList(event.target.value);
  });

  document.querySelector("#audit-operator-filter").addEventListener("input", (event) => {
    state.auditOperatorFilter = event.target.value;
    renderAudit();
  });

  document.querySelector("#workspace-governance-search").addEventListener("input", (event) => {
    state.workspaceGovernanceSearch = event.target.value;
    renderWorkspaceGovernanceModal();
  });

  document.querySelector("#groups-modal").addEventListener("click", (event) => {
    const addButton = event.target.closest("[data-group-add]");
    const removeButton = event.target.closest("[data-group-remove]");
    if (addButton) {
      changeIdentityGroup(
        "add",
        decodeURIComponent(addButton.dataset.groupAdd),
        decodeURIComponent(addButton.dataset.groupName || ""),
        addButton.dataset.groupCritical === "1",
      );
      return;
    }
    if (removeButton) {
      changeIdentityGroup(
        "remove",
        decodeURIComponent(removeButton.dataset.groupRemove),
        decodeURIComponent(removeButton.dataset.groupName || ""),
      );
    }
  });

  document.querySelector("#password-submit").addEventListener("click", submitPasswordReset);

  document.querySelector("#move-ou-submit").addEventListener("click", submitMoveOu);

  document.querySelector("#create-user-submit").addEventListener("click", submitCreateUser);

  document.querySelector("#create-group-submit").addEventListener("click", submitCreateGroup);

  document.querySelectorAll("[data-operator-action]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.operatorAction === "remove") {
        removeSelectedOperator();
        return;
      }
      readonlyNotice(button.textContent.trim());
    });
  });

  document.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.action === "sync-google-workspace") {
        button.disabled = true;
        showToast("Sync Google Workspace iniciado. Aguarde o retorno da tarefa.");
        try {
          await apiPost("/api/sync/google-workspace");
          showToast("Sync Google Workspace executado com sucesso.");
          await refreshAudit();
        } catch (error) {
          showToast(`Falha no sync Google Workspace: ${error.message}`);
          await refreshAudit();
        } finally {
          button.disabled = false;
        }
        return;
      }

      if (button.dataset.action === "sync") {
        button.disabled = true;
        showToast("Sincronização AD iniciada. Aguarde o retorno da API.");
        try {
          const result = await apiPost("/api/sync/ad");
          showToast(`Sincronização concluída: ${result.users_synced} usuários e ${result.groups_synced} grupos.`);
          await loadData();
        } catch (error) {
          showToast(`Falha na sincronização: ${error.message}`);
          await loadData();
        } finally {
          button.disabled = false;
        }
        return;
      }

      if (button.dataset.action === "invite-user") {
        openCreateUserModal();
        return;
      }

      if (button.dataset.action === "map-app") {
        openCreateGroupModal();
        return;
      }

      if (button.dataset.action === "workspace-governance") {
        openWorkspaceGovernanceModal();
        return;
      }

      if (button.dataset.action === "export-audit") {
        exportAuditReport();
        return;
      }

      if (button.dataset.action === "export-critical") {
        exportCriticalReport();
        return;
      }

      readonlyNotice(button.textContent.trim());
    });
  });

  document.querySelector("#logout-button").addEventListener("click", async () => {
    await logout("manual");
  });
}

function init() {
  bindEvents();
  startSessionTimer();
  loadData();
}

init();
