const API_BASE_URL = window.IAM_API_BASE_URL || localStorage.getItem("IAM_API_BASE_URL") || "";
const SESSION_TIMEOUT_MS =
  Number(window.IAM_SESSION_TIMEOUT_MS || localStorage.getItem("IAM_SESSION_TIMEOUT_MS")) || 30 * 60 * 1000;
let sessionTimeoutId = null;

const state = {
  identities: [],
  groups: [],
  operators: [],
  critical: { users_count: 0, groups_count: 0, users: [], groups: [] },
  syncRuns: [],
  currentUser: null,
  selectedIdentityId: null,
  selectedIdentityGroups: [],
  selectedOperatorId: null,
  activeFilter: "all",
  identityPage: 1,
  identityPageSize: 10,
  groupPage: 1,
  groupPageSize: 10,
  loading: true,
  apiOnline: false,
};

const statusLabels = {
  active: "Ativo",
  pending: "Pendente",
  review: "Em revisão",
  blocked: "Bloqueado",
  disabled: "Desabilitado",
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
    throw new Error(`GET ${path} retornou ${response.status}`);
  }
  return response.json();
}

async function apiPost(path) {
  const response = await fetch(apiUrl(path), {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST ${path} retornou ${response.status}`);
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

  if (reason === "timeout") {
    sessionStorage.setItem("IAM_LOGOUT_REASON", "Sua sessão expirou por inatividade.");
  }

  window.location.href = "/login.html";
}

function resetSessionTimer() {
  window.clearTimeout(sessionTimeoutId);
  sessionTimeoutId = window.setTimeout(() => {
    logout("timeout");
  }, SESSION_TIMEOUT_MS);
}

function startSessionTimer() {
  ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach((eventName) => {
    document.addEventListener(eventName, resetSessionTimer, { passive: true });
  });
  resetSessionTimer();
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
  return status || "review";
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
    state.currentUser?.role ||
    state.currentUser?.title ||
    state.operators.find((operator) => operator.display_name === name || operator.username === name)?.title ||
    "Service Desk";

  document.querySelector("#current-user-avatar").textContent = initials(name);
  document.querySelector("#current-user-name").textContent = name;
  document.querySelector("#current-user-role").textContent = role || "Service Desk";
}

function renderReviews() {
  const reviewList = document.querySelector("#review-list");
  const latestRuns = state.syncRuns.slice(0, 4);

  if (!latestRuns.length) {
    renderEmpty("#review-list", "Nenhuma sincronização registrada ainda.");
    return;
  }

  reviewList.innerHTML = latestRuns
    .map(
      (run) => `
        <article class="review-item">
          <div>
            <strong>Sincronização ${statusLabel(run.status)}</strong>
            <span>${formatSyncTime(run.started_at)} - ${run.users_synced || 0} usuários, ${run.groups_synced || 0} grupos</span>
          </div>
          <span class="badge sync-status ${run.status === "success" ? "success" : "review"}">${run.status}</span>
        </article>
      `,
    )
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

  statusEl.textContent = latest.status === "success" ? "Sincronização concluída" : `Sincronização ${latest.status}`;
  lastSyncEl.textContent = `Última leitura: ${formatSyncTime(latest.finished_at || latest.started_at)}`;
}

function renderDirectoryIndicators() {
  const blocked = state.identities.filter((identity) => identity.status === "blocked").length;
  const disabled = state.identities.filter((identity) => identity.status === "disabled").length;
  const criticalGroups = state.critical.groups_count || 0;
  const pendingOperators = state.operators.filter((operator) => operator.status === "pending").length;
  const max = Math.max(state.identities.length, state.groups.length, state.operators.length, 1);
  const sources = [
    { label: "Contas bloqueadas", value: Math.round((blocked / max) * 100) },
    { label: "Contas desabilitadas", value: Math.round((disabled / max) * 100) },
    { label: "Grupos críticos com membros", value: Math.round((criticalGroups / Math.max(state.groups.length, 1)) * 100) },
    { label: "Operadores pendentes", value: Math.round((pendingOperators / Math.max(state.operators.length, 1)) * 100) },
  ];

  document.querySelector("#risk-bars").innerHTML = sources
    .map(
      (source) => `
        <article class="risk-row">
          <div class="risk-meta">
            <span>${source.label}</span>
            <span>${source.value}%</span>
          </div>
          <div class="bar" aria-hidden="true"><span style="width: ${source.value}%"></span></div>
        </article>
      `,
    )
    .join("");
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
        <article class="access-card">
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
                  <button type="button" data-search-group="${encodeURIComponent(group.name)}">
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
    renderEmpty("#operator-list", "Nenhum operador importado do grupo GG-IAM-OPERADORES.");
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

  document.querySelector("#operator-profile").innerHTML = `
    <div class="identity-avatar">${initials(operator.display_name || operator.username)}</div>
    <div>
      <p class="eyebrow">${operator.title || "Operador IAM"}</p>
      <h3>${operator.display_name || operator.username}</h3>
      <span>${operator.email || ""}</span>
      <span>Departamento: ${operator.department || "-"}</span>
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
          <input type="checkbox" data-permission-key="${permission.key}" ${operatorPermissions[permission.key] ? "checked" : ""} />
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
  document.querySelector("#audit-feed").innerHTML = state.syncRuns.length
    ? state.syncRuns
        .map(
          (run) => `
            <li>
              <span class="audit-time">${formatSyncTime(run.started_at)}</span>
              <strong>Sincronização AD ${run.status}</strong>
              <span class="badge sync-status ${run.status === "success" ? "success" : "review"}">${run.users_synced || 0} usuários</span>
            </li>
          `,
        )
        .join("")
    : `<li><span class="audit-time">-</span><strong>Nenhuma sincronização registrada</strong><span class="badge review">Pendente</span></li>`;
}

function renderAll() {
  renderMetrics();
  renderCurrentUser();
  renderSidebarSyncStatus();
  renderReviews();
  renderDirectoryIndicators();
  renderIdentities();
  renderAccess();
  renderGlobalSearchResults();
  renderCriticalPermissions();
  renderOperators();
  renderAudit();
}

async function loadData() {
  state.loading = true;
  try {
    const [identities, groups, operators, critical, syncRuns, currentUser] = await Promise.all([
      apiGet("/api/identities"),
      apiGet("/api/groups"),
      apiGet("/api/operators"),
      apiGet("/api/critical-permissions"),
      apiGet("/api/sync-runs"),
      apiGetOptional("/api/auth/me"),
    ]);

    state.identities = identities;
    state.groups = groups;
    state.operators = operators;
    state.critical = critical;
    state.syncRuns = syncRuns;
    state.currentUser = currentUser;
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
    const activeView = viewName === "identity-detail" ? "identities" : viewName;
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
    <span class="avatar">${initials(identityName(identity))}</span>
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
              <button class="text-button danger-text" type="button" data-readonly-submit="remove-group">Remover</button>
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
              <button class="text-button" type="button" data-readonly-submit="add-group">Adicionar</button>
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
      document.querySelector("#global-search").value = decodeURIComponent(groupButton.dataset.searchGroup);
      state.groupPage = 1;
      renderAccess();
      document.querySelector("#global-search-results").classList.remove("is-visible");
      switchView("access");
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

  document.querySelector("#operator-list").addEventListener("click", (event) => {
    const operatorButton = event.target.closest("[data-operator-id]");
    if (!operatorButton) return;
    state.selectedOperatorId = operatorButton.dataset.operatorId;
    renderOperators();
  });

  document.querySelector("#permission-grid").addEventListener("change", (event) => {
    if (event.target.closest("[data-permission-key]")) {
      event.target.checked = !event.target.checked;
      readonlyNotice("Alteração de permissões");
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

      if (button.dataset.identityAction === "add-group" || button.dataset.identityAction === "revoke") {
        openGroupsModal();
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

  document.querySelector("#groups-modal").addEventListener("click", (event) => {
    const actionButton = event.target.closest("[data-readonly-submit]");
    if (actionButton) {
      readonlyNotice(actionButton.textContent.trim());
    }
  });

  document.querySelectorAll("#password-modal [data-readonly-submit]").forEach((button) => {
    button.addEventListener("click", () => readonlyNotice(button.textContent.trim()));
  });

  document.querySelectorAll("[data-operator-action]").forEach((button) => {
    button.addEventListener("click", () => readonlyNotice(button.textContent.trim()));
  });

  document.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.action === "sync") {
        button.disabled = true;
        showToast("Sincronização AD iniciada. Aguarde o retorno da API.");
        try {
          const result = await apiPost("/api/sync/ad");
          showToast(`Sincronização concluída: ${result.users_synced} usuários e ${result.groups_synced} grupos.`);
          await loadData();
        } catch (error) {
          showToast(`Falha na sincronização: ${error.message}`);
        } finally {
          button.disabled = false;
        }
        return;
      }

      if (button.dataset.action === "export-audit" || button.dataset.action === "export-critical") {
        readonlyNotice("Exportação");
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
