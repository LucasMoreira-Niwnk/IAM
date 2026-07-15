const API_BASE_URL = window.IAM_API_BASE_URL || localStorage.getItem("IAM_API_BASE_URL") || "";

const state = {
  identities: [],
  groups: [],
  operators: [],
  critical: { users_count: 0, groups_count: 0, users: [], groups: [] },
  syncRuns: [],
  selectedIdentityId: null,
  selectedIdentityGroups: [],
  selectedOperatorId: null,
  activeFilter: "all",
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
  const response = await fetch(apiUrl(path), { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`GET ${path} retornou ${response.status}`);
  }
  return response.json();
}

async function apiPost(path) {
  const response = await fetch(apiUrl(path), { method: "POST", headers: { Accept: "application/json" } });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `POST ${path} retornou ${response.status}`);
  }
  return response.json();
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
          <span class="badge ${run.status === "success" ? "active" : "review"}">${run.status}</span>
        </article>
      `,
    )
    .join("");
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
  const searchTerm = document.querySelector("#global-search").value.trim().toLowerCase();
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
    return;
  }

  document.querySelector("#identity-table").innerHTML = users
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
            <article class="group-item">
              <div>
                <strong>${group.group_name}</strong>
                <span>${group.is_critical ? "Crítico" : "Padrão"}</span>
              </div>
              <button class="text-button danger-text" type="button" data-readonly-action="remove-group">Remover</button>
            </article>
          `,
        )
        .join("")
    : `<div class="empty-state">Nenhum grupo retornado pela API.</div>`;

  document.querySelector("#group-select").innerHTML = state.groups
    .map((group) => `<option value="${group.name}">${group.name}</option>`)
    .join("");

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
  if (!state.groups.length) {
    renderEmpty("#access-grid", "Nenhum grupo sincronizado ainda.");
    return;
  }

  document.querySelector("#access-grid").innerHTML = state.groups
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
              <span class="badge ${run.status === "success" ? "active" : "review"}">${run.users_synced || 0} usuários</span>
            </li>
          `,
        )
        .join("")
    : `<li><span class="audit-time">-</span><strong>Nenhuma sincronização registrada</strong><span class="badge review">Pendente</span></li>`;
}

function renderAll() {
  renderMetrics();
  renderReviews();
  renderDirectoryIndicators();
  renderIdentities();
  renderAccess();
  renderCriticalPermissions();
  renderOperators();
  renderAudit();
}

async function loadData() {
  state.loading = true;
  try {
    const [identities, groups, operators, critical, syncRuns] = await Promise.all([
      apiGet("/api/identities"),
      apiGet("/api/groups"),
      apiGet("/api/operators"),
      apiGet("/api/critical-permissions"),
      apiGet("/api/sync-runs"),
    ]);

    state.identities = identities;
    state.groups = groups;
    state.operators = operators;
    state.critical = critical;
    state.syncRuns = syncRuns;
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
      document.querySelectorAll(".chip").forEach((chip) => chip.classList.remove("is-active"));
      button.classList.add("is-active");
      renderIdentities();
    });
  });

  document.querySelector("#global-search").addEventListener("input", renderIdentities);

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
    if (event.target.closest("[data-readonly-action]")) {
      readonlyNotice("Remoção de grupo");
    }
  });

  document.querySelectorAll("[data-identity-action]").forEach((button) => {
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
}

function init() {
  bindEvents();
  loadData();
}

init();
