const identities = [
  {
    id: "ana-martins",
    name: "Ana Martins",
    email: "ana.martins@empresa.com",
    username: "ana.martins",
    title: "Analista financeira",
    department: "Financeiro",
    manager: "Marcos Lima",
    phone: "+55 11 4000-1001",
    location: "Sao Paulo",
    source: "AD",
    status: "active",
    risk: "low",
    access: 8,
    lastLogin: "Hoje, 08:12",
    passwordAge: "34 dias",
    groups: ["CT-Financeiro", "ERP-Leitura", "M365-Usuarios", "ERP-Admin"],
    apps: ["Microsoft 365", "ERP Financeiro", "Service Desk"],
    events: ["Logon no AD registrado", "Senha alterada ha 34 dias", "Grupo ERP-Admin revisado"],
  },
  {
    id: "bruno-costa",
    name: "Bruno Costa",
    email: "bruno.costa@empresa.com",
    username: "bruno.costa",
    title: "Administrador de infraestrutura",
    department: "TI",
    manager: "Renata Alves",
    phone: "+55 11 4000-1002",
    location: "Campinas",
    source: "AD",
    status: "review",
    risk: "high",
    access: 21,
    lastLogin: "Hoje, 07:44",
    passwordAge: "82 dias",
    groups: ["CT-TI", "VPN-Admin", "M365-Admin", "ServiceDesk-Admin"],
    apps: ["Microsoft 365", "VPN Global", "Service Desk", "Data Lake"],
    events: ["Permissao critica detectada", "Revisao trimestral pendente", "Logon fora do horario padrao"],
  },
  {
    id: "carla-nunes",
    name: "Carla Nunes",
    email: "carla.nunes@empresa.com",
    username: "carla.nunes",
    title: "Coordenadora de operacoes",
    department: "Operacoes",
    manager: "Patricia Gomes",
    phone: "+55 11 4000-1003",
    location: "Santos",
    source: "HR",
    status: "active",
    risk: "medium",
    access: 12,
    lastLogin: "Ontem, 18:31",
    passwordAge: "19 dias",
    groups: ["CT-Operacoes", "CRM-Leitura", "M365-Usuarios"],
    apps: ["Microsoft 365", "CRM Vendas", "Service Desk"],
    events: ["Novo cargo importado do RH", "Grupo CRM-Leitura concedido", "Senha alterada ha 19 dias"],
  },
  {
    id: "diego-rocha",
    name: "Diego Rocha",
    email: "diego.rocha@empresa.com",
    username: "diego.rocha",
    title: "Executivo comercial",
    department: "Comercial",
    manager: "Sofia Mendes",
    phone: "+55 11 4000-1004",
    location: "Rio de Janeiro",
    source: "AD",
    status: "blocked",
    risk: "high",
    access: 3,
    lastLogin: "12/05/2026, 16:20",
    passwordAge: "91 dias",
    groups: ["CT-Comercial"],
    apps: ["Microsoft 365", "CRM Vendas"],
    events: ["Conta bloqueada por desligamento", "Grupos privilegiados removidos", "Sessao encerrada"],
  },
  {
    id: "elisa-prado",
    name: "Elisa Prado",
    email: "elisa.prado@empresa.com",
    username: "elisa.prado",
    title: "Advogada corporativa",
    department: "Juridico",
    manager: "Helena Torres",
    phone: "+55 11 4000-1005",
    location: "Sao Paulo",
    source: "AD",
    status: "review",
    risk: "medium",
    access: 10,
    lastLogin: "Hoje, 09:04",
    passwordAge: "45 dias",
    groups: ["CT-Juridico", "M365-Usuarios", "DPO-Consulta", "DataLake-Consulta"],
    apps: ["Microsoft 365", "Data Lake"],
    events: ["Conta exige revisao operacional", "Politica DPO aplicada", "Grupo DataLake-Consulta revisado"],
  },
];

const availableGroups = [
  "CT-Financeiro",
  "CT-TI",
  "CT-Operacoes",
  "CT-Comercial",
  "CT-Juridico",
  "ERP-Admin",
  "ERP-Leitura",
  "VPN-Admin",
  "VPN-Usuarios",
  "M365-Admin",
  "M365-Usuarios",
  "DataLake-Consulta",
  "ServiceDesk-Admin",
  "Domain Admins",
  "Account Operators",
  "Backup Operators",
];

const criticalGroups = [
  "Domain Admins",
  "Account Operators",
  "Backup Operators",
  "ERP-Admin",
  "VPN-Admin",
  "M365-Admin",
  "ServiceDesk-Admin",
  "DataLake-Consulta",
];

const adGroupCatalog = [
  { name: "M365-Usuarios", owner: "TI Corporativo", members: 128, critical: false, risk: "low" },
  { name: "ERP-Admin", owner: "Controladoria", members: 3, critical: true, risk: "high" },
  { name: "CRM-Leitura", owner: "Comercial", members: 54, critical: false, risk: "low" },
  { name: "VPN-Admin", owner: "Seguranca", members: 2, critical: true, risk: "high" },
  { name: "ServiceDesk-Admin", owner: "Operacoes TI", members: 4, critical: true, risk: "medium" },
  { name: "DataLake-Consulta", owner: "Dados", members: 8, critical: true, risk: "high" },
];

const serviceDeskOperations = [
  { title: "Reset de senha para usuario bloqueado", owner: "Service Desk N1", priority: "Alta" },
  { title: "Inclusao em grupo M365-Usuarios", owner: "Service Desk N1", priority: "Normal" },
  { title: "Remocao de grupo VPN-Admin", owner: "Service Desk N2", priority: "Critica" },
  { title: "Bloqueio por desligamento importado do RH", owner: "Service Desk N2", priority: "Alta" },
];

const permissions = [
  {
    key: "viewIdentities",
    title: "Consultar identidades",
    description: "Pesquisar usuarios e visualizar atributos importados do AD.",
  },
  {
    key: "resetPassword",
    title: "Alterar senha",
    description: "Redefinir senha e exigir troca no proximo logon.",
  },
  {
    key: "lockUnlock",
    title: "Bloquear ou desbloquear",
    description: "Bloquear, desbloquear e encerrar sessoes do usuario.",
  },
  {
    key: "manageGroups",
    title: "Editar grupos",
    description: "Adicionar ou remover o usuario de grupos permitidos.",
  },
  {
    key: "managePrivilegedGroups",
    title: "Editar grupos privilegiados",
    description: "Alterar grupos administrativos como VPN-Admin e M365-Admin.",
  },
  {
    key: "syncAd",
    title: "Sincronizar AD",
    description: "Executar leitura manual do diretorio e atualizar cache.",
  },
  {
    key: "manageOperators",
    title: "Gerenciar operadores",
    description: "Criar usuarios internos e alterar permissoes do IAM.",
  },
  {
    key: "viewAudit",
    title: "Auditoria",
    description: "Consultar logs das alteracoes feitas via conta de servico.",
  },
];

const operators = [
  {
    id: "mariana-lopes",
    name: "Mariana Lopes",
    email: "mariana.lopes@casaeterra.com",
    role: "Coordenadora Service Desk",
    status: "active",
    mfa: "Ativo",
    lastAccess: "Hoje, 09:28",
    scope: "Todos os departamentos",
    permissions: {
      viewIdentities: true,
      resetPassword: true,
      lockUnlock: true,
      manageGroups: true,
      managePrivilegedGroups: true,
      syncAd: true,
      manageOperators: true,
      viewAudit: true,
    },
  },
  {
    id: "rafael-pires",
    name: "Rafael Pires",
    email: "rafael.pires@casaeterra.com",
    role: "Service Desk N2",
    status: "active",
    mfa: "Ativo",
    lastAccess: "Hoje, 10:14",
    scope: "TI, Operacoes e Comercial",
    permissions: {
      viewIdentities: true,
      resetPassword: true,
      lockUnlock: true,
      manageGroups: true,
      managePrivilegedGroups: false,
      syncAd: true,
      manageOperators: false,
      viewAudit: true,
    },
  },
  {
    id: "julia-santos",
    name: "Julia Santos",
    email: "julia.santos@casaeterra.com",
    role: "Service Desk N1",
    status: "review",
    mfa: "Pendente",
    lastAccess: "Ontem, 17:51",
    scope: "Usuarios padrao",
    permissions: {
      viewIdentities: true,
      resetPassword: true,
      lockUnlock: false,
      manageGroups: false,
      managePrivilegedGroups: false,
      syncAd: false,
      manageOperators: false,
      viewAudit: false,
    },
  },
  {
    id: "thiago-ramos",
    name: "Thiago Ramos",
    email: "thiago.ramos@casaeterra.com",
    role: "Service Desk N1",
    status: "review",
    mfa: "Ativo",
    lastAccess: "Primeiro acesso pendente",
    scope: "Aguardando liberacao",
    permissions: {
      viewIdentities: false,
      resetPassword: false,
      lockUnlock: false,
      manageGroups: false,
      managePrivilegedGroups: false,
      syncAd: false,
      manageOperators: false,
      viewAudit: false,
    },
  },
];

const audits = [
  { time: "08:42", event: "Sincronizacao AD concluiu com 128 alteracoes", actor: "Conector AD" },
  { time: "09:15", event: "Grupo VPN Admin marcado para recertificacao", actor: "Politica IAM" },
  { time: "10:03", event: "Senha redefinida para Ana Martins", actor: "Marcos Lima" },
  { time: "11:20", event: "Usuario Diego Rocha bloqueado por desligamento", actor: "Sistema RH" },
  { time: "13:08", event: "Grupo DataLake-Consulta mapeado como critico", actor: "Dados" },
];

const statusLabels = {
  active: "Ativo",
  review: "Em revisao",
  blocked: "Bloqueado",
  disabled: "Desabilitado",
};

const riskLabels = {
  low: "Baixo",
  medium: "Medio",
  high: "Alto",
};

let activeFilter = "all";
let selectedIdentityId = identities[0].id;
let selectedOperatorId = operators[0].id;

function initials(name) {
  return name
    .split(" ")
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(showToast.timeout);
  showToast.timeout = window.setTimeout(() => toast.classList.remove("is-visible"), 2600);
}

function renderMetrics() {
  document.querySelector("#metric-users").textContent = identities.filter(
    (user) => user.status === "active",
  ).length;
  document.querySelector("#metric-privileged").textContent = criticalUsers().length;
  document.querySelector("#metric-operations").textContent = serviceDeskOperations.length;
  document.querySelector("#metric-operators").textContent = operators.filter(
    (operator) => operator.status === "active",
  ).length;
}

function userCriticalGroups(user) {
  return user.groups.filter((group) => criticalGroups.includes(group));
}

function criticalUsers() {
  return identities.filter((user) => userCriticalGroups(user).length > 0);
}

function renderReviews() {
  const reviewList = document.querySelector("#review-list");
  const items = serviceDeskOperations;

  reviewList.innerHTML = items
    .map(
      (item) => `
        <article class="review-item">
          <div>
            <strong>${item.title}</strong>
            <span>${item.owner}</span>
          </div>
          <span class="badge ${item.priority === "Critica" ? "high" : "medium"}">${item.priority}</span>
        </article>
      `,
    )
    .join("");
}

function renderRiskBars() {
  const sources = [
    { label: "Contas bloqueadas", value: 20 },
    { label: "Contas em revisao", value: 40 },
    { label: "Grupos criticos com membros", value: 70 },
    { label: "Operadores sem permissao", value: 25 },
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
  const users = identities.filter((user) => {
    const matchesFilter = activeFilter === "all" || user.status === activeFilter;
    const searchable = `${user.name} ${user.email} ${user.department} ${user.source}`.toLowerCase();
    return matchesFilter && searchable.includes(searchTerm);
  });

  document.querySelector("#identity-table").innerHTML = users
    .map(
      (user) => `
        <tr class="clickable-row" data-identity-id="${user.id}">
          <td>
            <div class="user-cell">
              <span class="avatar">${initials(user.name)}</span>
              <div>
                <strong>${user.name}</strong><br />
                <small>${user.email}</small>
              </div>
            </div>
          </td>
          <td>${user.department}</td>
          <td>${user.source}</td>
          <td><span class="badge ${user.status}">${statusLabels[user.status]}</span></td>
          <td><span class="badge ${user.risk}">${riskLabels[user.risk]}</span></td>
          <td>${user.groups.length}</td>
          <td><button class="text-button" type="button" data-open-identity="${user.id}">Detalhes</button></td>
        </tr>
      `,
    )
    .join("");
}

function selectedIdentity() {
  return identities.find((user) => user.id === selectedIdentityId) || identities[0];
}

function renderIdentityDetail() {
  const user = selectedIdentity();
  const blockButton = document.querySelector("[data-identity-action='block']");
  const unlockButton = document.querySelector("[data-identity-action='unlock']");
  const disableButton = document.querySelector("[data-identity-action='disable']");

  if (blockButton) {
    blockButton.disabled = user.status === "blocked" || user.status === "disabled";
  }

  if (unlockButton) {
    unlockButton.disabled = user.status !== "blocked";
  }

  if (disableButton) {
    disableButton.textContent = user.status === "disabled" ? "Habilitar" : "Desabilitar";
  }

  document.querySelector("#identity-hero").innerHTML = `
    <div class="identity-avatar">${initials(user.name)}</div>
    <div>
      <p class="eyebrow">${user.department}</p>
      <h2>${user.name}</h2>
      <span>${user.title} - ${user.email}</span>
    </div>
    <div class="identity-badges">
      <span class="badge ${user.status}">${statusLabels[user.status]}</span>
      <span class="badge ${user.risk}">Criticidade ${riskLabels[user.risk]}</span>
    </div>
  `;

  const info = [
    ["Usuario", user.username],
    ["Gestor", user.manager],
    ["Telefone", user.phone],
    ["Localidade", user.location],
    ["Origem", user.source],
    ["Ultimo login", user.lastLogin],
  ];

  document.querySelector("#identity-info").innerHTML = info
    .map(([label, value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`)
    .join("");

  document.querySelector("#identity-security").innerHTML = `
    <article>
      <span>Idade da senha</span>
      <strong>${user.passwordAge}</strong>
    </article>
    <article>
      <span>Sessoes ativas</span>
      <strong>${["blocked", "disabled"].includes(user.status) ? "0" : "2"}</strong>
    </article>
  `;

  document.querySelector("#identity-groups").innerHTML = user.groups
    .map(
      (group) => `
        <article class="group-item">
          <div>
            <strong>${group}</strong>
            <span>${group.includes("Admin") ? "Privilegiado" : "Padrao"}</span>
          </div>
          <button class="text-button danger-text" type="button" data-remove-group="${group}">Remover</button>
        </article>
      `,
    )
    .join("");

  const groupSelect = document.querySelector("#group-select");
  groupSelect.innerHTML = availableGroups
    .filter((group) => !user.groups.includes(group))
    .map((group) => `<option value="${group}">${group}</option>`)
    .join("");

  document.querySelector("#identity-apps").innerHTML = user.apps
    .map((app) => `<article><strong>${app}</strong><span>Provisionado por grupo</span></article>`)
    .join("");

  document.querySelector("#identity-events").innerHTML = user.events
    .map((event) => `<li>${event}</li>`)
    .join("");
}

function openIdentityDetail(identityId) {
  selectedIdentityId = identityId;
  renderIdentityDetail();
  switchView("identity-detail");
}

function renderAccess() {
  document.querySelector("#access-grid").innerHTML = adGroupCatalog
    .map(
      (app) => `
        <article class="access-card">
          <div>
            <strong>${app.name}</strong>
            <span>Responsavel: ${app.owner}</span>
          </div>
          <span class="badge ${app.risk}">${app.critical ? "Critico" : "Padrao"}</span>
          <footer>
            <span>${app.members} membros</span>
            <span>${app.critical ? "Requer controle" : "Uso comum"}</span>
          </footer>
        </article>
      `,
    )
    .join("");
}

function renderCriticalPermissions() {
  const users = criticalUsers();
  const groupCounts = criticalGroups
    .map((group) => ({
      group,
      count: identities.filter((user) => user.groups.includes(group)).length,
    }))
    .filter((item) => item.count > 0);

  document.querySelector("#critical-user-count").textContent = users.length;
  document.querySelector("#critical-group-count").textContent = groupCounts.length;
  document.querySelector("#critical-disabled-count").textContent = users.filter(
    (user) => user.status === "disabled" || user.status === "blocked",
  ).length;

  document.querySelector("#critical-groups").innerHTML = groupCounts
    .map(
      (item) => `
        <article class="critical-group-row">
          <div>
            <strong>${item.group}</strong>
            <span>${item.count} usuario${item.count > 1 ? "s" : ""}</span>
          </div>
          <div class="bar" aria-hidden="true"><span style="width: ${Math.min(item.count * 24, 100)}%"></span></div>
        </article>
      `,
    )
    .join("");

  document.querySelector("#critical-table").innerHTML = users
    .map((user) => {
      const groups = userCriticalGroups(user);
      return `
        <tr class="clickable-row" data-critical-identity-id="${user.id}">
          <td>
            <div class="user-cell">
              <span class="avatar">${initials(user.name)}</span>
              <div>
                <strong>${user.name}</strong><br />
                <small>${user.email}</small>
              </div>
            </div>
          </td>
          <td>${user.department}</td>
          <td><span class="badge ${user.status}">${statusLabels[user.status]}</span></td>
          <td>${groups.map((group) => `<span class="inline-pill">${group}</span>`).join("")}</td>
          <td><button class="text-button" type="button" data-open-critical="${user.id}">Detalhes</button></td>
        </tr>
      `;
    })
    .join("");
}

function selectedOperator() {
  return operators.find((operator) => operator.id === selectedOperatorId) || operators[0];
}

function renderOperators() {
  document.querySelector("#operator-list").innerHTML = operators
    .map(
      (operator) => `
        <button class="operator-card ${operator.id === selectedOperatorId ? "is-selected" : ""}" type="button" data-operator-id="${operator.id}">
          <span class="avatar">${initials(operator.name)}</span>
          <span>
            <strong>${operator.name}</strong>
            <small>${operator.role}</small>
          </span>
          <span class="badge ${operator.status}">${statusLabels[operator.status]}</span>
        </button>
      `,
    )
    .join("");

  renderOperatorDetail();
}

function renderOperatorDetail() {
  const operator = selectedOperator();
  const enabledCount = permissions.filter((permission) => operator.permissions[permission.key]).length;

  document.querySelector("#operator-profile").innerHTML = `
    <div class="identity-avatar">${initials(operator.name)}</div>
    <div>
      <p class="eyebrow">${operator.role}</p>
      <h3>${operator.name}</h3>
      <span>${operator.email}</span>
      <span>Escopo: ${operator.scope}</span>
    </div>
    <div class="operator-stats">
      <span class="badge ${operator.status}">${statusLabels[operator.status]}</span>
      <span class="badge ${operator.mfa === "Ativo" ? "active" : "review"}">MFA ${operator.mfa}</span>
      <strong>${enabledCount}/${permissions.length}</strong>
      <small>permissoes ativas</small>
    </div>
  `;

  document.querySelector("#permission-grid").innerHTML = permissions
    .map(
      (permission) => `
        <label class="permission-item">
          <input type="checkbox" data-permission-key="${permission.key}" ${operator.permissions[permission.key] ? "checked" : ""} />
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
  document.querySelector("#audit-feed").innerHTML = audits
    .map(
      (item) => `
        <li>
          <span class="audit-time">${item.time}</span>
          <strong>${item.event}</strong>
          <span class="badge low">${item.actor}</span>
        </li>
      `,
    )
    .join("");
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

function bindEvents() {
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.view));
  });

  document.querySelectorAll("[data-view-link]").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.viewLink));
  });

  document.querySelectorAll(".chip").forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
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

    if (identityId) {
      openIdentityDetail(identityId);
    }
  });

  document.querySelector("#critical-table").addEventListener("click", (event) => {
    const openButton = event.target.closest("[data-open-critical]");
    const row = event.target.closest("[data-critical-identity-id]");
    const identityId = openButton?.dataset.openCritical || row?.dataset.criticalIdentityId;

    if (identityId) {
      openIdentityDetail(identityId);
    }
  });

  document.querySelector("#identity-groups").addEventListener("click", (event) => {
    const removeButton = event.target.closest("[data-remove-group]");
    if (!removeButton) return;

    const user = selectedIdentity();
    user.groups = user.groups.filter((group) => group !== removeButton.dataset.removeGroup);
    user.access = Math.max(0, user.access - 1);
    renderIdentityDetail();
    renderIdentities();
    renderCriticalPermissions();
    renderMetrics();
    showToast(`Grupo ${removeButton.dataset.removeGroup} removido de ${user.name}.`);
  });

  document.querySelector("#operator-list").addEventListener("click", (event) => {
    const operatorButton = event.target.closest("[data-operator-id]");
    if (!operatorButton) return;

    selectedOperatorId = operatorButton.dataset.operatorId;
    renderOperators();
  });

  document.querySelector("#permission-grid").addEventListener("change", (event) => {
    const permissionInput = event.target.closest("[data-permission-key]");
    if (!permissionInput) return;

    const operator = selectedOperator();
    operator.permissions[permissionInput.dataset.permissionKey] = permissionInput.checked;
    renderOperatorDetail();
  });

  document.querySelectorAll("[data-operator-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const messages = {
        create: "Novos operadores serao importados do grupo GG-IAM-OPERADORES via LDAP.",
        save: `Permissoes de ${selectedOperator().name} salvas no frontend.`,
      };
      showToast(messages[button.dataset.operatorAction] || "Acao do operador registrada.");
    });
  });

  document.querySelectorAll("[data-identity-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const user = selectedIdentity();

      if (button.dataset.identityAction === "block") {
        user.status = "blocked";
        renderIdentityDetail();
        renderIdentities();
        renderCriticalPermissions();
        renderMetrics();
        showToast(`${user.name} bloqueado com sucesso.`);
        return;
      }

      if (button.dataset.identityAction === "unlock") {
        user.status = "active";
        renderIdentityDetail();
        renderIdentities();
        renderCriticalPermissions();
        renderMetrics();
        showToast(`${user.name} desbloqueado com sucesso.`);
        return;
      }

      if (button.dataset.identityAction === "disable") {
        user.status = user.status === "disabled" ? "active" : "disabled";
        renderIdentityDetail();
        renderIdentities();
        renderCriticalPermissions();
        renderMetrics();
        showToast(`${user.name} ${user.status === "disabled" ? "desabilitado" : "habilitado"} no frontend.`);
        return;
      }

      if (button.dataset.identityAction === "password") {
        user.passwordAge = "0 dias";
        renderIdentityDetail();
        showToast(`Redefinicao de senha preparada para ${user.name}.`);
        return;
      }

      if (button.dataset.identityAction === "sessions") {
        user.events.unshift("Sessoes encerradas pelo administrador");
        renderIdentityDetail();
        showToast(`Sessoes de ${user.name} encerradas.`);
        return;
      }

      if (button.dataset.identityAction === "review") {
        user.status = "review";
        renderIdentityDetail();
        renderIdentities();
        renderCriticalPermissions();
        showToast(`Revisao operacional iniciada para ${user.name}.`);
        return;
      }

      if (button.dataset.identityAction === "revoke") {
        user.groups = [];
        user.apps = [];
        user.access = 0;
        user.risk = "low";
        renderIdentityDetail();
        renderIdentities();
        renderCriticalPermissions();
        renderMetrics();
        showToast(`Grupos de ${user.name} removidos no frontend.`);
        return;
      }

      if (button.dataset.identityAction === "add-group") {
        const groupSelect = document.querySelector("#group-select");
        const group = groupSelect.value;
        if (!group) {
          showToast("Nao ha grupos disponiveis para adicionar.");
          return;
        }
        user.groups.push(group);
        user.access += 1;
        renderIdentityDetail();
        renderIdentities();
        renderCriticalPermissions();
        renderMetrics();
        showToast(`Grupo ${group} adicionado a ${user.name}.`);
      }
    });
  });

  document.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const messages = {
        sync: "Sincronizacao AD colocada na fila.",
        "invite-user": "Criacao de usuario no AD sera conectada ao backend.",
        "map-app": "Mapeamento de grupo AD sera conectado ao backend.",
        "export-audit": "Exportacao sera gerada pela API de auditoria.",
        "export-critical": "Relatorio de permissoes criticas sera gerado pelo backend.",
      };
      showToast(messages[button.dataset.action] || "Acao registrada.");
    });
  });
}

function init() {
  renderMetrics();
  renderReviews();
  renderRiskBars();
  renderIdentities();
  renderAccess();
  renderCriticalPermissions();
  renderOperators();
  renderAudit();
  bindEvents();
}

init();
