"use strict";

const API = {
  repositories: "/api/repositories",
  scans: "/api/scans",
  scanAll: "/api/repositories/scan-all",
  auth: "/api/auth",
  users: "/api/users",
};
const state = {
  user: null,
  csrf: null,
  scanBusy: false,
  users: new Map(),
  scans: new Map(),
  latestScans: new Map(),
  redirecting: false,
  authRefresh: null,
  latestGeneration: 0,
  historyGeneration: 0,
};
const PAGE = document.body.dataset.page;
const ROLE_NAMES = {
  superuser: "Super User",
  operator: "Operator",
  viewer: "Viewer",
};
const SAFE_PAGES = new Set([
  "/dashboard/",
  "/dashboard/index.html",
  "/dashboard/scan.html",
  "/dashboard/history.html",
  "/dashboard/policy.html",
  "/dashboard/users.html",
]);
const el = (id) => document.getElementById(id);
const canScan = () => ["superuser", "operator"].includes(state.user?.role);
const isSuperUser = () => state.user?.role === "superuser";
const mobileNavigation = window.matchMedia("(max-width: 900px)");

class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
}

function errorDetail(data, fallback) {
  const detail = data?.detail ?? data?.message ?? data?.error ?? data;
  if (typeof detail === "string" && detail.trim()) return detail.slice(0, 2000);
  if (Array.isArray(detail))
    return detail
      .map((item) =>
        typeof item === "string"
          ? item
          : `${Array.isArray(item?.loc) ? item.loc.filter((part) => part !== "body").join(".") + ": " : ""}${item?.msg || "Invalid request"}`,
      )
      .join("; ")
      .slice(0, 2000);
  return fallback;
}

async function fetchJson(url, options = {}) {
  const {
    allowUnauthorized = false,
    refreshOnForbidden = true,
    ...request
  } = options;
  const headers = new Headers(request.headers || {});
  const method = (request.method || "GET").toUpperCase();
  if (request.body && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  headers.set("Accept", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrf)
    headers.set("X-CSRF-Token", state.csrf);
  let response;
  try {
    response = await fetch(url, {
      ...request,
      headers,
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    throw new ApiError(
      "Cannot connect to the service. Check your connection and try again.",
    );
  }
  let raw;
  try {
    raw = await response.text();
  } catch {
    throw new ApiError(
      `Could not read the service response (HTTP ${response.status}).`,
      response.status,
    );
  }
  let data = {};
  if (raw.trim()) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = raw;
      if (
        response.ok &&
        response.headers.get("Content-Type")?.includes("application/json")
      )
        throw new ApiError(
          `The service returned invalid JSON (HTTP ${response.status}).`,
          response.status,
        );
    }
  }
  if (!response.ok) {
    if (response.status === 401 && !allowUnauthorized && PAGE !== "login")
      redirectToLogin();
    if (
      response.status === 403 &&
      refreshOnForbidden &&
      PAGE !== "login" &&
      state.user
    )
      await refreshIdentity().catch(() => {});
    throw new ApiError(
      `${errorDetail(data, response.statusText || "Request failed")} (HTTP ${response.status})`,
      response.status,
    );
  }
  return data;
}

function requireArray(data, key) {
  if (!Array.isArray(data?.[key]))
    throw new ApiError(
      `The service returned an invalid ${key} response. Try again.`,
    );
  return data[key];
}

function setMessage(id, text, type = "info") {
  const target = el(id);
  if (!target) return;
  target.replaceChildren();
  if (!text) return;
  const box = document.createElement("div");
  box.className = `message ${["info", "success", "warning", "error"].includes(type) ? type : "info"}`;
  box.textContent = text;
  box.setAttribute("role", type === "error" ? "alert" : "status");
  target.append(box);
}

function emptyState(title, text) {
  return `<div class="empty-state"><h3>${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p></div>`;
}

function errorBox(error, action, id = "") {
  return `<div class="error-box" role="alert"><p>${escapeHtml(error.message || error)}</p>${action ? `<button type="button" class="small-button" data-action="${escapeHtml(action)}" data-id="${escapeHtml(id)}">Retry</button>` : ""}</div>`;
}

function formatDate(value) {
  if (!value) return "Not scanned";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      });
}

function statusBadge(status) {
  const value = String(status || "NOT SCANNED").toUpperCase();
  const className =
    value === "ALLOW" ? "allow" : value === "BLOCK" ? "block" : "unknown";
  return `<span class="status-badge ${className}">${escapeHtml(value)}</span>`;
}

function findingRow(finding, repositoryName = "") {
  const severity = String(finding.severity || "UNKNOWN").toUpperCase();
  const className = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity)
    ? severity.toLowerCase()
    : "unknown";
  const location = `${finding.file || "No file information"}${finding.line != null ? `:${finding.line}` : ""}`;
  const meta = [repositoryName, finding.scanner || "Unknown scanner", location]
    .filter(Boolean)
    .join(" / ");
  return `<article class="finding-row"><div><strong>${escapeHtml(finding.rule_id || finding.message || "Security finding")}</strong><span class="finding-meta">${escapeHtml(meta)}</span>${finding.message ? `<p>${escapeHtml(finding.message)}</p>` : ""}${finding.cwe ? `<span class="finding-meta">${escapeHtml(finding.cwe)}</span>` : ""}</div><span class="severity-badge ${className}">${escapeHtml(severity)}</span></article>`;
}

function safeRepositoryLink(url) {
  try {
    const parsed = new URL(url);
    if (
      parsed.protocol === "https:" &&
      parsed.hostname === "github.com" &&
      !parsed.username &&
      !parsed.password
    )
      return `<a class="repository-url" href="${escapeHtml(parsed.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a>`;
  } catch {}
  return `<span class="repository-url">${escapeHtml(url)}</span>`;
}

function redirectToLogin() {
  if (state.redirecting) return;
  state.redirecting = true;
  state.user = null;
  state.csrf = null;
  if (el("protected-app")) el("protected-app").hidden = true;
  const next = SAFE_PAGES.has(location.pathname)
    ? location.pathname
    : "/dashboard/";
  location.replace(`/dashboard/login.html?next=${encodeURIComponent(next)}`);
}

function loginDestination() {
  const next = new URLSearchParams(location.search).get("next");
  if (!SAFE_PAGES.has(next)) return "/dashboard/";
  if (next === "/dashboard/users.html" && !isSuperUser()) return "/dashboard/";
  return next;
}

function navigationIcon(name) {
  const paths = {
    dashboard:
      '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    scan: '<path d="m12 3 8 4v6c0 4-5 7-8 8-3-1-8-4-8-8V7l8-4Z"/><path d="m8 12 3 3 5-6"/>',
    history: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    policy: '<path d="M7 3h10v18H7zM10 7h4M10 11h4M10 15h4"/>',
    users:
      '<circle cx="9" cy="8" r="3"/><path d="M3 21v-4a6 6 0 0 1 12 0v4M17 5a3 3 0 0 1 0 6M19 21v-4a5 5 0 0 0-2-4"/>',
  };
  return `<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">${paths[name]}</svg>`;
}

function renderShell() {
  const links = [
    ["dashboard", "index.html", "Dashboard"],
    ["scan", "scan.html", "Security Scan"],
    ["history", "history.html", "Scan History"],
    ["policy", "policy.html", "Security Policy"],
    ["users", "users.html", "User Management"],
  ];
  el("navigation-shell").innerHTML =
    `<aside class="sidebar" id="sidebar"><a class="brand" href="index.html"><span class="brand-icon" aria-hidden="true">S</span><span><strong>DevSecOps</strong><small>SECURITY PLATFORM</small></span></a><p class="nav-caption">WORKSPACE</p><nav aria-label="Main navigation">${links.map(([page, path, label]) => `<a class="nav-item ${PAGE === page ? "active" : ""}" href="${path}" ${PAGE === page ? 'aria-current="page"' : ""} ${page === "users" ? 'data-role="admin"' : ""}>${navigationIcon(page)}<span>${label}</span></a>`).join("")}</nav><div class="sidebar-footer"><span class="health-dot" id="health-dot"></span><span id="health-status">Checking service...</span><p>Bandit / Trivy / Gitleaks</p></div></aside><button type="button" class="nav-overlay" id="nav-overlay" aria-label="Close navigation"></button>`;
  el("menu-toggle").addEventListener("click", () =>
    toggleNavigation(!el("sidebar").classList.contains("open")),
  );
  el("nav-overlay").addEventListener("click", () => toggleNavigation(false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") toggleNavigation(false);
  });
  el("logout-button").addEventListener("click", logout);
  mobileNavigation.addEventListener("change", () => toggleNavigation(false));
  toggleNavigation(false);
  applyIdentity();
}

function toggleNavigation(open) {
  const sidebar = el("sidebar");
  if (!sidebar) return;
  const expanded = open && mobileNavigation.matches;
  if (!expanded && sidebar.contains(document.activeElement))
    el("menu-toggle")?.focus();
  sidebar.classList.toggle("open", expanded);
  sidebar.inert = mobileNavigation.matches && !expanded;
  sidebar.setAttribute("aria-hidden", String(sidebar.inert));
  el("menu-toggle")?.setAttribute("aria-expanded", String(expanded));
  el("menu-toggle")?.setAttribute(
    "aria-label",
    expanded ? "Close navigation" : "Open navigation",
  );
  if (expanded) sidebar.querySelector(".nav-item.active")?.focus();
  if (!expanded && document.activeElement === el("nav-overlay"))
    el("menu-toggle")?.focus();
}

function applyIdentity() {
  if (!state.user) return;
  if (el("current-username"))
    el("current-username").textContent = state.user.username;
  if (el("current-role"))
    el("current-role").textContent =
      ROLE_NAMES[state.user.role] || "Unknown role";
  if (el("user-avatar"))
    el("user-avatar").textContent = state.user.username
      .slice(0, 2)
      .toUpperCase();
  document.querySelectorAll('[data-role="scan"]').forEach((node) => {
    node.hidden = !canScan();
  });
  document.querySelectorAll('[data-role="admin"]').forEach((node) => {
    node.hidden = !isSuperUser();
  });
  if (el("viewer-notice")) el("viewer-notice").hidden = canScan();
  if (PAGE === "users" && !isSuperUser()) location.replace("/dashboard/");
}

async function refreshIdentity() {
  if (state.authRefresh) return state.authRefresh;
  state.authRefresh = (async () => {
    const data = await fetchJson(`${API.auth}/me`, {
      refreshOnForbidden: false,
    });
    if (!data.user || !ROLE_NAMES[data.user.role] || !data.csrf_token)
      throw new ApiError(
        "The service returned an invalid session. Please log in again.",
      );
    state.user = data.user;
    state.csrf = data.csrf_token;
    applyIdentity();
    return data;
  })();
  try {
    return await state.authRefresh;
  } finally {
    state.authRefresh = null;
  }
}

async function updateHealth() {
  try {
    const data = await fetchJson("/health", {
      allowUnauthorized: true,
      refreshOnForbidden: false,
    });
    const healthy = ["healthy", "ok"].includes(data?.status);
    if (el("health-status"))
      el("health-status").textContent = healthy
        ? "Service available"
        : "Service unavailable";
    if (el("health-dot"))
      el("health-dot").className =
        `health-dot ${healthy ? "online" : "offline"}`;
  } catch {
    if (el("health-status"))
      el("health-status").textContent = "Service unavailable";
    if (el("health-dot")) el("health-dot").className = "health-dot offline";
  }
}

async function startProtectedPage() {
  try {
    await refreshIdentity();
    if (PAGE === "users" && !isSuperUser()) return;
    renderShell();
    el("auth-check").hidden = true;
    el("protected-app").hidden = false;
    void updateHealth();
    if (PAGE === "dashboard") await loadDashboard();
    if (PAGE === "scan") {
      el("add-repository-form").addEventListener("submit", addRepository);
      el("scan-form").addEventListener("submit", (event) => {
        event.preventDefault();
        void runScan(el("repository-select").value);
      });
      el("repository-select").addEventListener("change", syncScanButtons);
      await loadRepositorySelect();
    }
    if (PAGE === "history") await loadHistory();
    if (PAGE === "policy") await loadPolicy();
    if (PAGE === "users") {
      el("create-user-form").addEventListener("submit", createUser);
      await loadUsers();
    }
  } catch (error) {
    if (state.redirecting) return;
    el("auth-check").innerHTML = errorBox(error, "retry-auth");
  }
}

async function initLogin() {
  el("login-button").disabled = true;
  void updateHealth();
  el("login-form").addEventListener("submit", login);
  try {
    const data = await fetchJson(`${API.auth}/me`, { allowUnauthorized: true });
    if (data.user && ROLE_NAMES[data.user.role]) {
      state.user = data.user;
      location.replace(loginDestination());
      return;
    }
  } catch (error) {
    if (error.status !== 401)
      setMessage("login-message", error.message, "error");
  }
  try {
    const data = await fetchJson(`${API.auth}/csrf`, {
      allowUnauthorized: true,
    });
    if (!data.csrf_token)
      throw new ApiError("Could not initialize the login session. Try again.");
    state.csrf = data.csrf_token;
  } catch (error) {
    setMessage("login-message", error.message, "error");
  } finally {
    el("login-button").disabled = false;
  }
}

async function login(event) {
  event.preventDefault();
  const button = el("login-button");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "Logging in...";
  setMessage("login-message", "");
  try {
    if (!state.csrf) {
      const session = await fetchJson(`${API.auth}/csrf`, {
        allowUnauthorized: true,
      });
      state.csrf = session.csrf_token;
      if (!state.csrf)
        throw new ApiError(
          "Could not initialize the login session. Try again.",
        );
    }
    const data = await fetchJson(`${API.auth}/login`, {
      method: "POST",
      body: JSON.stringify({
        username: el("username").value.trim(),
        password: el("password").value,
      }),
      allowUnauthorized: true,
    });
    if (!data.user || !ROLE_NAMES[data.user.role])
      throw new ApiError(
        "The service returned an invalid login response. Try again.",
      );
    state.user = data.user;
    state.csrf = data.csrf_token;
    el("password").value = "";
    location.replace(loginDestination());
  } catch (error) {
    setMessage("login-message", error.message, "error");
    el("password").value = "";
    el("password").focus();
    try {
      state.csrf =
        (await fetchJson(`${API.auth}/csrf`, { allowUnauthorized: true }))
          .csrf_token || null;
    } catch {
      state.csrf = null;
    }
  } finally {
    button.disabled = false;
    button.textContent = "Log in";
  }
}

async function logout() {
  const button = el("logout-button");
  if (button.disabled) return;
  button.disabled = true;
  try {
    await fetchJson(`${API.auth}/logout`, { method: "POST" });
    state.user = null;
    state.csrf = null;
    location.replace("/dashboard/login.html");
  } catch (error) {
    setMessage("global-message", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function loadDashboard() {
  await Promise.all([loadDashboardRepositories(), loadLatestFindings()]);
}

function repositoryCard(repo) {
  const score = repo.score == null ? "-" : `${repo.score}/100`;
  const count = repo.last_scan ? String(repo.findings ?? 0) : "-";
  return `<article class="repository-card"><div class="repository-header"><div><h3>${escapeHtml(repo.name)}</h3>${safeRepositoryLink(repo.url)}</div>${statusBadge(repo.status)}</div><div class="repository-stats"><div><span>Score</span><strong>${escapeHtml(score)}</strong></div><div><span>Grade</span><strong>${escapeHtml(repo.grade || "-")}</strong></div><div><span>Findings</span><strong>${escapeHtml(count)}</strong></div></div><p class="repository-reason">${escapeHtml(repo.reason || "Run a scan to assess this repository.")}</p><div class="repository-footer"><span>${repo.last_scan ? "Last scan: " : ""}${escapeHtml(formatDate(repo.last_scan))}</span><div class="actions"><a class="small-button" href="history.html?repository=${encodeURIComponent(repo.id)}">History</a><button type="button" class="small-button" data-action="scan-repository" data-id="${escapeHtml(repo.id)}" data-role="scan" data-scan-button>Scan</button><button type="button" class="danger-button" data-action="delete-repository" data-id="${escapeHtml(repo.id)}" data-name="${escapeHtml(repo.name)}" data-role="admin">Delete</button></div></div></article>`;
}

async function loadDashboardRepositories() {
  const container = el("repositories-container");
  container.innerHTML = '<div class="loading">Loading repositories...</div>';
  try {
    const repositories = requireArray(
      await fetchJson(API.repositories),
      "repositories",
    );
    el("total-repositories").textContent = repositories.length;
    el("passed-repositories").textContent = repositories.filter(
      (repo) => repo.status === "ALLOW",
    ).length;
    el("blocked-repositories").textContent = repositories.filter(
      (repo) => repo.status === "BLOCK",
    ).length;
    el("total-findings").textContent = repositories.reduce(
      (total, repo) => total + (Number(repo.findings) || 0),
      0,
    );
    container.innerHTML = repositories.length
      ? repositories.map(repositoryCard).join("")
      : emptyState(
          "No repositories yet",
          canScan()
            ? "Open Security Scan to connect an authorized GitHub repository."
            : "An Operator or Super User can connect a repository.",
        );
    document.querySelectorAll('[data-action="scan-all"]').forEach((button) => {
      button.dataset.empty = String(repositories.length === 0);
    });
    applyIdentity();
    syncScanButtons();
  } catch (error) {
    [
      "total-repositories",
      "passed-repositories",
      "blocked-repositories",
      "total-findings",
    ].forEach((id) => {
      el(id).textContent = "-";
    });
    container.innerHTML = errorBox(error, "reload-dashboard");
  }
}

function latestFindingGroup(scan, findings, error = null) {
  return `<section class="finding-group" id="latest-scan-${escapeHtml(scan.id)}"><h3>${escapeHtml(scan.repository_name || "Repository")}<a class="text-link" href="history.html?scan=${encodeURIComponent(scan.id)}">Scan details</a></h3>${
    error
      ? errorBox(error, "retry-latest-findings", scan.id)
      : findings.length
        ? findings
            .slice(0, 3)
            .map((item) => findingRow(item))
            .join("") +
          (findings.length > 3
            ? `<p class="muted">${escapeHtml(findings.length - 3)} more findings in scan history.</p>`
            : "")
        : '<p class="no-findings">No findings in this recorded scan.</p>'
  }</section>`;
}

async function loadLatestFindings() {
  const container = el("latest-findings");
  const generation = ++state.latestGeneration;
  container.innerHTML = '<div class="loading">Loading latest findings...</div>';
  try {
    const scans = requireArray(await fetchJson(API.scans), "scans").slice(0, 5);
    state.latestScans = new Map(scans.map((scan) => [String(scan.id), scan]));
    if (!scans.length) {
      if (generation === state.latestGeneration)
        container.innerHTML = emptyState(
          "No recorded scans",
          "Findings will appear after a repository has been scanned.",
        );
      return;
    }
    const results = await Promise.allSettled(
      scans.map((scan) =>
        fetchJson(`${API.scans}/${encodeURIComponent(scan.id)}/findings`).then(
          (data) => requireArray(data, "findings"),
        ),
      ),
    );
    if (generation !== state.latestGeneration) return;
    container.innerHTML = results
      .map((result, index) =>
        result.status === "fulfilled"
          ? latestFindingGroup(scans[index], result.value)
          : latestFindingGroup(scans[index], [], result.reason),
      )
      .join("");
  } catch (error) {
    if (generation === state.latestGeneration)
      container.innerHTML = errorBox(error, "reload-findings");
  }
}

async function retryLatestFindings(id) {
  const scan = state.latestScans.get(String(id));
  const container = el(`latest-scan-${id}`);
  if (!scan || !container) return;
  container.innerHTML = '<div class="loading">Loading scan findings...</div>';
  try {
    const findings = requireArray(
      await fetchJson(`${API.scans}/${encodeURIComponent(id)}/findings`),
      "findings",
    );
    container.outerHTML = latestFindingGroup(scan, findings);
  } catch (error) {
    container.outerHTML = latestFindingGroup(scan, [], error);
  }
}

async function loadRepositorySelect() {
  const select = el("repository-select");
  const previousSelection = select.value;
  select.disabled = true;
  select.replaceChildren(new Option("Loading repositories...", ""));
  try {
    const repositories = requireArray(
      await fetchJson(API.repositories),
      "repositories",
    );
    select.replaceChildren(
      new Option(
        repositories.length
          ? "Select a repository"
          : "No repositories available",
        "",
      ),
    );
    repositories.forEach((repo) =>
      select.add(new Option(repo.name, String(repo.id))),
    );
    if (repositories.some((repo) => String(repo.id) === previousSelection))
      select.value = previousSelection;
    select.disabled = repositories.length === 0;
    el("scan-all-button").dataset.empty = String(repositories.length === 0);
    if (!repositories.length)
      setMessage(
        "scan-message",
        "No repositories are connected yet. Add an authorized repository to start scanning.",
        "info",
      );
  } catch (error) {
    select.replaceChildren(new Option("Repositories unavailable", ""));
    el("scan-message").innerHTML = errorBox(error, "reload-repository-select");
    el("scan-all-button").dataset.empty = "true";
  } finally {
    syncScanButtons();
  }
}

async function addRepository(event) {
  event.preventDefault();
  if (!canScan()) return;
  const button = el("add-repository-button");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "Adding...";
  try {
    const data = await fetchJson(API.repositories, {
      method: "POST",
      body: JSON.stringify({ repo_url: el("repo-url").value.trim() }),
    });
    setMessage(
      "add-message",
      `Repository "${data.repository?.name || ""}" added.`,
      "success",
    );
    el("repo-url").value = "";
    await loadRepositorySelect();
  } catch (error) {
    setMessage("add-message", error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "Add repository";
  }
}

function syncScanButtons() {
  document.querySelectorAll("[data-scan-button]").forEach((button) => {
    const noSelection =
      button.id === "scan-button" && !el("repository-select")?.value;
    button.disabled =
      state.scanBusy ||
      button.dataset.empty === "true" ||
      noSelection ||
      !canScan();
    button.setAttribute("aria-busy", String(state.scanBusy));
  });
}

function renderScanResult(scan, name = "") {
  const repositoryName = scan.repository?.name || name || "Repository";
  const findings = Array.isArray(scan.findings_data)
    ? scan.findings_data
    : null;
  const stats = [
    ["Security score", scan.score == null ? "-" : `${scan.score}/100`],
    ["Grade", scan.grade || "-"],
    ["Findings", scan.findings ?? "-"],
  ];
  return `<article class="result-detail"><div class="result-heading"><div><h3>${escapeHtml(repositoryName)}</h3><p>Execution completed / Policy decision below</p></div>${statusBadge(scan.status)}</div><p class="result-reason"><strong>Decision reason:</strong> ${escapeHtml(scan.reason || "No reason returned by the service.")}</p><div class="result-stats">${stats.map(([label, value]) => `<div class="result-stat"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}</div><div class="scanner-grid">${["Bandit", "Trivy", "Gitleaks"].map((name) => `<div class="scanner-card"><span>${name} findings</span><strong>${escapeHtml(scan.scanner_counts?.[name] ?? "-")}</strong></div>`).join("")}</div><div class="severity-grid">${["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((level) => `<div><span>${level}</span><strong>${escapeHtml(scan.severity_counts?.[level] ?? "-")}</strong></div>`).join("")}</div><h3>Findings</h3>${findings === null ? errorBox(new Error("Findings details were not included in the scan response. Open scan history to load the recorded findings.")) : findings.length ? findings.map((finding) => findingRow(finding)).join("") : '<p class="no-findings">No findings reported by this scan.</p>'}</article>`;
}

function renderBulkResults(data) {
  const results = requireArray(data, "results");
  return `<h2>Scan all results</h2><div class="bulk-summary"><span><strong>${escapeHtml(data.total ?? "-")}</strong>Repositories</span><span><strong>${escapeHtml(data.successful ?? "-")}</strong>Execution completed</span><span><strong>${escapeHtml(data.failed ?? "-")}</strong>Execution failed</span></div>${data.total === 0 ? emptyState("No repositories to scan", "Connect a repository before running Scan all.") : results.map((result) => (result.status === "success" && result.scan ? renderScanResult(result.scan, result.repository_name) : `<article class="bulk-failure"><h3>${escapeHtml(result.repository_name || "Repository")} / Execution failed</h3><p>${escapeHtml(result.error || "The service did not return a scan result.")}</p></article>`)).join("")}`;
}

async function runScan(repositoryId = "all") {
  if (!canScan() || state.scanBusy) return;
  const messageId = PAGE === "dashboard" ? "dashboard-message" : "scan-message";
  if (!repositoryId) {
    setMessage(messageId, "Select a repository first.", "error");
    return;
  }
  const all = repositoryId === "all";
  state.scanBusy = true;
  syncScanButtons();
  setMessage(
    messageId,
    all
      ? "Scanning all repositories. This may take a few minutes..."
      : "Security scan is running. This may take a few minutes...",
    "info",
  );
  const container = el("scan-results");
  container.hidden = false;
  container.innerHTML =
    '<div class="loading">Running the security scanners...</div>';
  try {
    const data = await fetchJson(
      all
        ? API.scanAll
        : `${API.repositories}/${encodeURIComponent(repositoryId)}/scan`,
      { method: "POST" },
    );
    if (all) {
      container.innerHTML = renderBulkResults(data);
      setMessage(
        messageId,
        data.total === 0
          ? "No repositories were available to scan."
          : `${data.successful}/${data.total} executions completed; ${data.failed} failed. Each completed scan has a separate policy decision.`,
        Number(data.failed) ? "warning" : "success",
      );
    } else {
      container.innerHTML =
        "<h2>Security scan result</h2>" + renderScanResult(data);
      setMessage(
        messageId,
        `Scan execution completed. Security gate: ${data.status || "UNKNOWN"}. ${data.reason || ""}`,
        data.status === "BLOCK" ? "warning" : "success",
      );
    }
    if (PAGE === "dashboard") await loadDashboard();
    if (PAGE === "scan") await loadRepositorySelect();
  } catch (error) {
    setMessage(messageId, error.message, "error");
    container.innerHTML = errorBox(
      error,
      all ? "scan-all" : "scan-repository",
      all ? "" : repositoryId,
    );
  } finally {
    state.scanBusy = false;
    syncScanButtons();
  }
}

async function deleteRepository(id, name, button) {
  if (!isSuperUser() || button.disabled) return;
  if (
    !window.confirm(
      `Delete "${name}" and its stored scan history? This cannot be undone.`,
    )
  )
    return;
  button.disabled = true;
  try {
    await fetchJson(`${API.repositories}/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    setMessage("dashboard-message", `Repository "${name}" deleted.`, "success");
    await loadDashboard();
  } catch (error) {
    setMessage("dashboard-message", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function loadHistory() {
  const container = el("history-container");
  container.innerHTML = '<div class="loading">Loading scan history...</div>';
  try {
    const scans = requireArray(await fetchJson(API.scans), "scans");
    state.scans = new Map(scans.map((scan) => [String(scan.id), scan]));
    const repositoryId = new URLSearchParams(location.search).get("repository");
    const displayed = repositoryId
      ? scans.filter((scan) => String(scan.repository_id) === repositoryId)
      : scans;
    if (!displayed.length) {
      container.innerHTML = emptyState(
        "No recorded scans",
        repositoryId
          ? "There are no recorded scans for this repository."
          : "Run a repository scan to create a history entry.",
      );
      return;
    }
    container.innerHTML = `${repositoryId ? '<p class="muted">Showing this repository only. <a href="history.html">View all scans</a></p>' : ""}<div class="table-wrapper"><table class="history-table"><caption class="hidden">Recorded repository security scans</caption><thead><tr><th scope="col">Repository</th><th scope="col">Score</th><th scope="col">Grade</th><th scope="col">Gate</th><th scope="col">Reason</th><th scope="col">Findings</th><th scope="col">Scanned</th><th scope="col">Details</th></tr></thead><tbody>${displayed.map((scan) => `<tr><td><strong>${escapeHtml(scan.repository_name || "Repository")}</strong></td><td>${escapeHtml(scan.score)}/100</td><td>${escapeHtml(scan.grade)}</td><td>${statusBadge(scan.status)}</td><td><span class="reason-cell">${escapeHtml(scan.reason || "-")}</span></td><td>${escapeHtml(scan.findings)}</td><td>${escapeHtml(formatDate(scan.scanned_at))}</td><td><button type="button" class="small-button" data-action="show-findings" data-id="${escapeHtml(scan.id)}" aria-label="View findings for ${escapeHtml(scan.repository_name || "repository")} scan">View</button></td></tr>`).join("")}</tbody></table></div>`;
    const scanId = new URLSearchParams(location.search).get("scan");
    if (scanId && state.scans.has(scanId)) await showHistoryFindings(scanId);
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-history");
  }
}

async function showHistoryFindings(id) {
  const container = el("history-detail");
  const generation = ++state.historyGeneration;
  const scan = state.scans.get(String(id));
  if (!scan) return;
  container.hidden = false;
  container.innerHTML = '<div class="loading">Loading scan findings...</div>';
  container.focus({ preventScroll: true });
  container.scrollIntoView({ behavior: "smooth", block: "start" });
  try {
    const findings = requireArray(
      await fetchJson(`${API.scans}/${encodeURIComponent(id)}/findings`),
      "findings",
    );
    if (generation !== state.historyGeneration) return;
    container.innerHTML = `<div class="section-header"><div><h2>${escapeHtml(scan.repository_name || "Repository")} / Scan #${escapeHtml(id)}</h2><p>${escapeHtml(formatDate(scan.scanned_at))}</p></div>${statusBadge(scan.status)}</div><p class="result-reason"><strong>Decision reason:</strong> ${escapeHtml(scan.reason || "-")}</p>${findings.length ? findings.map((finding) => findingRow(finding)).join("") : emptyState("No findings in this recorded scan", "The policy decision and reason are shown above.")}`;
  } catch (error) {
    if (generation === state.historyGeneration)
      container.innerHTML = `<h2>Findings could not be loaded</h2>${errorBox(error, "show-findings", id)}`;
  }
}

async function loadPolicy() {
  const container = el("policy-container");
  container.innerHTML =
    '<div class="loading">Loading the configured security policy...</div>';
  try {
    const data = await fetchJson("/api/policy");
    const minimum = data.policy?.minimum_score;
    const rules = data.severity;
    const penalties = data.severity_penalties;
    const bands = requireArray(data, "grade_bands");
    if (
      typeof minimum !== "number" ||
      !Number.isFinite(minimum) ||
      !rules ||
      !penalties ||
      !bands.length
    )
      throw new ApiError(
        "The service returned an invalid policy response. Try again.",
      );
    const blockLevels = Object.entries(rules)
      .filter(([, action]) => String(action).toUpperCase() === "BLOCK")
      .map(([level]) => level.toUpperCase());
    const levels = [
      ...new Set([
        ...Object.keys(penalties),
        ...Object.keys(rules).map((level) => level.toUpperCase()),
      ]),
    ];
    const gradeScale = bands
      .map((band, index) => {
        const upper = index === 0 ? 100 : bands[index - 1].minimum_score - 1;
        return `<span><b>${escapeHtml(band.grade)}</b>${escapeHtml(band.minimum_score)}-${escapeHtml(upper)}</span>`;
      })
      .join("");
    container.innerHTML = `<section class="content-section"><div class="section-header"><div><h2>Security gate rules</h2><p>Loaded from the active policy configuration.</p></div><div class="actions"><span class="status-badge unknown">Read only</span><button type="button" class="secondary-button" data-action="reload-policy">Refresh</button></div></div><div class="policy-summary"><div class="policy-number"><span>Minimum score</span><strong>${escapeHtml(minimum)}<span> / 100</span></strong></div><p>${blockLevels.length ? `Any ${escapeHtml(blockLevels.join(" or "))} finding blocks the repository. ` : "No severity automatically blocks under the configured policy. "}The security gate also blocks when the total score falls below ${escapeHtml(minimum)}.</p></div><div class="policy-grid">${levels
      .map((level) => {
        const action = rules[level.toLowerCase()] || rules[level];
        const blocks = String(action || "").toUpperCase() === "BLOCK";
        const severityClass = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(
          level,
        )
          ? level.toLowerCase()
          : "unknown";
        return `<article class="policy-card ${severityClass}"><span class="severity-badge ${severityClass}">${escapeHtml(level)}</span><h3>${blocks ? "Always blocks" : "Affects the score"}</h3><p>Deducts ${escapeHtml(penalties[level] ?? 0)} points per finding. ${blocks ? "Blocks the security gate regardless of score." : `The gate can block when the total score falls below ${escapeHtml(minimum)}.`}</p><p class="policy-action">Configured action: ${escapeHtml(action || "No severity action")}</p></article>`;
      })
      .join(
        "",
      )}</div></section><section class="two-column"><div class="content-section"><div class="section-header"><div><h2>How scoring works</h2><p>Every scan starts at 100 points; the minimum possible score is zero.</p></div></div><div class="score-formula">100 - severity penalties = security score</div><p class="muted">A grade describes the score. ALLOW or BLOCK describes the security policy decision.</p><div class="grade-scale">${gradeScale}</div></div><div class="content-section"><div class="section-header"><div><h2>From scan to decision</h2><p>The same process applies to every repository.</p></div></div><ol class="process-list"><li>Clone the authorized repository</li><li>Run Bandit, Trivy, and Gitleaks</li><li>Normalize findings and calculate a score</li><li>Apply severity rules and the minimum score</li><li>Store ALLOW or BLOCK with the reason</li></ol><div class="message info">A scanner failure is an execution error. It is not a clean result or an ALLOW decision.</div></div></section>`;
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-policy");
  }
}

async function loadUsers() {
  if (!isSuperUser()) return;
  await Promise.all([loadUserList(), loadAudit()]);
}

async function loadUserList() {
  const container = el("users-container");
  container.innerHTML = '<div class="loading">Loading users...</div>';
  try {
    const users = requireArray(await fetchJson(API.users), "users");
    state.users = new Map(users.map((user) => [String(user.id), user]));
    container.innerHTML = users.length
      ? `<div class="table-wrapper"><table class="user-table"><thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Access controls</th></tr></thead><tbody>${users
          .map(
            (user) =>
              `<tr><td><strong>${escapeHtml(user.username)}</strong>${user.id === state.user.id ? '<span class="you-label">You</span>' : ""}</td><td>${escapeHtml(ROLE_NAMES[user.role] || user.role)}</td><td><span class="status-badge ${user.is_active ? "allow" : "unknown"}">${user.is_active ? "Active" : "Disabled"}</span></td><td>${escapeHtml(formatDate(user.created_at))}</td><td><div class="user-access-controls"><select id="user-role-${escapeHtml(user.id)}" aria-label="Role for ${escapeHtml(user.username)}">${Object.entries(
                ROLE_NAMES,
              )
                .map(
                  ([role, label]) =>
                    `<option value="${role}" ${role === user.role ? "selected" : ""}>${label}</option>`,
                )
                .join(
                  "",
                )}</select><button type="button" class="small-button" data-action="save-user-role" data-id="${escapeHtml(user.id)}" aria-label="Save role for ${escapeHtml(user.username)}">Save role</button><button type="button" class="${user.is_active ? "danger-button" : "small-button"}" data-action="toggle-user" data-id="${escapeHtml(user.id)}" aria-label="${user.is_active ? "Disable" : "Enable"} ${escapeHtml(user.username)}">${user.is_active ? "Disable" : "Enable"}</button></div></td></tr>`,
          )
          .join("")}</tbody></table></div>`
      : emptyState(
          "No users available",
          "Create a user to grant access to this workspace.",
        );
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-users");
  }
}

function auditChanges(event) {
  const labels = [];
  if (event.before?.role !== event.after?.role && event.after?.role)
    labels.push(
      `Role: ${event.before?.role ? (ROLE_NAMES[event.before.role] || event.before.role) + " -> " : ""}${ROLE_NAMES[event.after.role] || event.after.role}`,
    );
  if (
    typeof event.after?.is_active === "boolean" &&
    event.before?.is_active !== event.after.is_active
  )
    labels.push(event.after.is_active ? "Account enabled" : "Account disabled");
  return labels.join(" / ") || "Account created";
}

async function loadAudit() {
  const container = el("audit-container");
  container.innerHTML = '<div class="loading">Loading activity...</div>';
  try {
    const events = requireArray(
      await fetchJson(`${API.users}/audit`),
      "events",
    );
    container.innerHTML = events.length
      ? `<div class="table-wrapper"><table class="audit-table"><thead><tr><th scope="col">Time</th><th scope="col">Performed by</th><th scope="col">Account</th><th scope="col">Action</th><th scope="col">Change</th></tr></thead><tbody>${events.map((event) => `<tr><td>${escapeHtml(formatDate(event.created_at))}</td><td>${escapeHtml(event.actor_username || "Bootstrap CLI")}</td><td>${escapeHtml(event.target_username || event.after?.username || "-")}</td><td>${escapeHtml(event.action || "-")}</td><td>${escapeHtml(auditChanges(event))}</td></tr>`).join("")}</tbody></table></div>`
      : emptyState(
          "No administrative activity",
          "Account and permission changes will appear here.",
        );
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-audit");
  }
}

async function createUser(event) {
  event.preventDefault();
  if (!isSuperUser()) return;
  const button = el("create-user-button");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "Creating...";
  try {
    const data = await fetchJson(API.users, {
      method: "POST",
      body: JSON.stringify({
        username: el("new-username").value.trim(),
        password: el("new-password").value,
        role: el("new-role").value,
      }),
    });
    el("create-user-form").reset();
    setMessage(
      "user-message",
      `Account "${data.user?.username || ""}" created.`,
      "success",
    );
    await loadUsers();
  } catch (error) {
    setMessage("user-message", error.message, "error");
  } finally {
    el("new-password").value = "";
    button.disabled = false;
    button.textContent = "Create user";
  }
}

async function updateUser(id, toggleActive, button) {
  if (!isSuperUser() || button.disabled) return;
  const user = state.users.get(String(id));
  if (!user) return;
  const role = el(`user-role-${id}`)?.value;
  if (!toggleActive && role === user.role) {
    setMessage("user-message", "This user already has that role.", "info");
    return;
  }
  if (
    toggleActive &&
    user.is_active &&
    !window.confirm(
      `Disable "${user.username}"? Their active sessions will lose access.`,
    )
  )
    return;
  if (
    !toggleActive &&
    !window.confirm(
      `Change "${user.username}" to ${ROLE_NAMES[role]}? Their current sessions will be updated or revoked.`,
    )
  )
    return;
  button.disabled = true;
  try {
    await fetchJson(`${API.users}/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(
        toggleActive ? { is_active: !Boolean(user.is_active) } : { role },
      ),
    });
    setMessage(
      "user-message",
      `Access updated for "${user.username}".`,
      "success",
    );
    if (user.id === state.user.id) await refreshIdentity();
    if (isSuperUser()) await loadUsers();
  } catch (error) {
    setMessage("user-message", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function dispatchAction(button) {
  if (button.disabled) return;
  const id = button.dataset.id;
  switch (button.dataset.action) {
    case "retry-auth":
      return startProtectedPage();
    case "reload-dashboard":
      return loadDashboard();
    case "reload-findings":
      return loadLatestFindings();
    case "retry-latest-findings":
      return retryLatestFindings(id);
    case "reload-repository-select":
      return loadRepositorySelect();
    case "scan-all":
      return runScan("all");
    case "scan-repository":
      return runScan(id);
    case "delete-repository":
      return deleteRepository(id, button.dataset.name, button);
    case "reload-history":
      return loadHistory();
    case "reload-policy":
      return loadPolicy();
    case "show-findings":
      return showHistoryFindings(id);
    case "reload-users":
      return loadUsers();
    case "reload-audit":
      return loadAudit();
    case "save-user-role":
      return updateUser(id, false, button);
    case "toggle-user":
      return updateUser(id, true, button);
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (button)
    void dispatchAction(button).catch((error) =>
      setMessage("global-message", error.message, "error"),
    );
});

document.addEventListener("DOMContentLoaded", () => {
  if (PAGE === "login") void initLogin();
  else void startProtectedPage();
});

// Permissions reload on return to the tab. Every request is also authorized by the server.
window.addEventListener("focus", () => {
  if (PAGE !== "login" && state.user)
    void refreshIdentity().catch((error) => {
      if (!state.redirecting)
        setMessage("global-message", error.message, "error");
    });
  void updateHealth();
});
window.setInterval(() => {
  if (document.visibilityState === "visible" && PAGE !== "login" && state.user)
    void refreshIdentity().catch(() => {});
}, 60000);
