// Shared state, API, authentication, navigation, sync, and application lifecycle.
// Loaded with defer; common.js provides the single shared state.

"use strict";

// Match template interpolation coercion; escaping stays at the original call sites.
function templateText(value) {
  return `${value}`;
}

// Configuration and the single shared application state.
const API = {
  repositories: "/api/repositories",
  scans: "/api/scans",
  scanAll: "/api/github/sync",
  auth: "/api/auth",
  users: "/api/users",
};
const state = {
  githubConfigured: false,
  collapsedRepositories: new Map(),
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
  historyLoading: false,
  historyListScope: null,
  scopedScans: [],
  historyFilters: {
    search: "",
    repository: "",
    gate: "",
  },
  selectedDetail: null,
  detailFilters: {
    scanner: "",
    sort: "severity",
  },
  findingDisclosure: new Map(),
  dashboardLoading: false,
  autoRefreshBusy: false,
  repositorySelectLoading: false,
  monitoringRepositories: new Map(),
  renderedContent: new WeakMap(),
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
// API requests, error handling, CSRF, and safe display helpers.
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
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char],
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

function updateMarkup(node, html) {
  const cached = state.renderedContent.get(node);
  if (cached?.source === html && cached.dom === node.innerHTML) return;
  node.innerHTML = html;
  state.renderedContent.set(node, {
    source: html,
    dom: node.innerHTML,
  });
}

function emptyState(title, text) {
  return `<div class="empty-state"><h3>${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p></div>`;
}

function errorBox(error, action, id = "") {
  return [
    '<div class="error-box" role="alert">',
    "<p>",
    templateText(escapeHtml(error.message || error)),
    "</p>",
    templateText(
      action
        ? `<button type="button" class="small-button" data-action="${escapeHtml(action)}" data-id="${escapeHtml(id)}">Retry</button>`
        : "",
    ),
    "</div>",
  ].join("");
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

function findingRow(finding, repositoryName = "", github = null) {
  const severity = String(finding.severity || "UNKNOWN").toUpperCase();
  const className = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity)
    ? severity.toLowerCase()
    : "unknown";
  const location = `${finding.file || "No file information"}${finding.line != null ? `:${finding.line}` : ""}`;
  const relativeFile = reportFilePath(finding.file);
  const validLine = Number.isInteger(finding.line) && finding.line > 0;
  const codeLink =
    github?.full_name &&
    /^[a-f0-9]{40}$/.test(github.commit_sha || "") &&
    relativeFile &&
    !relativeFile.startsWith("/") &&
    !relativeFile.includes(":") &&
    !relativeFile.split("/").some((part) => part === ".." || part === ".")
      ? safeRepositoryLink(
          [
            "https://github.com/",
            templateText(github.full_name),
            "/blob/",
            templateText(github.commit_sha),
            "/",
            templateText(
              relativeFile.split("/").map(encodeURIComponent).join("/"),
            ),
            templateText(validLine ? "#L" + finding.line : ""),
          ].join(""),
          "Open file on GitHub",
        )
      : "";
  const fileDetails = [
    '<dl class="finding-location">',
    "<div>",
    "<dt>Affected file",
    "</dt>",
    "<dd>",
    "<code>",
    templateText(escapeHtml(relativeFile || "Not available")),
    "</code>",
    "</dd>",
    "</div>",
    "<div>",
    "<dt>Line",
    "</dt>",
    "<dd>",
    templateText(validLine ? escapeHtml(finding.line) : "Not available"),
    "</dd>",
    "</div>",
    "</dl>",
  ].join("");
  const meta = [repositoryName, finding.scanner || "Unknown scanner", location]
    .filter(Boolean)
    .join(" / ");
  return [
    '<article class="finding-row">',
    "<div>",
    "<strong>",
    templateText(
      escapeHtml(finding.rule_id || finding.message || "Security finding"),
    ),
    "</strong>",
    '<span class="finding-meta">',
    templateText(escapeHtml(meta)),
    "</span>",
    templateText(
      finding.message ? `<p>${escapeHtml(finding.message)}</p>` : "",
    ),
    templateText(
      finding.cwe
        ? `<span class="finding-meta">${escapeHtml(finding.cwe)}</span>`
        : "",
    ),
    templateText(fileDetails),
    templateText(codeLink),
    "</div>",
    '<span class="severity-badge ',
    templateText(className),
    '">',
    templateText(escapeHtml(severity)),
    "</span>",
    "</article>",
  ].join("");
}

function reportFilePath(value) {
  const path = String(value || "").replaceAll("\\", "/");
  // Strip only known checkout prefixes; keep unknown absolute paths visible.
  return path
    .replace(/^\/(?:home\/runner\/work|__w)\/([^/]+)\/\1\/target\//, "")
    .replace(/^[A-Za-z]:\/a\/([^/]+)\/\1\/target\//, "")
    .replace(/^\.\//, "")
    .replace(/^target\//, "");
}

function safeRepositoryLink(url, label = url) {
  try {
    const parsed = new URL(url);
    if (
      parsed.protocol === "https:" &&
      parsed.hostname === "github.com" &&
      !parsed.username &&
      !parsed.password
    )
      return `<a class="repository-url" href="${escapeHtml(parsed.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
  } catch {}
  return `<span class="repository-url">${escapeHtml(url)}</span>`;
}

// Session handling, navigation, and role-aware page access.
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
    ["scan", "scan.html", "Repository Monitoring"],
    ["history", "history.html", "Scan History"],
    ["policy", "policy.html", "Security Policy"],
    ["users", "users.html", "User Management"],
  ];
  el("navigation-shell").innerHTML = [
    '<aside class="sidebar" id="sidebar">',
    '<a class="brand" href="index.html">',
    '<span class="brand-icon" aria-hidden="true">S',
    "</span>",
    "<span>",
    "<strong>DevSecOps",
    "</strong>",
    "<small>SECURITY PLATFORM",
    "</small>",
    "</span>",
    "</a>",
    '<p class="nav-caption">WORKSPACE',
    "</p>",
    '<nav aria-label="Main navigation">',
    templateText(
      links
        .map(([page, path, label]) =>
          [
            '<a class="nav-item ',
            templateText(PAGE === page ? "active" : ""),
            '" href="',
            templateText(path),
            '" ',
            templateText(PAGE === page ? 'aria-current="page"' : ""),
            " ",
            templateText(page === "users" ? 'data-role="admin"' : ""),
            ">",
            templateText(navigationIcon(page)),
            "<span>",
            templateText(label),
            "</span>",
            "</a>",
          ].join(""),
        )
        .join(""),
    ),
    "</nav>",
    '<div class="sidebar-footer">',
    '<span class="health-dot" id="health-dot">',
    "</span>",
    '<span id="health-status">Checking service...',
    "</span>",
    "<p>Bandit / Trivy / Gitleaks",
    "</p>",
    "</div>",
    "</aside>",
    '<button type="button" class="nav-overlay" id="nav-overlay" aria-label="Close navigation">',
    "</button>",
  ].join("");
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

// Initialize only the script for the current protected page.
async function startProtectedPage() {
  try {
    await refreshIdentity();
    if (PAGE === "users" && !isSuperUser()) return;
    renderShell();
    el("auth-check").hidden = true;
    el("protected-app").hidden = false;
    void updateHealth();
    void initializeGitHubMonitor();
    if (PAGE === "dashboard") await loadDashboard();
    if (PAGE === "scan") {
      el("add-repository-form").addEventListener("submit", addRepository);
      el("scan-form").addEventListener("submit", (event) => {
        event.preventDefault();
        void runScan(el("repository-select").value);
      });
      el("repository-select").addEventListener("change", () => {
        renderMonitoringRepository();
        syncScanButtons();
      });
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

async function logout() {
  const button = el("logout-button");
  if (button.disabled) return;
  button.disabled = true;
  try {
    await fetchJson(`${API.auth}/logout`, {
      method: "POST",
    });
    state.user = null;
    state.csrf = null;
    location.replace("/dashboard/login.html");
  } catch (error) {
    setMessage("global-message", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

// Commit and branch summaries shared by Dashboard, Monitoring, and History.
function trackingDetails(info) {
  const labels = {
    not_synced: "Not synced",
    waiting: "Waiting for this commit",
    queued: "Queued",
    running: "Running",
    completed: "Completed",
    error: "Sync / scan error",
  };
  return [
    "<p>",
    "<strong>",
    templateText(escapeHtml(labels[info.execution_status] || "Unknown")),
    "</strong> / Gate: ",
    templateText(escapeHtml(info.policy_status || "Not evaluated")),
    "</p>",
    "<p>",
    templateText(escapeHtml(info.branch || "Default branch")),
    " / ",
    templateText(escapeHtml((info.commit_sha || "").slice(0, 12))),
    "</p>",
    "<p>",
    templateText(
      escapeHtml(info.commit_message || "No commit synchronized yet"),
    ),
    "</p>",
    '<p class="muted">',
    templateText(escapeHtml(info.pushed_by || info.commit_author || "")),
    " ",
    templateText(
      info.commit_time
        ? "/ Commit time: " + escapeHtml(formatDate(info.commit_time))
        : "",
    ),
    "</p>",
    templateText(info.run_url ? safeRepositoryLink(info.run_url) : ""),
    templateText(
      info.message
        ? `<p class="message warning">${escapeHtml(info.message)}</p>`
        : "",
    ),
  ].join("");
}

function uiIcon(name, extraClass = "") {
  const paths = {
    history: '<path d="M3 4v6h6M3 10a9 9 0 1 1 1 9M12 7v5l3 2"/>',
    shield: '<path d="m12 3 8 4v6c0 4-5 7-8 8-3-1-8-4-8-8V7l8-4Z"/>',
    file: '<path d="M5 3h9l5 5v13H5zM14 3v6h5M8 13h8M8 17h6"/>',
    list: '<path d="M8 5h13M8 12h13M8 19h13M3 5h.01M3 12h.01M3 19h.01"/>',
    user: '<circle cx="12" cy="7" r="4"/><path d="M4 22v-4a8 8 0 0 1 16 0v4"/>',
    calendar:
      '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 2v6M17 2v6M3 11h18"/>',
    commit: '<circle cx="12" cy="12" r="4"/><path d="M2 12h6M16 12h6"/>',
    search: '<circle cx="10" cy="10" r="7"/><path d="m15 15 6 6"/>',
    external: '<path d="M14 3h7v7M21 3l-11 11M10 3H3v18h18v-7"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
    home: '<path d="m2 10 10-8 10 8M5 8v13h14V8M9 21v-8h6v8"/>',
    database:
      '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
    branch:
      '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><path d="M6 7v10M18 7v2a7 7 0 0 1-7 7H6"/>',
    block: '<circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/>',
    error: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/>',
    allow: '<circle cx="12" cy="12" r="9"/><path d="m7 12 3 3 7-7"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    refresh:
      '<path d="M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>',
    link: '<path d="m10 13 4-4M8 16l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0M16 8l1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0"/>',
    plus: '<path d="M12 4v16M4 12h16"/>',
    arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
    settings:
      '<path d="m9 3-.5 3-2 1-3-.5-2 4 2.5 2v2L2 17l2 4 3-.5 2 1L10 24h4l1-2.5 2-1 3 .5 2-4-2.5-2.5v-2L22 10l-2-4-3 .5-2-1L14 3Z" transform="translate(1 -1) scale(.92)"/><circle cx="12" cy="12" r="3"/>',
    chart: '<path d="M3 21h18M5 17v-5h3v5M11 17V4h3v13M17 17V8h3v9"/>',
    book: '<path d="M12 5v16M3 4c4-1 6-1 9 1 3-2 5-2 9-1v15c-4-1-6-1-9 1-3-2-5-2-9-1Z"/>',
    chevron: '<path d="m8 4 8 8-8 8"/>',
    github:
      '<path fill="currentColor" stroke="none" d="M12 .8a11.2 11.2 0 0 0-3.5 21.8c.6.1.8-.2.8-.5v-2.1c-3.4.7-4.1-1.5-4.1-1.5-.6-1.4-1.4-1.8-1.4-1.8-1.1-.8.1-.8.1-.8 1.2.1 1.8 1.2 1.8 1.2 1 1.7 2.7 1.2 3.4.9.1-.7.4-1.2.7-1.5-2.7-.3-5.5-1.4-5.5-6.1 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.6.1-3.2 0 0 1-.3 3.3 1.2a11 11 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.6 1.6.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.7-2.8 5.8-5.5 6.1.4.4.8 1.1.8 2.2v3.3c0 .3.2.6.8.5A11.2 11.2 0 0 0 12 .8Z"/>',
  };
  return [
    '<svg class="ui-icon ',
    templateText(extraClass),
    '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" ',
    'stroke-linejoin="round" aria-hidden="true">',
    templateText(paths[name] || paths.clock),
    "</svg>",
  ].join("");
}

// Capture native details toggles so background refresh preserves the user's choice.
document.addEventListener(
  "toggle",
  (event) => {
    const group = event.target;
    if (group.matches?.("details[data-repository-group]") && group.isConnected)
      state.collapsedRepositories.set(
        group.dataset.repositoryGroup,
        !group.open,
      );
  },
  true,
);
function historyLink(repo, branch = null, scan = null) {
  const params = new URLSearchParams({
    repository: String(repo.id),
  });
  if (branch !== null) params.set("branch", branch);
  if (scan !== null) params.set("scan", String(scan));
  return `history.html?${escapeHtml(params.toString())}`;
}

function branchState(branch) {
  if (
    branch.execution_status === "completed" &&
    ["ALLOW", "BLOCK"].includes(branch.policy_status)
  )
    return {
      label: branch.policy_status,
      style: branch.policy_status.toLowerCase(),
    };
  if (branch.execution_status === "error")
    return {
      label: "ERROR",
      style: "error",
    };
  return {
    label:
      {
        running: "RUNNING",
        queued: "QUEUED",
        not_synced: "NOT SYNCED",
      }[branch.execution_status] || "PENDING",
    style: "pending",
  };
}

function scanGroup(repo) {
  const branches = Array.isArray(repo.tracking?.branches)
    ? repo.tracking.branches
    : [];
  return [
    '<details class="scan-group" data-repository-group="',
    templateText(escapeHtml(repo.id)),
    '" ',
    templateText(
      state.collapsedRepositories.get(String(repo.id)) ? "" : "open",
    ),
    ">",
    '<summary class="scan-group-header">',
    '<div class="repo-identity">',
    templateText(uiIcon("github", "repo-icon")),
    "<div>",
    "<h3>",
    templateText(escapeHtml(repo.name)),
    "</h3>",
    '<span class="repository-url">',
    templateText(escapeHtml(repo.url)),
    "</span>",
    "</div>",
    "</div>",
    '<span class="group-controls">',
    '<span class="status-badge unknown">',
    templateText(uiIcon("branch")),
    templateText(branches.length),
    " branches",
    "</span>",
    templateText(uiIcon("chevron", "collapse-chevron")),
    "</span>",
    "</summary>",
    templateText(
      branches.length
        ? [
            '<div class="branch-rows">',
            templateText(
              branches
                .map((branch) => {
                  const status = branchState(branch);
                  return [
                    '<div class="branch-summary ',
                    templateText(status.style),
                    '">',
                    '<div class="branch-name">',
                    templateText(uiIcon("branch")),
                    '<span class="state-dot" aria-hidden="true">',
                    "</span>",
                    "<strong>",
                    templateText(escapeHtml(branch.branch)),
                    "</strong>",
                    "</div>",
                    '<div class="branch-commit">',
                    "<strong>",
                    templateText(
                      escapeHtml(
                        branch.commit_message || "No commit synchronized yet",
                      ),
                    ),
                    "</strong>",
                    '<span class="finding-meta">',
                    templateText(
                      escapeHtml((branch.commit_sha || "").slice(0, 12)),
                    ),
                    " / ",
                    templateText(
                      escapeHtml(
                        branch.commit_time
                          ? formatDate(branch.commit_time)
                          : "Awaiting commit",
                      ),
                    ),
                    "</span>",
                    "</div>",
                    "<div>",
                    '<span class="status-badge ',
                    templateText(status.style),
                    '">',
                    templateText(
                      uiIcon(
                        ["allow", "block", "error"].includes(status.style)
                          ? status.style
                          : "clock",
                      ),
                    ),
                    templateText(status.label),
                    "</span>",
                    '<span class="finding-meta">',
                    templateText(
                      status.style === "allow" || status.style === "block"
                        ? `${escapeHtml(branch.findings ?? "-")} findings`
                        : escapeHtml(
                            branch.message || "No policy decision yet",
                          ),
                    ),
                    "</span>",
                    "</div>",
                    '<a class="small-button" href="',
                    templateText(historyLink(repo, branch.branch)),
                    '">See details ',
                    templateText(uiIcon("chevron")),
                    "</a>",
                    "</div>",
                  ].join("");
                })
                .join(""),
            ),
            "</div>",
          ].join("")
        : `<p class="muted scan-group-empty">${escapeHtml(repo.tracking?.message || "Waiting for the first branch sync. No policy decision yet.")}</p>`,
    ),
    "</details>",
  ].join("");
}

// Shared GitHub synchronization actions; no scanner is started in the browser.
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

async function runScan(repositoryId = "all") {
  if (!canScan() || state.scanBusy) return;
  const messageId = PAGE === "dashboard" ? "dashboard-message" : "scan-message";
  if (!repositoryId) return;
  const all = repositoryId === "all";
  state.scanBusy = true;
  syncScanButtons();
  setMessage(
    messageId,
    "Reading GitHub Actions results. No local scan is started.",
  );
  const container = el("scan-results");
  container.hidden = PAGE === "dashboard";
  try {
    const data = await fetchJson(
      all
        ? API.scanAll
        : `${API.repositories}/${encodeURIComponent(repositoryId)}/sync`,
      {
        method: "POST",
      },
    );
    const repositories = all ? requireArray(data, "results") : [data];
    const results = repositories.flatMap((item) =>
      Array.isArray(item.branches) && item.branches.length
        ? item.branches.map((branch) => ({
            repository_name: item.repository_name,
            ...branch,
          }))
        : [item],
    );
    if (PAGE !== "scan")
      container.innerHTML = results
        .map((item) =>
          [
            '<article class="result-detail">',
            "<h3>",
            templateText(
              escapeHtml(item.repository_name || "GitHub Actions result"),
            ),
            "</h3>",
            templateText(trackingDetails(item)),
            templateText(
              item.scan_id
                ? `<a href="history.html?scan=${encodeURIComponent(item.scan_id)}">Open findings</a>`
                : "",
            ),
            "</article>",
          ].join(""),
        )
        .join("");
    await initializeGitHubMonitor(false);
    const failed = results.filter((item) => item.execution_status === "error");
    const completed = results.filter(
      (item) => item.execution_status === "completed",
    );
    setMessage(
      messageId,
      failed.length
        ? `Could not read ${failed.length} result(s): ${failed.map((item) => item.message || "Unknown error").join("; ")}`
        : completed.length
          ? `Imported results: ${completed.map((item) => `${item.branch || "Repository"}: ${item.policy_status}`).join("; ")}. Open branch details to investigate.`
          : "No completed result for this commit yet. Check the run status below.",
      failed.length ? "warning" : "success",
    );
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

async function initializeGitHubMonitor(autoSync = true) {
  try {
    state.githubConfigured =
      (await fetchJson("/api/github/status")).configured === true;
    if (!state.githubConfigured) {
      setMessage(
        "global-message",
        "GitHub App is not configured. Add repository URLs now; private results will be available after the administrator follows the GitHub setup in README.",
      );
    } else {
      setMessage("global-message", "");
      if (autoSync && PAGE === "dashboard" && canScan()) await runScan("all");
    }
  } catch (error) {
    setMessage("global-message", error.message, "error");
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

// One delegated action listener and one page startup handler.
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
    case "close-findings":
      return closeHistoryFindings();
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
// Password visibility controls shared by Login and User Management.
function setPasswordVisible(input, button, visible) {
  input.type = visible ? "text" : "password";
  button.setAttribute("aria-pressed", String(visible));
  button.setAttribute(
    "aria-label",
    visible ? "Hide password" : "Show password",
  );
  button.title = visible ? "Hide password" : "Show password";
  button.innerHTML = [
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">',
    '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>',
    '<circle cx="12" cy="12" r="3"/>',
    templateText(visible ? '<path d="m3 3 18 18"/>' : ""),
    "</svg>",
  ].join("");
}

function initializePasswordToggles() {
  document.querySelectorAll('input[type="password"]').forEach((input) => {
    if (!input.id || input.closest(".password-field")) return;
    const wrapper = document.createElement("div");
    wrapper.className = "password-field";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "password-toggle";
    button.setAttribute("aria-controls", input.id);
    setPasswordVisible(input, button, false);
    input.parentNode.insertBefore(wrapper, input);
    wrapper.append(input, button);
    button.addEventListener("click", () => {
      setPasswordVisible(input, button, input.type === "password");
    });
    const hide = () => setPasswordVisible(input, button, false);
    input.form?.addEventListener("reset", hide);
    input.form?.addEventListener("submit", hide);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-ui-icon]").forEach((node) => {
    node.innerHTML = uiIcon(node.dataset.uiIcon);
  });
  initializePasswordToggles();
  if (PAGE === "login") void initLogin();
  else void startProtectedPage();
});

// Permissions reload on return to the tab. Every request is also authorized by the server.
window.addEventListener("focus", () => {
  if (PAGE !== "login" && state.user) void initializeGitHubMonitor(false);
  if (PAGE !== "login" && state.user)
    void refreshIdentity().catch((error) => {
      if (!state.redirecting)
        setMessage("global-message", error.message, "error");
    });
  void updateHealth();
});
// Only read stored API data here; GitHub requests run in the backend polling loop.
async function refreshVisiblePage() {
  if (
    document.visibilityState !== "visible" ||
    !state.user ||
    state.autoRefreshBusy ||
    state.scanBusy
  )
    return;
  state.autoRefreshBusy = true;
  try {
    if (PAGE === "dashboard")
      await loadDashboard({
        background: true,
      });
    if (PAGE === "history")
      await loadHistory({
        background: true,
      });
    // Monitoring has editable controls; retain its selection during a refresh.
    if (PAGE === "scan" && !el("repository-select")?.matches(":focus"))
      await loadRepositorySelect({
        background: true,
      });
  } finally {
    state.autoRefreshBusy = false;
  }
}

window.setInterval(() => {
  void refreshVisiblePage().catch(() => {});
}, 5000);
window.setInterval(() => {
  if (document.visibilityState === "visible" && PAGE !== "login" && state.user)
    void refreshIdentity().catch(() => {});
}, 60000);
