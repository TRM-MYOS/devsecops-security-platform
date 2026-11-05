// Scan History: filtering, breadcrumbs, selected scans, and finding details.
// Loaded with defer; common.js provides the single shared state.

"use strict";

// Repository/branch navigation and list filtering.
function historyScope(repo, branch, scan) {
  const branches = Array.isArray(repo.tracking?.branches)
    ? repo.tracking.branches
    : [];
  const current = branches.find((item) => item.branch === branch);
  return [
    templateText(historyBreadcrumb(repo, branch, scan)),
    templateText(
      scan
        ? ""
        : [
            '<p class="muted">Retained GitHub push workflow runs, including attempts without a validated report.',
            "</p>",
            templateText(
              branch === null
                ? scanGroup(repo)
                : current
                  ? `<details class="branch-current"><summary>Latest branch sync status</summary>${trackingDetails(current)}</details>`
                  : '<p class="muted">This branch is not present in the latest sync; recorded history is shown below.</p>',
            ),
          ].join(""),
    ),
  ].join("");
}

function filterHistory(scans) {
  const { search, repository, gate } = state.historyFilters;
  const query = search.trim().toLowerCase();
  return scans
    .filter(
      (scan) =>
        (!repository || String(scan.repository_id) === repository) &&
        (!gate ||
          (gate === "OTHER"
            ? !["ALLOW", "BLOCK"].includes(scan.status)
            : scan.status === gate)) &&
        (!query ||
          [
            scan.repository_name,
            scan.github?.branch,
            scan.github?.commit_sha,
            scan.github?.commit_message,
          ].some((value) =>
            String(value || "")
              .toLowerCase()
              .includes(query),
          )),
    )
    .slice()
    .sort(
      (a, b) =>
        (Date.parse(b.scanned_at) || 0) - (Date.parse(a.scanned_at) || 0) ||
        Number(b.id) - Number(a.id),
    );
}

function renderHistoryList() {
  const scans = state.scopedScans;
  const filtered = filterHistory(scans);
  const pages = Math.max(1, Math.ceil(filtered.length / 20));
  state.historyPage = Math.max(1, Math.min(state.historyPage || 1, pages));
  const displayed = filtered.slice(
    (state.historyPage - 1) * 20,
    state.historyPage * 20,
  );
  const selected = new URLSearchParams(location.search).get("scan");
  const container = el("history-container");
  if (!scans.length) {
    updateMarkup(
      container,
      emptyState(
        "No recorded scans",
        "Sync GitHub Actions results to import commit history for this scope.",
      ),
    );
    return;
  }
  if (!displayed.length) {
    updateMarkup(
      container,
      emptyState(
        "No matching scans",
        "Try a different search or filter. The selected scan remains open below.",
      ),
    );
    return;
  }
  updateMarkup(
    container,
    [
      '<div class="table-wrapper">',
      '<table class="history-table">',
      '<caption class="hidden">Recorded security scans, newest first',
      "</caption>",
      "<thead>",
      "<tr>",
      templateText(
        [
          "Repository / Commit",
          "Score",
          "Grade",
          "Gate",
          "Findings",
          "Scanned",
          "Details",
        ]
          .map((label) => `<th scope="col">${label}</th>`)
          .join(""),
      ),
      "</tr>",
      "</thead>",
      "<tbody>",
      templateText(
        displayed
          .map((scan) =>
            [
              '<tr class="',
              templateText(String(scan.id) === selected ? "selected-scan" : ""),
              '" ',
              templateText(
                String(scan.id) === selected ? 'aria-current="true"' : "",
              ),
              ">",
              '<td class="scan-identity">',
              "<strong>",
              templateText(escapeHtml(scan.repository_name || "Repository")),
              "</strong>",
              templateText(
                scan.github
                  ? [
                      '<span class="scan-branch">',
                      templateText(uiIcon("branch")),
                      templateText(
                        escapeHtml(scan.github.branch || "Not available"),
                      ),
                      " ",
                      "<code>",
                      templateText(
                        escapeHtml((scan.github.commit_sha || "").slice(0, 12)),
                      ),
                      "</code>",
                      "</span>",
                      '<span class="scan-commit-message">',
                      templateText(
                        escapeHtml(
                          scan.github.commit_message || "Not available",
                        ),
                      ),
                      "</span>",
                    ].join("")
                  : '<span class="scan-commit-message">Legacy local scan</span>',
              ),
              "</td>",
              '<td class="score-cell">',
              templateText(
                scan.score == null
                  ? "Not available"
                  : `${escapeHtml(scan.score)}/100`,
              ),
              "</td>",
              "<td>",
              templateText(escapeHtml(scan.grade || "?")),
              "</td>",
              "<td>",
              templateText(historyRecordBadge(scan)),
              "</td>",
              "<td>",
              templateText(escapeHtml(scan.findings ?? "?")),
              "</td>",
              '<td class="scan-date">',
              templateText(escapeHtml(formatDate(scan.scanned_at))),
              "</td>",
              "<td>",
              '<button class="small-button view-scan" data-action="show-findings" data-id="',
              templateText(escapeHtml(scan.id)),
              '" aria-label="View details for ',
              templateText(escapeHtml(scan.repository_name || "repository")),
              " scan ",
              templateText(escapeHtml(scan.id)),
              '">View details ',
              templateText(uiIcon("chevron")),
              "</button>",
              "</td>",
              "</tr>",
            ].join(""),
          )
          .join(""),
      ),
      "</tbody>",
      "</table>",
      "</div>",
      '<div class="history-table-footer">',
      "<span>",
      "<strong>",
      templateText(filtered.length),
      "</strong> of ",
      templateText(scans.length),
      " recorded scans",
      "<br>Select a scan to inspect its findings.",
      paginationControls(state.historyPage, pages, "history-page"),
      "</span>",
      "<span>",
      templateText(uiIcon("info")),
      " Scores and gate decisions are independent.",
      "</span>",
      "</div>",
    ].join(""),
  );
}

function renderHistoryStats() {
  const scans = state.scopedScans;
  const values = [
    ["Recorded scans", scans.length, "file", ""],
    [
      "Allowed",
      scans.filter((scan) => scan.status === "ALLOW").length,
      "allow",
      "allow",
    ],
    [
      "Blocked",
      scans.filter((scan) => scan.status === "BLOCK").length,
      "block",
      "block",
    ],
    [
      "Total findings",
      scans.reduce((sum, scan) => sum + (Number(scan.findings) || 0), 0),
      "shield",
      "",
    ],
  ];
  updateMarkup(
    el("history-stats"),
    values
      .map(
        ([label, count, icon, color]) =>
          `<div class="history-stat ${color}"><span class="history-stat-icon">${uiIcon(icon)}</span><div><span>${label}</span><strong>${count}</strong></div></div>`,
      )
      .join(""),
  );
  const scope = state.historyListScope;
  el("history-stats-scope").textContent = [
    "Historical records",
    templateText(
      scope?.repository
        ? " for the selected repository"
        : " across repositories",
    ),
    templateText(scope?.branch ? ` / ${scope.branch}` : ""),
    ". Counts describe this history scope before search filters, not current branch status.",
  ].join("");
  const options = new Map(
    scans.map((scan) => [
      String(scan.repository_id),
      scan.repository_name || "Repository",
    ]),
  );
  // Do not rebuild the select on each timer tick (preserves focus and the selection).
  const select = el("history-repository-filter");
  const key = JSON.stringify([...options]);
  if (select.dataset.optionsKey !== key) {
    select.innerHTML =
      '<option value="">All repositories</option>' +
      [...options]
        .map(
          ([id, name]) =>
            `<option value="${escapeHtml(id)}">${escapeHtml(name)}</option>`,
        )
        .join("");
    if (options.has(state.historyFilters.repository))
      select.value = state.historyFilters.repository;
    else {
      state.historyFilters.repository = "";
      select.value = "";
    }
    select.dataset.optionsKey = key;
  }
}

// Reload stored history while retaining the current selection.
async function loadHistory({ background = false } = {}) {
  if (state.historyLoading) return;
  state.historyLoading = true;
  const route = location.search;
  const params = new URLSearchParams(route);
  if (!state.historyListScope)
    state.historyListScope = {
      repository: params.get("repository"),
      branch: params.get("branch"),
    };
  const container = el("history-container");
  if (!background)
    container.innerHTML = '<div class="loading">Loading scan history...</div>';
  try {
    const scans = requireArray(await fetchJson(API.scans), "scans");
    if (route !== location.search) return;
    const repositoryId = params.get("repository");
    const branchName = params.get("branch");
    const repositories = repositoryId
      ? requireArray(await fetchJson(API.repositories), "repositories")
      : [];
    if (route !== location.search) return;
    state.scans = new Map(scans.map((scan) => [String(scan.id), scan]));
    const scope = state.historyListScope;
    state.scopedScans = scans.filter(
      (scan) =>
        (!scope.repository ||
          String(scan.repository_id) === scope.repository) &&
        (scope.branch === null || scan.github?.branch === scope.branch),
    );
    const repository = repositories.find(
      (repo) => String(repo.id) === repositoryId,
    );
    if (repositoryId && !repository)
      throw new ApiError("Repository not found or access removed", 404);
    const current = null;
    updateMarkup(
      el("history-scope"),
      repository
        ? historyScope(repository, branchName, params.get("scan"))
        : current
          ? historyBreadcrumb(
              {
                id: current.repository_id,
                name: current.repository_name,
              },
              current.github?.branch ?? null,
              current.id,
            )
          : '<nav class="breadcrumbs" aria-label="Breadcrumb"><a href="index.html">Dashboard</a><span aria-hidden="true">&rsaquo;</span><span aria-current="page">Scan History</span></nav>',
    );
    renderHistoryStats();
    renderHistoryList();
    const savedScroll = sessionStorage.getItem(
      "history-scroll:" + location.search,
    );
    if (!background && savedScroll !== null)
      window.scrollTo(0, Number(savedScroll) || 0);
  } catch (error) {
    if (route === location.search) {
      state.scans.clear();
      state.scopedScans = [];
      el("history-scope").innerHTML = "";
      updateMarkup(container, errorBox(error, "reload-history"));
      el("history-stats").innerHTML =
        '<p class="message warning">Historical statistics unavailable. Refresh to retry.</p>';
    }
  } finally {
    state.historyLoading = false;
  }
}

function initializeHistory() {
  const params = new URLSearchParams(location.search);
  if (params.has("scan")) {
    const scan = params.get("scan");
    params.delete("scan");
    location.replace(
      scanDetailLink(scan, `history.html${params.size ? "?" + params : ""}`),
    );
    return false;
  }
  state.historyFilters = {
    search: params.get("q") || "",
    repository: params.get("filter_repo") || "",
    gate: params.get("gate") || "",
  };
  const requestedPage = Number(params.get("page"));
  state.historyPage =
    Number.isInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1;
  el("history-search").value = state.historyFilters.search;
  el("history-gate-filter").value = state.historyFilters.gate;
  return true;
}
function rememberHistory() {
  const params = new URLSearchParams(location.search);
  for (const [key, value] of Object.entries({
    q: state.historyFilters.search,
    filter_repo: state.historyFilters.repository,
    gate: state.historyFilters.gate,
    page: state.historyPage > 1 ? state.historyPage : "",
  })) {
    if (value) params.set(key, String(value));
    else params.delete(key);
  }
  history.replaceState(
    null,
    "",
    `history.html${params.size ? "?" + params : ""}`,
  );
}
document.addEventListener("input", (event) => {
  if (event.target.id !== "history-search") return;
  state.historyFilters.search = event.target.value;
  state.historyPage = 1;
  renderHistoryList();
  rememberHistory();
});
document.addEventListener("change", (event) => {
  if (event.target.id === "history-repository-filter")
    state.historyFilters.repository = event.target.value;
  else if (event.target.id === "history-gate-filter")
    state.historyFilters.gate = event.target.value;
  else return;
  state.historyPage = 1;
  renderHistoryList();
  rememberHistory();
});
