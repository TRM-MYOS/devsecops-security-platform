// Scan History: filtering, breadcrumbs, selected scans, and finding details.
// Loaded with defer; common.js provides the single shared state.

"use strict";

// Repository/branch navigation and list filtering.
function historyBreadcrumb(repo, branch, scan = null) {
  return [
    '<nav class="breadcrumbs" aria-label="Breadcrumb">',
    '<a href="index.html">',
    templateText(uiIcon("home")),
    "Dashboard",
    "</a>",
    '<span aria-hidden="true">&rsaquo;',
    "</span>",
    '<a href="history.html">Scan History',
    "</a>",
    '<span aria-hidden="true">&rsaquo;',
    "</span>",
    '<a href="',
    templateText(historyLink(repo)),
    '">',
    templateText(escapeHtml(repo.name || "Repository")),
    "</a>",
    templateText(
      branch !== null
        ? `<span aria-hidden="true">&rsaquo;</span><a href="${historyLink(repo, branch)}">${uiIcon("branch")}${escapeHtml(branch)}</a>`
        : "",
    ),
    templateText(
      scan
        ? `<span aria-hidden="true">&rsaquo;</span><span aria-current="page">${uiIcon("file")}Scan #${escapeHtml(scan)}</span>`
        : "",
    ),
    "</nav>",
  ].join("");
}

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

function historyGateBadge(status) {
  const known = ["ALLOW", "BLOCK"].includes(status);
  return [
    '<span class="status-badge ',
    templateText(known ? status.toLowerCase() : "unknown"),
    '">',
    templateText(
      uiIcon(
        status === "ALLOW" ? "allow" : status === "BLOCK" ? "block" : "info",
      ),
    ),
    templateText(escapeHtml(status || "Not evaluated")),
    "</span>",
  ].join("");
}

function historyRecordBadge(scan) {
  if (scan.report_available === false) {
    const label =
      {
        error: "ERROR",
        running: "RUNNING",
        queued: "QUEUED",
      }[scan.execution_status] || "NOT EVALUATED";
    return `<span class="status-badge ${label === "ERROR" ? "error" : "unknown"}">${uiIcon(label === "ERROR" ? "error" : "clock")}${label}</span>`;
  }
  return historyGateBadge(scan.status);
}

function renderHistoryList() {
  const scans = state.scopedScans;
  const displayed = filterHistory(scans);
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
      templateText(displayed.length),
      "</strong> of ",
      templateText(scans.length),
      " recorded scans",
      "<br>Select a scan to inspect its findings.",
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
    const current = state.scans.get(params.get("scan"));
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
    const selected = state.selectedDetail?.scan;
    if (background && selected?.report_available === false) {
      const updated = scans.find(
        (scan) =>
          scan.github?.run_id === selected.github?.run_id &&
          scan.github?.run_attempt === selected.github?.run_attempt &&
          scan.repository_id === selected.repository_id,
      );
      if (
        updated &&
        (updated.report_available !== false ||
          updated.execution_status !== selected.execution_status ||
          updated.reason !== selected.reason)
      )
        await showHistoryFindings(updated.id, {
          scroll: false,
        });
    }
    const scanId = params.get("scan");
    if (
      !background &&
      scanId &&
      state.scopedScans.some((scan) => String(scan.id) === scanId) &&
      el("history-detail").hidden
    )
      await showHistoryFindings(scanId);
  } catch (error) {
    if (route === location.search) {
      updateMarkup(container, errorBox(error, "reload-history"));
      el("history-stats").innerHTML =
        '<p class="message warning">Historical statistics unavailable. Refresh to retry.</p>';
    }
  } finally {
    state.historyLoading = false;
  }
}

// Selected scan lifecycle and commit metadata.
function closeDetailsButton() {
  return [
    '<button type="button" class="secondary-button compact close-details" data-action="close-findings" aria-label="Close scan ',
    'details">&times; Close details',
    "</button>",
  ].join("");
}

function closeHistoryFindings() {
  ++state.historyGeneration;
  state.selectedDetail = null;
  const params = new URLSearchParams(location.search);
  const scanId = params.get("scan");
  params.delete("scan");
  history.replaceState(
    null,
    "",
    `history.html${params.size ? "?" + params : ""}`,
  );
  const container = el("history-detail");
  container.hidden = true;
  container.innerHTML = "";
  const scope = el("history-scope");
  const breadcrumb = scope?.querySelector(".breadcrumbs");
  breadcrumb
    ?.querySelector('[aria-current="page"]')
    ?.previousElementSibling?.remove();
  breadcrumb?.querySelector('[aria-current="page"]')?.remove();
  if (scope) state.renderedContent.delete(scope);
  renderHistoryList();
  [...document.querySelectorAll('[data-action="show-findings"]')]
    .find((node) => node.dataset.id === scanId)
    ?.focus({
      preventScroll: true,
    });
}

function detailMetadata(scan) {
  const info = scan.github || {};
  const fields = [
    ["Branch", info.branch, "branch"],
    ["Commit", info.commit_sha?.slice(0, 12), "commit"],
    [
      "Execution",
      scan.report_available === false
        ? {
            error: "Scan / report error",
            running: "Running",
            queued: "Queued",
          }[scan.execution_status] || "Not evaluated"
        : "Completed",
      scan.report_available === false ? "info" : "allow",
    ],
    [
      "Scanned",
      scan.scanned_at ? formatDate(scan.scanned_at) : null,
      "calendar",
    ],
    ["Commit message", info.commit_message, "file"],
    ["Author", info.commit_author, "user"],
  ];
  return [
    '<div class="scan-metadata">',
    templateText(
      fields
        .map(([label, value, icon]) =>
          [
            '<div class="metadata-item ',
            templateText(
              label === "Commit message"
                ? "metadata-message"
                : label === "Execution"
                  ? "metadata-execution"
                  : "",
            ),
            '">',
            templateText(uiIcon(icon)),
            "<div>",
            "<span>",
            templateText(label),
            "</span>",
            "<strong>",
            templateText(escapeHtml(value || "Not available")),
            "</strong>",
            "</div>",
            "</div>",
          ].join(""),
        )
        .join(""),
    ),
    '<div class="metadata-run">',
    templateText(githubActionLink(info.run_url, "View GitHub run")),
    "</div>",
    "</div>",
  ].join("");
}

function githubActionLink(url, label) {
  if (!url) return '<span class="muted">GitHub run: Not available</span>';
  const link = safeRepositoryLink(url, label);
  return link.startsWith("<a ")
    ? link
        .replace(
          'class="repository-url"',
          'class="secondary-button github-button"',
        )
        .replace("</a>", `${uiIcon("external")}</a>`)
    : '<span class="muted">GitHub run: Not available</span>';
}

// Findings rendering, filtering, severity ordering, and disclosure state.
function findingCard(finding, index, scan) {
  const severity = String(finding.severity || "UNKNOWN").toUpperCase();
  const color = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity)
    ? severity.toLowerCase()
    : "unknown";
  const key = `${scan.id}:${index}`;
  const expanded = state.findingDisclosure.get(key) !== false;
  const original = `${finding.scanner || "Unknown scanner"} / ${finding.file || "No file information"}${finding.line != null ? ":" + finding.line : ""}`;
  const file = reportFilePath(finding.file);
  const line =
    Number.isInteger(finding.line) && finding.line > 0 ? finding.line : null;
  const validPath =
    file &&
    !file.startsWith("/") &&
    !file.includes(":") &&
    !file.split("/").some((part) => part === "." || part === "..");
  const info = scan.github;
  const codeLink =
    info?.full_name && /^[a-f0-9]{40}$/.test(info.commit_sha || "") && validPath
      ? safeRepositoryLink(
          `https://github.com/${info.full_name}/blob/${info.commit_sha}/${file.split("/").map(encodeURIComponent).join("/")}${line ? "#L" + line : ""}`,
          "Open file on GitHub",
        )
      : "";
  const cwe = /^CWE-([0-9]+)$/.exec(finding.cwe || "");
  return [
    '<details class="finding-card ',
    templateText(color),
    '" data-finding-key="',
    templateText(escapeHtml(key)),
    '" ',
    templateText(expanded ? "open" : ""),
    ">",
    "<summary>",
    templateText(
      uiIcon(
        ["HIGH", "CRITICAL", "MEDIUM"].includes(severity) ? "error" : "info",
      ),
    ),
    "<strong>",
    templateText(
      escapeHtml(finding.title || finding.rule_id || "Security finding"),
    ),
    "</strong>",
    templateText(
      finding.title && finding.rule_id
        ? `<span class="rule-chip">${escapeHtml(finding.rule_id)}</span>`
        : "",
    ),
    '<span class="scanner-chip">',
    templateText(escapeHtml(finding.scanner || "Unknown scanner")),
    "</span>",
    '<span class="severity-badge ',
    templateText(color),
    '">',
    templateText(escapeHtml(severity)),
    "</span>",
    templateText(uiIcon("chevron", "finding-chevron")),
    "</summary>",
    '<div class="finding-body">',
    templateText(
      finding.message ? `<p>${escapeHtml(finding.message)}</p>` : "",
    ),
    '<div class="finding-file-strip">',
    templateText(uiIcon("file")),
    "<div>",
    "<span>Affected file",
    "</span>",
    "<code>",
    templateText(escapeHtml(file || "Not available")),
    "</code>",
    "</div>",
    '<div class="finding-line">',
    "<span>Line",
    "</span>",
    "<strong>",
    templateText(line || "Not available"),
    "</strong>",
    "</div>",
    templateText(
      codeLink
        ? codeLink
            .replace(
              'class="repository-url"',
              'class="secondary-button github-button"',
            )
            .replace("</a>", `${uiIcon("external")}</a>`)
        : '<span class="muted">Source link unavailable</span>',
    ),
    "</div>",
    '<div class="finding-original">',
    "<span>",
    templateText(escapeHtml(original)),
    "</span>",
    templateText(
      cwe
        ? `<a href="https://cwe.mitre.org/data/definitions/${cwe[1]}.html" target="_blank" rel="noopener noreferrer">${escapeHtml(cwe[0])}${uiIcon("external")}</a>`
        : finding.cwe
          ? `<span>${escapeHtml(finding.cwe)}</span>`
          : "",
    ),
    "</div>",
    "</div>",
    "</details>",
  ].join("");
}

const SEVERITY_ORDER = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
};
function filteredFindings(findings) {
  const { scanner, sort } = state.detailFilters;
  const entries = findings
    .map((finding, index) => ({
      finding,
      index,
    }))
    .filter(
      ({ finding }) =>
        !scanner || (finding.scanner || "Unknown scanner") === scanner,
    );
  if (sort === "severity")
    entries.sort(
      (a, b) =>
        (SEVERITY_ORDER[String(a.finding.severity).toUpperCase()] ?? 4) -
          (SEVERITY_ORDER[String(b.finding.severity).toUpperCase()] ?? 4) ||
        a.index - b.index,
    );
  return entries;
}

function renderDetailFindings() {
  const detail = state.selectedDetail;
  if (!detail) return;
  const rows = filteredFindings(detail.findings);
  updateMarkup(
    el("detail-findings-list"),
    detail.scan.report_available === false
      ? emptyState(
          "No validated report",
          "This run has no policy decision. It is not a clean scan or an ALLOW result.",
        )
      : !detail.findings.length
        ? emptyState(
            "No findings in this recorded scan",
            "The policy decision and reason are shown above.",
          )
        : !rows.length
          ? emptyState(
              "No matching findings",
              "Choose another scanner to see findings.",
            )
          : rows
              .map(({ finding, index }) =>
                findingCard(finding, index, detail.scan),
              )
              .join(""),
  );
  el("detail-visible-count").textContent =
    `${rows.length} of ${detail.findings.length} findings`;
}

function detailView(scan, findings) {
  const status = scan.status;
  const tone =
    status === "BLOCK" ? "block" : status === "ALLOW" ? "allow" : "unknown";
  const title =
    status === "BLOCK"
      ? "Security gate blocked"
      : status === "ALLOW"
        ? "Security gate allowed"
        : "Policy not evaluated";
  const severities = findings.reduce((counts, finding) => {
    const severity = String(finding.severity || "UNKNOWN").toUpperCase();
    const key = severity in SEVERITY_ORDER ? severity : "UNKNOWN";
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
  const scanners = [
    ...new Set(findings.map((finding) => finding.scanner || "Unknown scanner")),
  ];
  return [
    '<div class="scan-detail-heading">',
    '<span class="title-icon">',
    templateText(uiIcon("shield")),
    "</span>",
    "<div>",
    "<h2>Scan details",
    "</h2>",
    "<p>",
    templateText(escapeHtml(scan.repository_name || "Repository")),
    " / Scan #",
    templateText(escapeHtml(scan.id)),
    "</p>",
    "</div>",
    '<div class="actions">',
    templateText(historyRecordBadge(scan)),
    templateText(closeDetailsButton()),
    "</div>",
    "</div>",
    '<div class="gate-notice ',
    templateText(tone),
    '">',
    templateText(
      uiIcon(
        status === "BLOCK" ? "error" : status === "ALLOW" ? "allow" : "info",
      ),
    ),
    "<div>",
    "<strong>",
    templateText(title),
    "</strong>",
    "<p>",
    templateText(escapeHtml(scan.reason || "No policy reason available.")),
    "</p>",
    "</div>",
    "</div>",
    templateText(detailMetadata(scan)),
    templateText(
      !scan.github
        ? '<p class="muted">Legacy local scan (not linked to a GitHub commit).</p>'
        : "",
    ),
    '<div class="detail-findings-toolbar">',
    '<div class="findings-heading">',
    "<h3>",
    templateText(uiIcon("list")),
    "Security findings",
    "</h3>",
    '<span id="detail-visible-count">',
    templateText(findings.length),
    " findings",
    "</span>",
    "</div>",
    '<div class="severity-counts">',
    templateText(
      Object.keys(SEVERITY_ORDER)
        .filter((level) => severities[level])
        .map(
          (level) =>
            `<span class="severity-badge ${level.toLowerCase()}">${severities[level]} ${level}</span>`,
        )
        .join(""),
    ),
    "</div>",
    '<div class="detail-filters">',
    '<label class="sr-filter-label">Scanner',
    '<select id="detail-scanner-filter">',
    '<option value="">All scanners',
    "</option>",
    templateText(
      scanners
        .map(
          (scanner) =>
            `<option value="${escapeHtml(scanner)}" ${scanner === state.detailFilters.scanner ? "selected" : ""}>${escapeHtml(scanner)}</option>`,
        )
        .join(""),
    ),
    "</select>",
    "</label>",
    '<label class="sr-filter-label">Order',
    '<select id="detail-sort">',
    '<option value="severity" ',
    templateText(state.detailFilters.sort === "severity" ? "selected" : ""),
    ">Severity: High first",
    "</option>",
    '<option value="original" ',
    templateText(state.detailFilters.sort === "original" ? "selected" : ""),
    ">Report order",
    "</option>",
    "</select>",
    "</label>",
    "</div>",
    "</div>",
    '<div id="detail-findings-list" class="finding-cards">',
    "</div>",
    '<footer class="scan-detail-footer">',
    templateText(uiIcon("info")),
    "Showing findings for this recorded commit. Score: ",
    templateText(escapeHtml(scan.score ?? "Not available")),
    templateText(scan.score != null ? "/100" : ""),
    " / Grade: ",
    templateText(escapeHtml(scan.grade || "Not available")),
    "</footer>",
  ].join("");
}

// Ignore stale responses if details close or the selection changes.
async function showHistoryFindings(id, { scroll = true } = {}) {
  const container = el("history-detail");
  const generation = ++state.historyGeneration;
  const scan = state.scans.get(String(id));
  if (!scan) return;
  if (String(state.selectedDetail?.scan.id) !== String(id)) {
    state.detailFilters = {
      scanner: "",
      sort: "severity",
    };
    state.findingDisclosure.clear();
  }
  state.selectedDetail = null;
  const params = new URLSearchParams(location.search);
  params.set("repository", String(scan.repository_id));
  if (scan.github?.branch) params.set("branch", scan.github.branch);
  else params.delete("branch");
  params.set("scan", String(id));
  history.replaceState(null, "", `history.html?${params}`);
  updateMarkup(
    el("history-scope"),
    historyBreadcrumb(
      {
        id: scan.repository_id,
        name: scan.repository_name,
      },
      scan.github?.branch ?? null,
      id,
    ),
  );
  renderHistoryList();
  container.hidden = false;
  container.innerHTML = `${closeDetailsButton()}<div class="loading">Loading scan findings...</div>`;
  if (scroll) {
    container.focus({
      preventScroll: true,
    });
    container.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }
  try {
    const findings =
      scan.report_available === false
        ? []
        : requireArray(
            await fetchJson(`${API.scans}/${encodeURIComponent(id)}/findings`),
            "findings",
          );
    if (generation !== state.historyGeneration) return;
    state.selectedDetail = {
      scan,
      findings,
    };
    container.innerHTML = detailView(scan, findings);
    renderDetailFindings();
  } catch (error) {
    if (generation === state.historyGeneration)
      container.innerHTML = `${closeDetailsButton()}<h2>Findings could not be loaded</h2>${errorBox(error, "show-findings", id)}`;
  }
}

document.addEventListener("input", (event) => {
  if (event.target.id !== "history-search") return;
  state.historyFilters.search = event.target.value;
  renderHistoryList();
});
document.addEventListener("change", (event) => {
  const { id, value } = event.target;
  if (id === "history-repository-filter")
    state.historyFilters.repository = value;
  else if (id === "history-gate-filter") state.historyFilters.gate = value;
  else if (id === "detail-scanner-filter") {
    state.detailFilters.scanner = value;
    renderDetailFindings();
    return;
  } else if (id === "detail-sort") {
    state.detailFilters.sort = value;
    renderDetailFindings();
    return;
  } else return;
  renderHistoryList();
});
document.addEventListener(
  "toggle",
  (event) => {
    const node = event.target;
    if (node.matches?.("details[data-finding-key]") && node.isConnected)
      state.findingDisclosure.set(node.dataset.findingKey, node.open);
  },
  true,
);
