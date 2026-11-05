// Shared scan presentation; policy decisions are always provided by the Backend.
"use strict";

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

function detailMetadata(scan) {
  const info = scan.github || {};
  const applied = scan.policy || info.policy;
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
    [
      "Score",
      scan.score != null ? `${scan.score}/100` : "Not available",
      "chart",
    ],
    ["Grade", scan.grade || "Not available", "shield"],
    [
      "Policy version",
      applied?.version || "Not recorded (legacy scan)",
      "shield",
    ],
    [
      "Passing threshold",
      applied?.minimum_score != null
        ? `${applied.minimum_score}/100`
        : "Not recorded",
      "shield",
    ],
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
  const { scanner, sort, severity, file } = state.detailFilters;
  const entries = findings
    .map((finding, index) => ({
      finding,
      index,
    }))
    .filter(
      ({ finding }) =>
        (!scanner || (finding.scanner || "Unknown scanner") === scanner) &&
        (!severity || String(finding.severity).toUpperCase() === severity) &&
        (!file ||
          String(reportFilePath(finding.file) || "")
            .toLowerCase()
            .includes(file.toLowerCase())),
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
  const pages = Math.max(1, Math.ceil(rows.length / 20));
  state.detailPage = Math.min(Math.max(1, state.detailPage || 1), pages);
  const displayed = rows.slice(
    (state.detailPage - 1) * 20,
    state.detailPage * 20,
  );
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
          : displayed
              .map(({ finding, index }) =>
                findingCard(finding, index, detail.scan),
              )
              .join("") +
            paginationControls(state.detailPage, pages, "findings-page"),
  );
  el("detail-visible-count").textContent =
    `${rows.length} of ${detail.findings.length} findings`;
  const pager = el("detail-pagination");
  if (pager)
    updateMarkup(
      pager,
      rows.length > 20
        ? paginationControls(state.detailPage, pages, "findings-page")
        : "",
    );
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
    `<label class="sr-filter-label">Severity<select id="detail-severity-filter"><option value="">All severities</option>${Object.keys(
      SEVERITY_ORDER,
    )
      .map(
        (level) =>
          `<option ${state.detailFilters.severity === level ? "selected" : ""}>${level}</option>`,
      )
      .join("")}</select></label>`,
    `<label class="sr-filter-label">File<input id="detail-file-filter" type="search" placeholder="Filter file path" value="${escapeHtml(state.detailFilters.file || "")}" /></label>`,
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
    '<div id="detail-pagination"></div>',
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

function closeDetailsButton() {
  return `<a class="secondary-button compact close-details" href="${escapeHtml(safeHistoryReturn(new URLSearchParams(location.search).get("return")))}">Back to history</a>`;
}
