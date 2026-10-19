// Repository Monitoring: connect repositories and display branch sync results.
// Loaded with defer; common.js provides the single shared state.

"use strict";

// Retained report renderers for compatibility with the previous UI.
function branchResults(info) {
  const branches = Array.isArray(info.branches)
    ? info.branches
    : info.branch
      ? [info]
      : [];
  if (!branches.length) return trackingDetails(info);
  return [
    '<p class="muted">Tracking all ',
    templateText(branches.length),
    " branches automatically",
    "</p>",
    templateText(
      branches
        .map((branch) =>
          [
            '<section class="branch-result">',
            templateText(trackingDetails(branch)),
            templateText(
              branch.scan_id
                ? `<a href="history.html?scan=${encodeURIComponent(branch.scan_id)}">View score and findings</a>`
                : "",
            ),
            "</section>",
          ].join(""),
        )
        .join(""),
    ),
  ].join("");
}

// Current repository/branch summaries and sync state.
function monitoringBranchRow(repo, branch) {
  const status =
    branch.execution_status === "completed" && branch.policy_status === "WARN"
      ? {
          label: "WARN",
          style: "warning",
        }
      : branchState(branch);
  const evaluated =
    branch.execution_status === "completed" &&
    ["ALLOW", "BLOCK", "WARN"].includes(branch.policy_status);
  const count =
    Number.isInteger(branch.findings) && branch.findings >= 0
      ? branch.findings
      : null;
  const findings = evaluated
    ? count === null
      ? "Findings unavailable"
      : `${count} ${count === 1 ? "finding" : "findings"}`
    : "Not evaluated";
  const commit = [branch.commit_sha?.slice(0, 12), branch.commit_message]
    .filter(Boolean)
    .join(" · ");
  const context = branch.message || commit || "Waiting for a matching scan";
  return [
    '<a class="monitoring-branch ',
    templateText(status.style),
    '" href="',
    templateText(historyLink(repo, branch.branch)),
    '" aria-label="',
    templateText(
      escapeHtml(`View ${branch.branch} history: ${status.label}, ${findings}`),
    ),
    '">',
    templateText(uiIcon("branch")),
    '<span class="monitoring-branch-identity">',
    "<strong>",
    templateText(escapeHtml(branch.branch)),
    "</strong>",
    '<span title="',
    templateText(escapeHtml(context)),
    '">',
    templateText(escapeHtml(context)),
    "</span>",
    "</span>",
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
    '<span class="monitoring-branch-count">',
    templateText(escapeHtml(findings)),
    "</span>",
    templateText(uiIcon("chevron")),
    "</a>",
  ].join("");
}

function renderMonitoringRepository() {
  const results = el("scan-results");
  const checked = el("monitoring-last-sync");
  const repository = state.monitoringRepositories.get(
    el("repository-select")?.value,
  );
  if (!results || !checked) return;
  results.hidden = !repository;
  if (!repository) {
    updateMarkup(results, "");
    checked.textContent = "No repository selected";
    return;
  }
  const tracking = repository.tracking || {};
  const branches = Array.isArray(tracking.branches) ? tracking.branches : [];
  checked.textContent = tracking.synced_at
    ? `Last synced: ${formatDate(tracking.synced_at)}`
    : "No sync recorded yet";
  const notice = tracking.message
    ? `<p class="message warning">${escapeHtml(tracking.message)}</p>`
    : "";
  const historyWarning =
    tracking.history?.status === "error"
      ? `<p class="message warning">History sync: ${escapeHtml(tracking.history.message || "Some past runs could not be imported.")}</p>`
      : "";
  updateMarkup(
    results,
    [
      '<div class="monitoring-repository-heading">',
      '<div class="repo-identity">',
      templateText(uiIcon("github", "repo-icon")),
      "<h3>",
      templateText(escapeHtml(repository.name)),
      "</h3>",
      '<span class="monitoring-branch-total">',
      templateText(branches.length),
      " ",
      templateText(branches.length === 1 ? "branch" : "branches"),
      "</span>",
      "</div>",
      '<a class="text-link" href="',
      templateText(historyLink(repository)),
      '">View history ',
      templateText(uiIcon("arrow")),
      "</a>",
      "</div>",
      templateText(notice),
      templateText(historyWarning),
      '<div class="monitoring-branches">',
      templateText(
        branches.length
          ? branches
              .map((branch) => monitoringBranchRow(repository, branch))
              .join("")
          : emptyState(
              "No branches synchronized yet",
              "Sync results to discover branches and read available workflow reports.",
            ),
      ),
      "</div>",
    ].join(""),
  );
}

// Repository selection and background refresh.
async function loadRepositorySelect({ background = false } = {}) {
  if (state.repositorySelectLoading) return;
  state.repositorySelectLoading = true;
  const select = el("repository-select");
  const previousSelection = select.value;
  if (!background) {
    select.disabled = true;
    select.replaceChildren(new Option("Loading repositories...", ""));
  }
  try {
    const repositories = requireArray(
      await fetchJson(API.repositories),
      "repositories",
    );
    state.monitoringRepositories = new Map(
      repositories.map((repo) => [String(repo.id), repo]),
    );
    const selected = background ? select.value : previousSelection;
    const optionsKey = JSON.stringify(
      repositories.map((repo) => [String(repo.id), repo.name]),
    );
    if (!background || select.dataset.optionsKey !== optionsKey) {
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
      select.dataset.optionsKey = optionsKey;
      if (repositories.some((repo) => String(repo.id) === selected))
        select.value = selected;
      else if (repositories.length === 1)
        select.value = String(repositories[0].id);
    }
    renderMonitoringRepository();
    select.disabled = repositories.length === 0;
    el("scan-all-button").dataset.empty = String(repositories.length === 0);
    if (!repositories.length)
      setMessage(
        "scan-message",
        "No repositories are connected yet. Add an authorized repository to monitor its workflow results.",
        "info",
      );
  } catch (error) {
    state.monitoringRepositories.clear();
    renderMonitoringRepository();
    if (el("monitoring-last-sync"))
      el("monitoring-last-sync").textContent =
        "Could not refresh repository data";
    delete select.dataset.optionsKey;
    select.replaceChildren(new Option("Repositories unavailable", ""));
    select.disabled = true;
    el("scan-message").innerHTML = errorBox(error, "reload-repository-select");
    el("scan-all-button").dataset.empty = "true";
  } finally {
    state.repositorySelectLoading = false;
    syncScanButtons();
  }
}

// Connect a repository and request its first synchronization.
async function addRepository(event) {
  event.preventDefault();
  if (!canScan()) return;
  const button = el("add-repository-button");
  if (button.disabled) return;
  const originalLabel = button.innerHTML;
  button.disabled = true;
  button.textContent = "Adding...";
  try {
    const data = await fetchJson(API.repositories, {
      method: "POST",
      body: JSON.stringify({
        repo_url: el("repo-url").value.trim(),
      }),
    });
    setMessage(
      "add-message",
      `Repository "${data.repository?.name || ""}" added.`,
      "success",
    );
    el("repo-url").value = "";
    await loadRepositorySelect();
    if (data.repository?.id) {
      el("repository-select").value = String(data.repository.id);
      renderMonitoringRepository();
      await runScan(String(data.repository.id));
    }
  } catch (error) {
    setMessage("add-message", error.message, "error");
  } finally {
    button.disabled = false;
    button.innerHTML = originalLabel;
  }
}

// Legacy result renderers retained without changing their output.
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
  return [
    '<article class="result-detail">',
    '<div class="result-heading">',
    "<div>",
    "<h3>",
    templateText(escapeHtml(repositoryName)),
    "</h3>",
    "<p>Execution completed / Policy decision below",
    "</p>",
    "</div>",
    templateText(statusBadge(scan.status)),
    "</div>",
    templateText(
      scan.github
        ? trackingDetails({
            ...scan.github,
            execution_status: "completed",
            policy_status: scan.status,
          })
        : "<p>Legacy local scan (not linked to a GitHub commit)</p>",
    ),
    '<p class="result-reason">',
    "<strong>Decision reason:",
    "</strong> ",
    templateText(
      escapeHtml(scan.reason || "No reason returned by the service."),
    ),
    "</p>",
    '<div class="result-stats">',
    templateText(
      stats
        .map(
          ([label, value]) =>
            `<div class="result-stat"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>`,
        )
        .join(""),
    ),
    "</div>",
    '<div class="scanner-grid">',
    templateText(
      ["Bandit", "Trivy", "Gitleaks"]
        .map(
          (name) =>
            `<div class="scanner-card"><span>${name} findings</span><strong>${escapeHtml(scan.scanner_counts?.[name] ?? "-")}</strong></div>`,
        )
        .join(""),
    ),
    "</div>",
    '<div class="severity-grid">',
    templateText(
      ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        .map(
          (level) =>
            `<div><span>${level}</span><strong>${escapeHtml(scan.severity_counts?.[level] ?? "-")}</strong></div>`,
        )
        .join(""),
    ),
    "</div>",
    "<h3>Findings",
    "</h3>",
    templateText(
      findings === null
        ? errorBox(
            new Error(
              "Findings details were not included in the scan response. Open scan history to load the recorded findings.",
            ),
          )
        : findings.length
          ? findings.map((finding) => findingRow(finding)).join("")
          : '<p class="no-findings">No findings reported by this scan.</p>',
    ),
    "</article>",
  ].join("");
}

function renderBulkResults(data) {
  const results = requireArray(data, "results");
  return [
    "<h2>Scan all results",
    "</h2>",
    '<div class="bulk-summary">',
    "<span>",
    "<strong>",
    templateText(escapeHtml(data.total ?? "-")),
    "</strong>Repositories",
    "</span>",
    "<span>",
    "<strong>",
    templateText(escapeHtml(data.successful ?? "-")),
    "</strong>Execution completed",
    "</span>",
    "<span>",
    "<strong>",
    templateText(escapeHtml(data.failed ?? "-")),
    "</strong>Execution failed",
    "</span>",
    "</div>",
    templateText(
      data.total === 0
        ? emptyState(
            "No repositories to scan",
            "Connect a repository before running Scan all.",
          )
        : results
            .map((result) =>
              result.status === "success" && result.scan
                ? renderScanResult(result.scan, result.repository_name)
                : [
                    '<article class="bulk-failure">',
                    "<h3>",
                    templateText(
                      escapeHtml(result.repository_name || "Repository"),
                    ),
                    " / Execution failed",
                    "</h3>",
                    "<p>",
                    templateText(
                      escapeHtml(
                        result.error ||
                          "The service did not return a scan result.",
                      ),
                    ),
                    "</p>",
                    "</article>",
                  ].join(""),
            )
            .join(""),
    ),
  ].join("");
}
