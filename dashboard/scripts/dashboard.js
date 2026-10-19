// Dashboard: repository summaries, branch disclosures, and latest findings.
// Loaded with defer; common.js provides the single shared state.

"use strict";

async function loadDashboard(options = {}) {
  await loadDashboardRepositories(options);
}

function repositoryCard(repo) {
  return [
    '<article class="repository-compact">',
    '<div class="repo-identity">',
    templateText(uiIcon("github", "repo-icon")),
    "<div>",
    "<h3>",
    templateText(escapeHtml(repo.name)),
    "</h3>",
    '<span class="muted">',
    templateText(repo.tracking?.branches?.length || 0),
    " branches / Last sync: ",
    templateText(escapeHtml(formatDate(repo.tracking?.synced_at))),
    "</span>",
    "</div>",
    "</div>",
    '<div class="actions">',
    '<a class="small-button" href="',
    templateText(historyLink(repo)),
    '">View repository',
    "</a>",
    '<button class="small-button" data-action="scan-repository" data-id="',
    templateText(escapeHtml(repo.id)),
    '" data-role="scan" data-scan-button>Sync results',
    "</button>",
    '<button class="danger-button" data-action="delete-repository" data-id="',
    templateText(escapeHtml(repo.id)),
    '" data-name="',
    templateText(escapeHtml(repo.name)),
    '" data-role="admin">Delete',
    "</button>",
    "</div>",
    "</article>",
  ].join("");
}

async function loadDashboardRepositories({ background = false } = {}) {
  if (state.dashboardLoading) return;
  state.dashboardLoading = true;
  const container = el("repositories-container");
  if (!background)
    container.innerHTML = '<div class="loading">Loading repositories...</div>';
  try {
    const repositories = requireArray(
      await fetchJson(API.repositories),
      "repositories",
    );
    updateMarkup(
      el("latest-findings"),
      repositories.length
        ? repositories.map(scanGroup).join("")
        : emptyState(
            "No repositories yet",
            "Add a repository to monitor its branches.",
          ),
    );
    el("dashboard-updated").textContent =
      `Dashboard refreshed: ${formatDate(new Date().toISOString())}`;
    el("total-repositories").textContent = repositories.length;
    const branches = repositories.flatMap(
      (repo) => repo.tracking?.branches || [],
    );
    el("passed-repositories").textContent = branches.length;
    el("blocked-repositories").textContent = branches.filter(
      (branch) => branchState(branch).label === "BLOCK",
    ).length;
    el("total-findings").textContent =
      branches.filter((branch) => branch.execution_status === "error").length +
      repositories.filter(
        (repo) =>
          !repo.tracking?.branches?.length &&
          repo.tracking?.execution_status === "error",
      ).length;
    updateMarkup(
      container,
      repositories.length
        ? repositories.map(repositoryCard).join("")
        : emptyState(
            "No repositories yet",
            canScan()
              ? "Open Security Scan to connect an authorized GitHub repository."
              : "An Operator or Super User can connect a repository.",
          ),
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
    el("latest-findings").innerHTML = errorBox(error, "reload-dashboard");
  } finally {
    state.dashboardLoading = false;
  }
}

// Retained latest-finding renderers and retry actions.
function latestFindingGroup(scan, findings, error = null) {
  return [
    '<section class="finding-group" id="latest-scan-',
    templateText(escapeHtml(scan.id)),
    '">',
    "<h3>",
    templateText(escapeHtml(scan.repository_name || "Repository")),
    '<a class="text-link" href="history.html?scan=',
    templateText(encodeURIComponent(scan.id)),
    '">Scan details',
    "</a>",
    "</h3>",
    '<p class="muted">',
    templateText(
      escapeHtml(
        scan.github
          ? `${scan.github.branch} / ${scan.github.commit_sha.slice(0, 12)} / ${scan.github.commit_message}`
          : "Legacy local scan; not linked to a GitHub commit",
      ),
    ),
    "</p>",
    templateText(
      error
        ? errorBox(error, "retry-latest-findings", scan.id)
        : findings.length
          ? findings
              .slice(0, 3)
              .map((item) => findingRow(item, "", scan.github))
              .join("") +
            (findings.length > 3
              ? `<p class="muted">${escapeHtml(findings.length - 3)} more findings in scan history.</p>`
              : "")
          : '<p class="no-findings">No findings in this recorded scan.</p>',
    ),
    "</section>",
  ].join("");
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
          "Findings will appear after GitHub Actions results have been imported.",
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
