const API = {
    repositories: "/api/repositories",
    scans: "/api/scans",
    scanAll: "/api/repositories/scan-all"
};


document.addEventListener("DOMContentLoaded", () => {

    const page = document.body.dataset.page;

    if (page === "dashboard") {
        initDashboard();
    }

    if (page === "scan") {
        initScanPage();
    }

    if (page === "history") {
        initHistoryPage();
    }

    if (page === "policy") {
        initPolicyPage();
    }

});


async function fetchJson(url, options = {}) {

    const response = await fetch(url, options);

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.detail || "Request failed"
        );
    }

    return data;
}


/* =========================================================
   DASHBOARD
========================================================= */

async function initDashboard() {

    await loadDashboardRepositories();

    await loadLatestFindings();

}


async function loadDashboardRepositories() {

    const container =
        document.getElementById("repositories-container");

    try {

        const data =
            await fetchJson(API.repositories);

        const repositories =
            data.repositories || [];

        updateDashboardStats(repositories);

        if (repositories.length === 0) {

            container.innerHTML = `
                <div class="empty-state">
                    <h3>No repositories</h3>
                    <p>Add a GitHub repository to begin.</p>
                </div>
            `;

            return;
        }

        container.innerHTML =
            repositories
                .map(createRepositoryCard)
                .join("");

    } catch (error) {

        container.innerHTML = `
            <div class="error-box">
                ${escapeHtml(error.message)}
            </div>
        `;

    }

}


function updateDashboardStats(repositories) {

    const total =
        repositories.length;

    const passed =
        repositories.filter(
            repo => repo.status === "ALLOW"
        ).length;

    const blocked =
        repositories.filter(
            repo => repo.status === "BLOCK"
        ).length;

    const findings =
        repositories.reduce(
            (sum, repo) =>
                sum + Number(repo.findings || 0),
            0
        );

    document.getElementById(
        "total-repositories"
    ).textContent = total;

    document.getElementById(
        "passed-repositories"
    ).textContent = passed;

    document.getElementById(
        "blocked-repositories"
    ).textContent = blocked;

    document.getElementById(
        "total-findings"
    ).textContent = findings;
}


function createRepositoryCard(repo) {

    const status =
        repo.status || "NOT SCANNED";

    const statusClass =
        status === "ALLOW"
            ? "allow"
            : status === "BLOCK"
                ? "block"
                : "unknown";

    const score =
        repo.score !== null &&
        repo.score !== undefined
            ? `${repo.score}/100`
            : "-";

    const grade =
        repo.grade || "-";

    const findings =
        repo.findings ?? 0;

    const lastScan =
        repo.last_scan
            ? formatDate(repo.last_scan)
            : "Never";

    return `
        <div class="repository-card">

            <div class="repository-header">

                <div>
                    <h3>
                        ${escapeHtml(repo.name)}
                    </h3>

                    <a
                        href="${escapeAttribute(repo.url)}"
                        target="_blank"
                        rel="noopener"
                        class="repository-url"
                    >
                        ${escapeHtml(repo.url)}
                    </a>
                </div>

                <span class="status-badge ${statusClass}">
                    ${escapeHtml(status)}
                </span>

            </div>


            <div class="repository-stats">

                <div>
                    <span>Score</span>
                    <strong>${score}</strong>
                </div>

                <div>
                    <span>Grade</span>
                    <strong>${grade}</strong>
                </div>

                <div>
                    <span>Findings</span>
                    <strong>${findings}</strong>
                </div>

            </div>


            <div class="repository-footer">

                <span>
                    Last scan: ${lastScan}
                </span>

                <button
                    class="small-button"
                    onclick="scanRepository(${repo.id})"
                >
                    Scan
                </button>

            </div>

        </div>
    `;
}


async function scanRepository(repositoryId) {

    showDashboardMessage(
        "Scanning repository...",
        "info"
    );

    try {

        const data =
            await fetchJson(
                `/api/repositories/${repositoryId}/scan`,
                {
                    method: "POST"
                }
            );

        showDashboardMessage(
            `Scan completed: ${data.scan?.status || data.policy || "completed"}`,
            "success"
        );

        await loadDashboardRepositories();
        await loadLatestFindings();

    } catch (error) {

        showDashboardMessage(
            error.message,
            "error"
        );

    }

}


async function scanAllRepositories() {

    showDashboardMessage(
        "Scanning all repositories...",
        "info"
    );

    try {

        const data =
            await fetchJson(
                API.scanAll,
                {
                    method: "POST"
                }
            );

        showDashboardMessage(
            `Scan All completed: ${data.successful}/${data.total} repositories successful.`,
            "success"
        );

        await loadDashboardRepositories();
        await loadLatestFindings();

    } catch (error) {

        showDashboardMessage(
            error.message,
            "error"
        );

    }

}


async function loadLatestFindings() {

    const container =
        document.getElementById("latest-findings");

    if (!container) {
        return;
    }

    try {

        const data =
            await fetchJson(API.scans);

        const scans =
            data.scans || [];

        if (scans.length === 0) {

            container.innerHTML = `
                <div class="empty-state">
                    <h3>No scan results</h3>
                    <p>Run a security scan to see findings.</p>
                </div>
            `;

            return;
        }

        const latestScans =
            scans.slice(0, 5);

        let html = "";

        for (const scan of latestScans) {

            let findings = [];

            try {

                const result =
                    await fetchJson(
                        `/api/scans/${scan.id}/findings`
                    );

                findings =
                    result.findings || [];

            } catch {
                findings = [];
            }


            if (findings.length === 0) {

                html += `
                    <div class="finding-row clean">

                        <div>
                            <strong>
                                ${escapeHtml(scan.repository_name)}
                            </strong>

                            <span>
                                No findings
                            </span>
                        </div>

                        <span class="status-badge allow">
                            CLEAN
                        </span>

                    </div>
                `;

                continue;
            }


            findings
                .slice(0, 3)
                .forEach(finding => {

                    html += `
                        <div class="finding-row">

                            <div>

                                <strong>
                                    ${escapeHtml(
                                        finding.rule_id ||
                                        finding.message ||
                                        "Security Finding"
                                    )}
                                </strong>

                                <span>
                                    ${escapeHtml(
                                        scan.repository_name
                                    )}
                                    ·
                                    ${escapeHtml(
                                        finding.file || "-"
                                    )}
                                </span>

                            </div>

                            <span class="severity-badge ${getSeverityClass(finding.severity)}">
                                ${escapeHtml(
                                    finding.severity || "UNKNOWN"
                                )}
                            </span>

                        </div>
                    `;

                });

        }

        container.innerHTML = html;

    } catch (error) {

        container.innerHTML = `
            <div class="error-box">
                ${escapeHtml(error.message)}
            </div>
        `;

    }

}


function showDashboardMessage(message, type) {

    const element =
        document.getElementById("dashboard-message");

    if (!element) {
        return;
    }

    element.innerHTML = `
        <div class="message ${type}">
            ${escapeHtml(message)}
        </div>
    `;

}


/* =========================================================
   SCAN PAGE
========================================================= */

async function initScanPage() {

    await loadRepositorySelect();

    document
        .getElementById("add-repository-button")
        .addEventListener(
            "click",
            addRepository
        );

    document
        .getElementById("scan-button")
        .addEventListener(
            "click",
            scanSelectedRepository
        );

    document
        .getElementById("scan-all-button")
        .addEventListener(
            "click",
            scanAllFromScanPage
        );

}


async function loadRepositorySelect() {

    const select =
        document.getElementById(
            "repository-select"
        );

    try {

        const data =
            await fetchJson(API.repositories);

        const repositories =
            data.repositories || [];

        select.innerHTML = `
            <option value="">
                Select repository
            </option>
        `;

        repositories.forEach(repo => {

            const option =
                document.createElement("option");

            option.value = repo.id;

            option.textContent =
                repo.name;

            select.appendChild(option);

        });

    } catch (error) {

        showScanMessage(
            error.message,
            "error"
        );

    }

}


async function addRepository() {

    const input =
        document.getElementById("repo-url");

    const url =
        input.value.trim();

    if (!url) {

        showAddMessage(
            "Please enter a GitHub repository URL.",
            "error"
        );

        return;
    }


    const button =
        document.getElementById(
            "add-repository-button"
        );

    button.disabled = true;
    button.textContent = "Adding...";


    try {

        const data =
            await fetchJson(
                API.repositories,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        repo_url: url
                    })
                }
            );

        input.value = "";

        showAddMessage(
            `Repository "${data.repository.name}" added successfully.`,
            "success"
        );

        await loadRepositorySelect();

    } catch (error) {

        showAddMessage(
            error.message,
            "error"
        );

    } finally {

        button.disabled = false;
        button.textContent = "Add Repository";

    }

}


async function scanSelectedRepository() {

    const select =
        document.getElementById(
            "repository-select"
        );

    const repositoryId =
        select.value;

    if (!repositoryId) {

        showScanMessage(
            "Please select a repository.",
            "error"
        );

        return;
    }


    const button =
        document.getElementById(
            "scan-button"
        );

    button.disabled = true;
    button.textContent = "Scanning...";


    showScanMessage(
        "Security scan is running...",
        "info"
    );


    try {

        const data =
            await fetchJson(
                `/api/repositories/${repositoryId}/scan`,
                {
                    method: "POST"
                }
            );

        showScanMessage(
            "Security scan completed.",
            "success"
        );

        displayScanResult(data);

    } catch (error) {

        showScanMessage(
            error.message,
            "error"
        );

    } finally {

        button.disabled = false;
        button.textContent = "Scan Repository";

    }

}


async function scanAllFromScanPage() {

    const button =
        document.getElementById(
            "scan-all-button"
        );

    button.disabled = true;
    button.textContent = "Scanning...";


    showScanMessage(
        "Scanning all repositories...",
        "info"
    );


    try {

        const data =
            await fetchJson(
                API.scanAll,
                {
                    method: "POST"
                }
            );

        showScanMessage(
            `Scan All completed: ${data.successful}/${data.total} successful.`,
            "success"
        );

        await loadRepositorySelect();

    } catch (error) {

        showScanMessage(
            error.message,
            "error"
        );

    } finally {

        button.disabled = false;
        button.textContent = "Scan All";

    }

}


function displayScanResult(data) {

    const section =
        document.getElementById(
            "scan-result-section"
        );

    section.classList.remove("hidden");


    const scan =
        data.scan || data;


    document.getElementById(
        "result-repository"
    ).textContent =
        data.repository ||
        data.project?.url ||
        "";


    const status =
        data.policy ||
        scan.status ||
        "UNKNOWN";


    const statusElement =
        document.getElementById(
            "result-status"
        );

    statusElement.textContent =
        status;

    statusElement.className =
        `status-badge ${
            status === "ALLOW"
                ? "allow"
                : status === "BLOCK"
                    ? "block"
                    : "unknown"
        }`;


    document.getElementById(
        "result-score"
    ).textContent =
        data.score !== undefined
            ? `${data.score}/100`
            : "-";


    document.getElementById(
        "result-grade"
    ).textContent =
        data.grade || "-";


    document.getElementById(
        "result-findings"
    ).textContent =
        data.findings ?? 0;


    const scanners =
        data.scanner_counts || {};


    document.getElementById(
        "result-bandit"
    ).textContent =
        scanners.Bandit || 0;


    document.getElementById(
        "result-trivy"
    ).textContent =
        scanners.Trivy || 0;


    document.getElementById(
        "result-gitleaks"
    ).textContent =
        scanners.Gitleaks || 0;


    const severity =
        data.severity_counts || {};


    document.getElementById(
        "result-critical"
    ).textContent =
        severity.CRITICAL || 0;


    document.getElementById(
        "result-high"
    ).textContent =
        severity.HIGH || 0;


    document.getElementById(
        "result-medium"
    ).textContent =
        severity.MEDIUM || 0;


    document.getElementById(
        "result-low"
    ).textContent =
        severity.LOW || 0;


    const findings =
        data.findings_details || [];


    const container =
        document.getElementById(
            "result-findings-list"
        );


    if (findings.length === 0) {

        container.innerHTML = `
            <div class="empty-state">
                <h3>No security findings</h3>
                <p>This repository passed without detected findings.</p>
            </div>
        `;

        return;
    }


    container.innerHTML =
        findings
            .map(createFindingRow)
            .join("");

}


/* =========================================================
   HISTORY
========================================================= */

async function initHistoryPage() {

    const container =
        document.getElementById(
            "history-container"
        );

    try {

        const data =
            await fetchJson(API.scans);

        const scans =
            data.scans || [];


        if (scans.length === 0) {

            container.innerHTML = `
                <div class="empty-state">
                    <h3>No scan history</h3>
                    <p>Run a security scan to create history.</p>
                </div>
            `;

            return;
        }


        container.innerHTML = `
            <div class="table-wrapper">

                <table>

                    <thead>
                        <tr>
                            <th>Repository</th>
                            <th>Score</th>
                            <th>Grade</th>
                            <th>Status</th>
                            <th>Findings</th>
                            <th>Scanned At</th>
                            <th></th>
                        </tr>
                    </thead>

                    <tbody>

                        ${scans.map(scan => `

                            <tr>

                                <td>
                                    <strong>
                                        ${escapeHtml(
                                            scan.repository_name || "-"
                                        )}
                                    </strong>
                                </td>

                                <td>
                                    ${scan.score}/100
                                </td>

                                <td>
                                    <strong>
                                        ${escapeHtml(
                                            scan.grade || "-"
                                        )}
                                    </strong>
                                </td>

                                <td>
                                    <span class="status-badge ${
                                        scan.status === "ALLOW"
                                            ? "allow"
                                            : "block"
                                    }">
                                        ${escapeHtml(
                                            scan.status
                                        )}
                                    </span>
                                </td>

                                <td>
                                    ${scan.findings}
                                </td>

                                <td>
                                    ${formatDate(
                                        scan.scanned_at
                                    )}
                                </td>

                                <td>
                                    <button
                                        class="small-button"
                                        onclick="showScanFindings(${scan.id})"
                                    >
                                        Findings
                                    </button>
                                </td>

                            </tr>

                        `).join("")}

                    </tbody>

                </table>

            </div>

            <div id="history-findings"></div>
        `;

    } catch (error) {

        container.innerHTML = `
            <div class="error-box">
                ${escapeHtml(error.message)}
            </div>
        `;

    }

}


async function showScanFindings(scanId) {

    const container =
        document.getElementById(
            "history-findings"
        );

    container.innerHTML =
        `<div class="loading">Loading findings...</div>`;


    try {

        const data =
            await fetchJson(
                `/api/scans/${scanId}/findings`
            );

        const findings =
            data.findings || [];


        container.innerHTML = `
            <div class="history-detail">

                <h3>Scan #${scanId} Findings</h3>

                ${
                    findings.length === 0
                        ? `
                            <div class="empty-state">
                                No findings
                            </div>
                        `
                        : `
                            <div class="findings-list">
                                ${findings
                                    .map(createFindingRow)
                                    .join("")}
                            </div>
                        `
                }

            </div>
        `;

    } catch (error) {

        container.innerHTML = `
            <div class="error-box">
                ${escapeHtml(error.message)}
            </div>
        `;

    }

}


/* =========================================================
   POLICY
========================================================= */

function initPolicyPage() {
    // Policy page is currently display-only.
}


/* =========================================================
   FINDING UI
========================================================= */

function createFindingRow(finding) {

    return `
        <div class="finding-row">

            <div>

                <strong>
                    ${escapeHtml(
                        finding.rule_id ||
                        "Security Finding"
                    )}
                </strong>

                <span>
                    ${escapeHtml(
                        finding.scanner || "-"
                    )}
                    ·
                    ${escapeHtml(
                        finding.file || "-"
                    )}
                    ${
                        finding.line
                            ? `:${finding.line}`
                            : ""
                    }
                </span>

                <p>
                    ${escapeHtml(
                        finding.message || ""
                    )}
                </p>

            </div>

            <span class="severity-badge ${getSeverityClass(finding.severity)}">
                ${escapeHtml(
                    finding.severity || "UNKNOWN"
                )}
            </span>

        </div>
    `;

}


function getSeverityClass(severity) {

    const value =
        String(severity || "")
            .toUpperCase();

    if (value === "CRITICAL") {
        return "critical";
    }

    if (value === "HIGH") {
        return "high";
    }

    if (value === "MEDIUM") {
        return "medium";
    }

    if (value === "LOW") {
        return "low";
    }

    return "unknown";
}


/* =========================================================
   MESSAGES
========================================================= */

function showAddMessage(message, type) {

    const element =
        document.getElementById(
            "add-message"
        );

    element.innerHTML = `
        <div class="message ${type}">
            ${escapeHtml(message)}
        </div>
    `;

}


function showScanMessage(message, type) {

    const element =
        document.getElementById(
            "scan-message"
        );

    element.innerHTML = `
        <div class="message ${type}">
            ${escapeHtml(message)}
        </div>
    `;

}


/* =========================================================
   HELPERS
========================================================= */

function formatDate(value) {

    if (!value) {
        return "-";
    }

    const date =
        new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString(
        "en-GB",
        {
            dateStyle: "medium",
            timeStyle: "short"
        }
    );

}


function escapeHtml(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}


function escapeAttribute(value) {

    return escapeHtml(value);
}