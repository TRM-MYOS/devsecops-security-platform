// Security Policy: display the server-provided policy and scoring rules.
// Loaded with defer; common.js provides the single shared state.

"use strict";

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
    container.innerHTML = [
      '<section class="content-section">',
      '<div class="section-header">',
      "<div>",
      "<h2>Security gate rules",
      "</h2>",
      "<p>Loaded from the active policy configuration.",
      "</p>",
      "</div>",
      '<div class="actions">',
      '<span class="status-badge unknown">Read only',
      "</span>",
      '<button type="button" class="secondary-button" data-action="reload-policy">Refresh',
      "</button>",
      "</div>",
      "</div>",
      '<div class="policy-summary">',
      '<div class="policy-number">',
      "<span>Minimum score",
      "</span>",
      "<strong>",
      templateText(escapeHtml(minimum)),
      "<span> / 100",
      "</span>",
      "</strong>",
      "</div>",
      "<p>",
      templateText(
        blockLevels.length
          ? `Any ${escapeHtml(blockLevels.join(" or "))} finding blocks the repository. `
          : "No severity automatically blocks under the configured policy. ",
      ),
      "The security gate also blocks when the total score falls below ",
      templateText(escapeHtml(minimum)),
      ".",
      "</p>",
      "</div>",
      '<div class="policy-grid">',
      templateText(
        levels
          .map((level) => {
            const action = rules[level.toLowerCase()] || rules[level];
            const blocks = String(action || "").toUpperCase() === "BLOCK";
            const severityClass = [
              "CRITICAL",
              "HIGH",
              "MEDIUM",
              "LOW",
            ].includes(level)
              ? level.toLowerCase()
              : "unknown";
            return [
              '<article class="policy-card ',
              templateText(severityClass),
              '">',
              '<span class="severity-badge ',
              templateText(severityClass),
              '">',
              templateText(escapeHtml(level)),
              "</span>",
              "<h3>",
              templateText(blocks ? "Always blocks" : "Affects the score"),
              "</h3>",
              "<p>Deducts ",
              templateText(escapeHtml(penalties[level] ?? 0)),
              " points per finding. ",
              templateText(
                blocks
                  ? "Blocks the security gate regardless of score."
                  : `The gate can block when the total score falls below ${escapeHtml(minimum)}.`,
              ),
              "</p>",
              '<p class="policy-action">Configured action: ',
              templateText(escapeHtml(action || "No severity action")),
              "</p>",
              "</article>",
            ].join("");
          })
          .join(""),
      ),
      "</div>",
      "</section>",
      '<section class="two-column">',
      '<div class="content-section">',
      '<div class="section-header">',
      "<div>",
      "<h2>How scoring works",
      "</h2>",
      "<p>Every scan starts at 100 points; the minimum possible score is zero.",
      "</p>",
      "</div>",
      "</div>",
      '<div class="score-formula">100 - severity penalties = security score',
      "</div>",
      '<p class="muted">A grade describes the score. ALLOW or BLOCK describes the security policy decision.',
      "</p>",
      '<div class="grade-scale">',
      templateText(gradeScale),
      "</div>",
      "</div>",
      '<div class="content-section">',
      '<div class="section-header">',
      "<div>",
      "<h2>From scan to decision",
      "</h2>",
      "<p>The same process applies to every repository.",
      "</p>",
      "</div>",
      "</div>",
      '<ol class="process-list">',
      "<li>GitHub Actions checks out the pushed commit",
      "</li>",
      "<li>Run Bandit, Trivy, and Gitleaks",
      "</li>",
      "<li>Normalize findings and calculate a score",
      "</li>",
      "<li>Apply severity rules and the minimum score",
      "</li>",
      "<li>Import the Central decision and commit metadata into the Dashboard",
      "</li>",
      "</ol>",
      '<div class="message info">A scanner failure is an execution error. It is not a clean result or an ALLOW decision.',
      "</div>",
      "</div>",
      "</section>",
    ].join("");
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-policy");
  }
}
