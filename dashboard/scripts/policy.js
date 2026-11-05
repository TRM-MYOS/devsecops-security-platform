// Security Policy: display the server-provided policy and scoring rules.
// Loaded with defer; common.js provides the single shared state.

"use strict";

let policyVersion = null;
let policySavedMinimum = null;
let policyPublicationBusy = false;
let policyDelivery = "central-repository";

function policyActivationText(data) {
  const settings = data.settings || {};
  return (
    {
      observed_in_report:
        "This policy version has been observed in an imported Runner report. Older scans retain their original policy.",
      awaiting_runner_report:
        "Signed publication is configured locally. Awaiting a Runner report for this version; GitHub deployment has not been confirmed.",
      published_awaiting_report:
        "Published in Central main at the last check; awaiting an imported Runner report with this version.",
      awaiting_merge:
        "A legacy pull request is pending. It has not applied this threshold. Apply directly below and close the old pull request manually.",
      publish_failed:
        "Publication failed. The saved threshold has not been confirmed in Central. Check the error and retry the same version.",
      publication_closed:
        "The publication pull request was closed without applying this threshold. Save a new version to submit again.",
      publication_superseded:
        "This publication was superseded in Central. Save and publish a new version if this threshold is still required.",
      publishing:
        "Publication is being prepared. Check GitHub status before retrying.",
    }[settings.activation] ||
    `Not applied to GitHub. Apply a threshold to update Central main. Local file baseline: ${data.central_file_minimum}/100.`
  );
}

function policyPublicationControls(settings) {
  const publication = settings.publication;
  const pr = publication?.pr_url;
  const link =
    typeof pr === "string" &&
    /^https:\/\/github\.com\/TRM-MYOS\/devsecops-security-platform\/pull\/[1-9][0-9]*$/.test(
      pr,
    )
      ? `<a class="secondary-button" href="${escapeHtml(pr)}" target="_blank" rel="noopener noreferrer">Legacy pull request ${uiIcon("external")}</a>`
      : "";
  return `<div class="policy-publication"><p>Apply commits only the policy file directly to Central main through the GitHub App. It does not create a pull request or start a scan. New scans use the applied version; existing results stay unchanged. Branch rules are respected.</p>${publication?.updated_at ? `<p class="muted">Last publication update: ${escapeHtml(formatDate(publication.updated_at))}${publication.commit_sha ? ` · Central commit: <code>${escapeHtml(publication.commit_sha.slice(0, 12))}</code>` : ""}</p>` : ""}${publication?.error ? `<p class="message warning">${escapeHtml(publication.error)}</p>` : ""}${link ? `<p class="message warning">An older policy PR still exists. Close it manually if no longer needed; do not merge an obsolete threshold.</p>` : ""}<div class="actions">${link}${isSuperUser() && settings.delivery !== "signed-https" ? `<button id="publish-policy-button" type="button" class="secondary-button" ${!settings.updated_at || policyPublicationBusy || ["applied", "merged", "superseded"].includes(publication?.state) ? "disabled" : ""}>${publication?.state === "failed" ? "Retry apply" : "Apply saved threshold"}</button>${publication ? `<button id="check-policy-publication" type="button" class="secondary-button" ${policyPublicationBusy ? "disabled" : ""}>Check GitHub status</button>` : ""}` : ""}</div></div>`;
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
    container.innerHTML = [
      '<section class="content-section">',
      '<div class="section-header">',
      "<div>",
      "<h2>Policy rules and requested threshold",
      "</h2>",
      "<p>Check the Runner activation status above before using this threshold as evidence.",
      "</p>",
      "</div>",
      '<div class="actions">',
      '<span class="status-badge unknown">',
      isSuperUser() ? "Super User settings" : "Read only",
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
      "With this policy applied, the gate blocks when the total score falls below ",
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
                  : `When applied, scores below ${escapeHtml(minimum)} block the gate.`,
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
    const settings = data.settings || {};
    policyVersion = settings.version;
    policySavedMinimum = minimum;
    policyDelivery = settings.delivery || "central-repository";
    const status = policyActivationText(data);
    container.insertAdjacentHTML(
      "afterbegin",
      `<section class="content-section"><h2>Global passing threshold</h2><p class="message info">${escapeHtml(status)}</p><p class="muted">Version: <code>${escapeHtml(settings.version || "Legacy")}</code></p>${isSuperUser() ? `<form id="policy-settings-form" class="inline-form"><label>Minimum passing score<input id="policy-minimum" type="number" min="0" max="100" step="1" required value="${escapeHtml(minimum)}" /></label><button id="save-policy-button" type="submit" class="primary-button" ${policyPublicationBusy ? "disabled" : ""}>${settings.delivery === "signed-https" ? "Save signed policy" : "Apply policy"}</button></form>` : "<p>Only a Super User can change the passing threshold.</p>"}${policyPublicationControls(settings)}<div id="policy-message" class="message-region" aria-live="polite"></div></section>`,
    );
    el("policy-settings-form")?.addEventListener("submit", savePolicy);
    el("publish-policy-button")?.addEventListener(
      "click",
      () => void publishPolicy(),
    );
    el("check-policy-publication")?.addEventListener(
      "click",
      () => void publishPolicy(true),
    );
  } catch (error) {
    policyVersion = null;
    container.innerHTML = errorBox(error, "reload-policy");
  }
}

async function savePolicy(event) {
  event.preventDefault();
  if (!isSuperUser() || policyPublicationBusy) return;
  const button = el("save-policy-button");
  if (button.disabled) return;
  const minimum = Number(el("policy-minimum").value);
  if (!Number.isInteger(minimum) || minimum < 0 || minimum > 100) return;
  if (
    !window.confirm(
      policyDelivery === "signed-https"
        ? `Save a signed passing score of ${minimum}/100? HIGH/CRITICAL and historical results stay unchanged.`
        : `Apply a passing score of ${minimum}/100 directly to Central main? This creates a policy commit, not a pull request. New scans use this version. HIGH/CRITICAL and historical results stay unchanged.`,
    )
  )
    return;
  policyPublicationBusy = true;
  ["save-policy-button", "publish-policy-button", "check-policy-publication"].forEach(id => {
    if (el(id)) el(id).disabled = true;
  });
  let failure;
  let saved = false;
  try {
    const data = await fetchJson("/api/policy", {
      method: "PATCH",
      body: JSON.stringify({ minimum_score: minimum }),
    });
    saved = true;
    if (data.settings?.delivery !== "signed-https") {
      if (!data.settings?.version) throw new ApiError("The saved Policy version is missing. Reload before applying.");
      await fetchJson("/api/policy/publish", {
        method: "POST", body: JSON.stringify({version: data.settings.version}),
      });
    }
  } catch (error) {
    failure = error;
  } finally {
    policyPublicationBusy = false;
    button.disabled = false;
    await loadPolicy();
    setMessage("policy-message", failure
      ? `${saved ? "Threshold saved locally, but apply was not confirmed. " : ""}${failure.message}`
      : "Policy saved. Check the activation status above; a Runner report is required to confirm use by a scan.",
      failure ? "error" : "success");
  }
}

async function publishPolicy(check = false) {
  if (!isSuperUser() || policyPublicationBusy || !policyVersion) return;
  if (
    !check &&
    !window.confirm(
      `Apply the saved threshold of ${policySavedMinimum}/100 directly to Central main without a pull request? This creates a policy commit. New scans use this version; HIGH/CRITICAL and historical results stay unchanged.`,
    )
  )
    return;
  policyPublicationBusy = true;
  [
    "publish-policy-button",
    "check-policy-publication",
    "save-policy-button",
  ].forEach((id) => {
    if (el(id)) el(id).disabled = true;
  });
  let error;
  try {
    await fetchJson(
      check ? "/api/policy/publication/check" : "/api/policy/publish",
      {
        method: "POST",
        body: JSON.stringify({ version: policyVersion }),
      },
    );
  } catch (failure) {
    error = failure;
  } finally {
    policyPublicationBusy = false;
    await loadPolicy();
    setMessage(
      "policy-message",
      error
        ? error.message
        : check
          ? "Publication status refreshed."
          : "Apply checked. Review the Central activation status above; new scans must confirm the Policy version.",
      error ? "error" : "success",
    );
  }
}
