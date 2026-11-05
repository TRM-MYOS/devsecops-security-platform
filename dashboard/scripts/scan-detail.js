"use strict";

async function loadScanDetail({ background = false } = {}) {
  if (state.detailLoading) return;
  state.detailLoading = true;
  const id = new URLSearchParams(location.search).get("scan");
  const container = el("history-detail");
  try {
    if (!id) throw new ApiError("No scan selected", 404);
    const scan = (await fetchJson(`${API.scans}/${encodeURIComponent(id)}`))
      .scan;
    if (!scan) throw new ApiError("Scan not found", 404);
    // Recheck access on every refresh, but keep this recorded commit/attempt selected.
    if (
      background &&
      state.selectedDetail &&
      JSON.stringify(state.selectedDetail.scan) === JSON.stringify(scan)
    )
      return;
    const findings =
      scan.report_available === false
        ? []
        : requireArray(
            await fetchJson(
              `${API.scans}/${encodeURIComponent(scan.id)}/findings`,
            ),
            "findings",
          );
    state.selectedDetail = { scan, findings };
    updateMarkup(
      el("history-scope"),
      historyBreadcrumb(
        { id: scan.repository_id, name: scan.repository_name },
        scan.github?.branch ?? null,
        scan.id,
      ),
    );
    container.innerHTML = detailView(scan, findings);
    renderDetailFindings();
  } catch (error) {
    state.selectedDetail = null;
    state.findingDisclosure.clear();
    el("history-scope").innerHTML = "";
    container.innerHTML = `${closeDetailsButton()}${errorBox(error, "reload-detail")}`;
  } finally {
    state.detailLoading = false;
  }
}

document.addEventListener("input", (event) => {
  if (event.target.id !== "detail-file-filter") return;
  state.detailFilters.file = event.target.value;
  state.detailPage = 1;
  renderDetailFindings();
});
document.addEventListener("change", (event) => {
  const fields = {
    "detail-scanner-filter": "scanner",
    "detail-sort": "sort",
    "detail-severity-filter": "severity",
  };
  const key = fields[event.target.id];
  if (!key) return;
  state.detailFilters[key] = event.target.value;
  state.detailPage = 1;
  renderDetailFindings();
});
document.addEventListener(
  "toggle",
  (event) => {
    if (
      event.target.matches?.("details[data-finding-key]") &&
      event.target.isConnected
    )
      state.findingDisclosure.set(
        event.target.dataset.findingKey,
        event.target.open,
      );
  },
  true,
);
