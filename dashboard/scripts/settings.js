// Super User connection settings. Key contents and tokens never enter this page.
"use strict";

const OWNER_FIELDS = [
  "owner",
  "app_id",
  "installation_id",
  "private_key_path",
  "workflow",
];
let ownerSettingsBusy = false;

function ownerSettingsPayload() {
  return Object.fromEntries(
    OWNER_FIELDS.map((field) => [field, el(`setting-${field}`).value.trim()]),
  );
}

function ownerSettingsErrors(errors = {}) {
  for (const field of OWNER_FIELDS) {
    const input = el(`setting-${field}`);
    input.setAttribute("aria-invalid", String(Boolean(errors[field])));
    el(`error-${field}`).textContent = errors[field] || "";
  }
}

function showOwnerSettings(data) {
  for (const field of OWNER_FIELDS)
    el(`setting-${field}`).value = data.settings[field] || "";
  el("settings-source").textContent =
    data.source === "database"
      ? `Saved in database · Updated ${formatDate(data.updated_at)}`
      : "Using Environment / .env and default values. No database settings saved yet.";
}

async function initializeOwnerSettings() {
  el("owner-settings-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void submitOwnerSettings(true);
  });
  el("test-owner-connection").addEventListener(
    "click",
    () => void submitOwnerSettings(false),
  );
  el("owner-settings-form").addEventListener("input", () => {
    ownerSettingsErrors();
    setMessage(
      "settings-message",
      "Settings edited. Test or save to verify this connection.",
    );
  });
  try {
    showOwnerSettings(await fetchJson("/api/owner-settings"));
    el("owner-settings-fields").disabled = false;
  } catch (error) {
    setMessage("settings-message", error.message, "error");
  }
}

async function submitOwnerSettings(save) {
  if (ownerSettingsBusy || !isSuperUser()) return;
  const form = el("owner-settings-form");
  if (!form.reportValidity()) return;
  ownerSettingsBusy = true;
  const payload = ownerSettingsPayload();
  ownerSettingsErrors();
  el("owner-settings-fields").disabled = true;
  el("owner-settings-form").setAttribute("aria-busy", "true");
  setMessage(
    "settings-message",
    save
      ? "Verifying connection and saving settings. Waiting for any active synchronization to finish..."
      : "Testing the entered connection. Settings have not been saved...",
  );
  try {
    const result = await fetchJson(
      `/api/owner-settings${save ? "" : "/test"}`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
    if (save) {
      showOwnerSettings(result);
      setMessage(
        "settings-message",
        "Settings saved. The next sync will use this connection; no Backend restart needed. Previous results remain in Scan History.",
        "success",
      );
      await initializeGitHubMonitor(false);
    } else {
      setMessage(
        "settings-message",
        `${result.message} Accessible repositories: ${result.repositories_accessible}. Settings have not been saved.`,
        "success",
      );
    }
  } catch (error) {
    ownerSettingsErrors(error.fields);
    setMessage(
      "settings-message",
      error.fields?.connection || error.message,
      "error",
    );
    const first = OWNER_FIELDS.find((field) => error.fields?.[field]);
    // Focus once disabled fields have been re-enabled below.
    if (first) form.dataset.errorFocus = first;
  } finally {
    ownerSettingsBusy = false;
    el("owner-settings-fields").disabled = false;
    form.setAttribute("aria-busy", "false");
    if (form.dataset.errorFocus) {
      el(`setting-${form.dataset.errorFocus}`).focus();
      delete form.dataset.errorFocus;
    }
  }
}
