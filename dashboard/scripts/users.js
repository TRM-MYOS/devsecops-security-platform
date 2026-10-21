// User Management: accounts, roles, and administrative activity.
// Loaded with defer; common.js provides the single shared state.

"use strict";

let passwordResetUser = null;
let passwordResetTrigger = null;
let passwordResetBusy = false;

async function loadUsers() {
  if (!isSuperUser()) return;
  await Promise.all([loadUserList(), loadAudit()]);
}

async function loadUserList() {
  const container = el("users-container");
  container.innerHTML = '<div class="loading">Loading users...</div>';
  try {
    const users = requireArray(await fetchJson(API.users), "users");
    state.users = new Map(users.map((user) => [String(user.id), user]));
    container.innerHTML = users.length
      ? [
          '<div class="table-wrapper">',
          '<table class="user-table">',
          "<thead>",
          "<tr>",
          '<th scope="col">User',
          "</th>",
          '<th scope="col">Role',
          "</th>",
          '<th scope="col">Status',
          "</th>",
          '<th scope="col">Created',
          "</th>",
          '<th scope="col">Access controls',
          "</th>",
          "</tr>",
          "</thead>",
          "<tbody>",
          templateText(
            users
              .map((user) =>
                [
                  "<tr>",
                  "<td>",
                  "<strong>",
                  templateText(escapeHtml(user.username)),
                  "</strong>",
                  templateText(
                    user.id === state.user.id
                      ? '<span class="you-label">You</span>'
                      : "",
                  ),
                  "</td>",
                  "<td>",
                  templateText(escapeHtml(ROLE_NAMES[user.role] || user.role)),
                  "</td>",
                  "<td>",
                  '<span class="status-badge ',
                  templateText(user.is_active ? "allow" : "unknown"),
                  '">',
                  templateText(user.is_active ? "Active" : "Disabled"),
                  "</span>",
                  "</td>",
                  "<td>",
                  templateText(escapeHtml(formatDate(user.created_at))),
                  "</td>",
                  "<td>",
                  '<div class="user-access-controls">',
                  '<select id="user-role-',
                  templateText(escapeHtml(user.id)),
                  '" aria-label="Role for ',
                  templateText(escapeHtml(user.username)),
                  '">',
                  templateText(
                    Object.entries(ROLE_NAMES)
                      .map(
                        ([role, label]) =>
                          `<option value="${role}" ${role === user.role ? "selected" : ""}>${label}</option>`,
                      )
                      .join(""),
                  ),
                  "</select>",
                  '<button type="button" class="small-button" data-action="save-user-role" data-id="',
                  templateText(escapeHtml(user.id)),
                  '" aria-label="Save role for ',
                  templateText(escapeHtml(user.username)),
                  '">Save role',
                  "</button>",
                  '<button type="button" class="',
                  templateText(
                    user.is_active ? "danger-button" : "small-button",
                  ),
                  '" data-action="toggle-user" data-id="',
                  templateText(escapeHtml(user.id)),
                  '" aria-label="',
                  templateText(user.is_active ? "Disable" : "Enable"),
                  " ",
                  templateText(escapeHtml(user.username)),
                  '">',
                  templateText(user.is_active ? "Disable" : "Enable"),
                  "</button>",
                  `<button type="button" class="small-button" data-action="reset-user-password" data-id="${escapeHtml(user.id)}" aria-label="Reset password for ${escapeHtml(user.username)}">Reset password</button>`,
                  `<button type="button" class="danger-button" data-action="delete-user" data-id="${escapeHtml(user.id)}" aria-label="Delete ${escapeHtml(user.username)}" ${user.id === state.user.id ? 'disabled title="You cannot delete your own account"' : ""}>Delete</button>`,
                  "</div>",
                  "</td>",
                  "</tr>",
                ].join(""),
              )
              .join(""),
          ),
          "</tbody>",
          "</table>",
          "</div>",
        ].join("")
      : emptyState(
          "No users available",
          "Create a user to grant access to this workspace.",
        );
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-users");
  }
}

function auditChanges(event) {
  if (event.action === "user.deleted") return "Account deleted";
  if (event.action === "user.password_reset")
    return "Password reset; sessions revoked";
  const labels = [];
  if (event.before?.role !== event.after?.role && event.after?.role)
    labels.push(
      `Role: ${event.before?.role ? (ROLE_NAMES[event.before.role] || event.before.role) + " -> " : ""}${ROLE_NAMES[event.after.role] || event.after.role}`,
    );
  if (
    typeof event.after?.is_active === "boolean" &&
    event.before?.is_active !== event.after.is_active
  )
    labels.push(event.after.is_active ? "Account enabled" : "Account disabled");
  return (
    labels.join(" / ") ||
    (["user.created", "user.bootstrap"].includes(event.action)
      ? "Account created"
      : "Account updated")
  );
}

async function loadAudit() {
  const container = el("audit-container");
  container.innerHTML = '<div class="loading">Loading activity...</div>';
  try {
    const events = requireArray(
      await fetchJson(`${API.users}/audit`),
      "events",
    );
    container.innerHTML = events.length
      ? [
          '<div class="table-wrapper">',
          '<table class="audit-table">',
          "<thead>",
          "<tr>",
          '<th scope="col">Time',
          "</th>",
          '<th scope="col">Performed by',
          "</th>",
          '<th scope="col">Account',
          "</th>",
          '<th scope="col">Action',
          "</th>",
          '<th scope="col">Change',
          "</th>",
          "</tr>",
          "</thead>",
          "<tbody>",
          templateText(
            events
              .map((event) =>
                [
                  "<tr>",
                  "<td>",
                  templateText(escapeHtml(formatDate(event.created_at))),
                  "</td>",
                  "<td>",
                  templateText(
                    escapeHtml(event.actor_username || "Bootstrap CLI"),
                  ),
                  "</td>",
                  "<td>",
                  templateText(
                    escapeHtml(
                      event.target_username || event.after?.username || "-",
                    ),
                  ),
                  "</td>",
                  "<td>",
                  templateText(escapeHtml(event.action || "-")),
                  "</td>",
                  "<td>",
                  templateText(escapeHtml(auditChanges(event))),
                  "</td>",
                  "</tr>",
                ].join(""),
              )
              .join(""),
          ),
          "</tbody>",
          "</table>",
          "</div>",
        ].join("")
      : emptyState(
          "No administrative activity",
          "Account and permission changes will appear here.",
        );
  } catch (error) {
    container.innerHTML = errorBox(error, "reload-audit");
  }
}

// Account mutations preserve the existing role checks and CSRF requests.
async function createUser(event) {
  event.preventDefault();
  if (!isSuperUser()) return;
  const button = el("create-user-button");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "Creating...";
  try {
    const data = await fetchJson(API.users, {
      method: "POST",
      body: JSON.stringify({
        username: el("new-username").value.trim(),
        password: el("new-password").value,
        role: el("new-role").value,
      }),
    });
    el("create-user-form").reset();
    setMessage(
      "user-message",
      `Account "${data.user?.username || ""}" created.`,
      "success",
    );
    await loadUsers();
  } catch (error) {
    setMessage("user-message", error.message, "error");
  } finally {
    el("new-password").value = "";
    button.disabled = false;
    button.textContent = "Create user";
  }
}

async function updateUser(id, toggleActive, button) {
  if (!isSuperUser() || button.disabled) return;
  const user = state.users.get(String(id));
  if (!user) return;
  const role = el(`user-role-${id}`)?.value;
  if (!toggleActive && role === user.role) {
    setMessage("user-message", "This user already has that role.", "info");
    return;
  }
  if (
    toggleActive &&
    user.is_active &&
    !window.confirm(
      `Disable "${user.username}"? Their active sessions will lose access.`,
    )
  )
    return;
  if (
    !toggleActive &&
    !window.confirm(
      `Change "${user.username}" to ${ROLE_NAMES[role]}? Their current sessions will be updated or revoked.`,
    )
  )
    return;
  button.disabled = true;
  try {
    await fetchJson(`${API.users}/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(
        toggleActive
          ? {
              is_active: !Boolean(user.is_active),
            }
          : {
              role,
            },
      ),
    });
    setMessage(
      "user-message",
      `Access updated for "${user.username}".`,
      "success",
    );
    if (user.id === state.user.id) await refreshIdentity();
    if (isSuperUser()) await loadUsers();
  } catch (error) {
    setMessage("user-message", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function deleteUser(id, button) {
  if (!isSuperUser() || button.disabled) return;
  const user = state.users.get(String(id));
  if (!user || user.id === state.user.id) return;
  if (
    !window.confirm(
      `Permanently delete "${user.username}"? Their sessions will be revoked. This cannot be undone.`,
    )
  )
    return;
  button.disabled = true;
  try {
    await fetchJson(`${API.users}/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    setMessage(
      "user-message",
      `Account "${user.username}" deleted.`,
      "success",
    );
    await loadUsers();
    el("refresh-users-button").focus();
  } catch (error) {
    setMessage("user-message", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function initializeUserManagement() {
  el("reset-password-form").addEventListener("submit", submitPasswordReset);
  el("reset-password-dialog").addEventListener("cancel", (event) => {
    event.preventDefault();
    closePasswordReset();
  });
}

function openPasswordReset(id, button) {
  if (!isSuperUser() || passwordResetBusy) return;
  const user = state.users.get(String(id));
  if (!user) return;
  passwordResetUser = user;
  passwordResetTrigger = button;
  el("reset-password-form").reset();
  setMessage("reset-password-message", "");
  el("reset-password-account").textContent =
    `Set a new password for "${user.username}". All sessions will be signed out.${user.id === state.user.id ? " You will need to log in again." : ""}`;
  el("reset-password-dialog").showModal();
  el("reset-password").focus();
}

function closePasswordReset() {
  if (passwordResetBusy) return;
  el("reset-password-form").reset();
  setMessage("reset-password-message", "");
  passwordResetUser = null;
  el("reset-password-dialog").close();
  const trigger = passwordResetTrigger;
  passwordResetTrigger = null;
  (trigger?.isConnected ? trigger : el("refresh-users-button"))?.focus();
}

async function submitPasswordReset(event) {
  event.preventDefault();
  if (!isSuperUser() || !passwordResetUser || passwordResetBusy) return;
  const password = el("reset-password").value;
  const confirmation = el("confirm-reset-password").value;
  if (Array.from(password).length < 8 || Array.from(password).length > 128) {
    setMessage(
      "reset-password-message",
      "Password must contain between 8 and 128 characters.",
      "error",
    );
    return;
  }
  if (password !== confirmation) {
    setMessage("reset-password-message", "Passwords do not match.", "error");
    return;
  }
  const user = passwordResetUser;
  const button = el("save-password-button");
  passwordResetBusy = true;
  button.disabled = true;
  button.textContent = "Resetting...";
  el("cancel-password-button").disabled = true;
  try {
    await fetchJson(`${API.users}/${encodeURIComponent(user.id)}/password`, {
      method: "POST",
      body: JSON.stringify({ password, confirm_password: confirmation }),
    });
    passwordResetBusy = false;
    closePasswordReset();
    if (user.id === state.user.id) {
      state.user = null;
      state.csrf = null;
      location.replace("/dashboard/login.html");
      return;
    }
    setMessage(
      "user-message",
      `Password reset for "${user.username}". Their sessions have been revoked.`,
      "success",
    );
    await loadUsers();
    el("refresh-users-button").focus();
  } catch (error) {
    el("reset-password-form").reset();
    setMessage("reset-password-message", error.message, "error");
    el("reset-password").focus();
  } finally {
    passwordResetBusy = false;
    button.disabled = false;
    button.textContent = "Reset password";
    el("cancel-password-button").disabled = false;
  }
}
