// User Management: accounts, roles, and administrative activity.
// Loaded with defer; common.js provides the single shared state.

"use strict";

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
  return labels.join(" / ") || "Account created";
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
