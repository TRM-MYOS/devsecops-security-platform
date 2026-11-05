"use strict";
let membersBusy = false;
let memberRepository = null;
let memberRows = new Map();
function renderMemberNavigation(repo = null) {
  const from = memberReturnInfo(
    new URLSearchParams(location.search).get("return"),
  );
  const back = el("member-back-link");
  back.href = from.href;
  back.textContent = `Back to ${from.label}`;
  el("member-origin-tag").textContent = from.direct
    ? "Direct link"
    : `From ${from.label}`;
  el("member-breadcrumbs").innerHTML =
    `<a href="index.html">${uiIcon("home")}Dashboard</a>${from.label !== "Dashboard" ? `<span aria-hidden="true">&rsaquo;</span><a href="${escapeHtml(from.href)}">${escapeHtml(from.label)}</a>` : ""}${repo ? `<span aria-hidden="true">&rsaquo;</span><a href="${historyLink(repo)}">${escapeHtml(repo.name)}</a>` : ""}<span aria-hidden="true">&rsaquo;</span><span aria-current="page">Members</span>`;
}
async function initializeMembers() {
  renderMemberNavigation();
  el("add-member-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void addMember();
  });
  el("member-search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void findMembers();
  });
  await loadMembers();
}
async function loadMembers({ background = false } = {}) {
  if (membersBusy) return;
  const id = new URLSearchParams(location.search).get("repository");
  try {
    const repo = (
      await fetchJson(`${API.repositories}/${encodeURIComponent(id)}`)
    ).repository;
    const rows = requireArray(
      await fetchJson(`${API.repositories}/${encodeURIComponent(id)}/members`),
      "members",
    );
    memberRepository = repo;
    memberRows = new Map(rows.map((row) => [String(row.id), row]));
    renderMemberNavigation(repo);
    el("member-repository-name").textContent = repo.name;
    el("member-repository-actions").innerHTML =
      `<a class="secondary-button" href="${historyLink(repo)}">View history</a>${!isSuperUser() ? `<button type="button" class="secondary-button" data-action="leave-repository" data-id="${repo.id}" data-name="${escapeHtml(repo.name)}">Leave repository</button>` : ""}`;
    el("member-forms").hidden = false;
    updateMarkup(
      el("members-list"),
      rows.length
        ? `<div class="table-wrapper"><table><thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows.map((row) => `<tr><td>${escapeHtml(row.username)}</td><td>${escapeHtml(ROLE_NAMES[row.role] || row.role)}</td><td>${row.is_active ? "Active" : "Disabled"}</td><td>${isSuperUser() || row.role === "viewer" ? `<button type="button" class="danger-button" data-action="remove-member" data-id="${row.id}">Remove member</button>` : "Super User required"}</td></tr>`).join("")}</tbody></table></div>`
        : emptyState(
            "No members",
            "Super Users have access without membership.",
          ),
    );
    if (!background) await findMembers();
  } catch (error) {
    memberRepository = null;
    memberRows.clear();
    renderMemberNavigation();
    el("member-forms").hidden = true;
    el("member-repository-name").textContent = "Repository unavailable";
    el("member-repository-actions").innerHTML = "";
    el("member-candidate").replaceChildren();
    el("members-list").innerHTML = errorBox(error, "reload-members");
  }
}
async function findMembers() {
  if (!memberRepository || membersBusy) return;
  try {
    const data = await fetchJson(
      `${API.repositories}/${memberRepository.id}/member-candidates?q=${encodeURIComponent(el("member-search").value)}`,
    );
    el("member-candidate").replaceChildren(new Option("Select a user", ""));
    requireArray(data, "users").forEach((user) =>
      el("member-candidate").add(
        new Option(
          `${user.username} (${ROLE_NAMES[user.role]})`,
          String(user.id),
        ),
      ),
    );
  } catch (error) {
    el("member-candidate").replaceChildren();
    setMessage("member-message", error.message, "error");
  }
}
async function addMember() {
  if (membersBusy || !memberRepository) return;
  const id = Number(el("member-candidate").value);
  if (!Number.isInteger(id) || id <= 0) return;
  membersBusy = true;
  el("add-member-button").disabled = true;
  try {
    await fetchJson(`${API.repositories}/${memberRepository.id}/members`, {
      method: "POST",
      body: JSON.stringify({ user_id: id }),
    });
    setMessage("member-message", "Member added.", "success");
  } catch (error) {
    setMessage("member-message", error.message, "error");
  } finally {
    membersBusy = false;
    el("add-member-button").disabled = false;
    await loadMembers();
  }
}
async function removeMember(id, button) {
  if (membersBusy || !memberRepository) return;
  const user = memberRows.get(String(id));
  if (!user) return;
  if (
    !window.confirm(
      `Remove "${user.username}" from "${memberRepository.name}"? Their account and scan history will remain.`,
    )
  )
    return;
  membersBusy = true;
  button.disabled = true;
  try {
    await fetchJson(
      `${API.repositories}/${memberRepository.id}/members/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    );
    setMessage("member-message", "Member removed.", "success");
  } catch (error) {
    setMessage("member-message", error.message, "error");
  } finally {
    membersBusy = false;
    button.disabled = false;
    await loadMembers();
  }
}
