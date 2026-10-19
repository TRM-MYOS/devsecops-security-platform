// Login page: session initialization and login form.
// Loaded with defer; common.js provides the single shared state.

"use strict";

function loginDestination() {
  const next = new URLSearchParams(location.search).get("next");
  if (!SAFE_PAGES.has(next)) return "/dashboard/";
  if (next === "/dashboard/users.html" && !isSuperUser()) return "/dashboard/";
  return next;
}

async function initLogin() {
  el("login-button").disabled = true;
  void updateHealth();
  el("login-form").addEventListener("submit", login);
  try {
    const data = await fetchJson(`${API.auth}/me`, {
      allowUnauthorized: true,
    });
    if (data.user && ROLE_NAMES[data.user.role]) {
      state.user = data.user;
      location.replace(loginDestination());
      return;
    }
  } catch (error) {
    if (error.status !== 401)
      setMessage("login-message", error.message, "error");
  }
  try {
    const data = await fetchJson(`${API.auth}/csrf`, {
      allowUnauthorized: true,
    });
    if (!data.csrf_token)
      throw new ApiError("Could not initialize the login session. Try again.");
    state.csrf = data.csrf_token;
  } catch (error) {
    setMessage("login-message", error.message, "error");
  } finally {
    el("login-button").disabled = false;
  }
}

async function login(event) {
  event.preventDefault();
  const button = el("login-button");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "Logging in...";
  setMessage("login-message", "");
  try {
    if (!state.csrf) {
      const session = await fetchJson(`${API.auth}/csrf`, {
        allowUnauthorized: true,
      });
      state.csrf = session.csrf_token;
      if (!state.csrf)
        throw new ApiError(
          "Could not initialize the login session. Try again.",
        );
    }
    const data = await fetchJson(`${API.auth}/login`, {
      method: "POST",
      body: JSON.stringify({
        username: el("username").value.trim(),
        password: el("password").value,
      }),
      allowUnauthorized: true,
    });
    if (!data.user || !ROLE_NAMES[data.user.role])
      throw new ApiError(
        "The service returned an invalid login response. Try again.",
      );
    state.user = data.user;
    state.csrf = data.csrf_token;
    el("password").value = "";
    location.replace(loginDestination());
  } catch (error) {
    setMessage("login-message", error.message, "error");
    el("password").value = "";
    el("password").focus();
    try {
      state.csrf =
        (
          await fetchJson(`${API.auth}/csrf`, {
            allowUnauthorized: true,
          })
        ).csrf_token || null;
    } catch {
      state.csrf = null;
    }
  } finally {
    button.disabled = false;
    button.textContent = "Log in";
  }
}
