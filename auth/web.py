"""Central access checks for API endpoints and protected dashboard pages."""

import posixpath
from urllib.parse import quote

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse

from auth.service import get_session, valid_csrf


READ_ROLES = frozenset({"superuser", "operator", "viewer"})
WRITE_ROLES = frozenset({"superuser", "operator"})


def _error(detail: str, status: int):
    return JSONResponse(
        {"detail": detail}, status_code=status,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        method = request.method
        settings = request.app.state.auth_settings
        request.state.auth_session = None
        request.state.user = None
        protected_api = path.startswith("/api/") or path == "/scan"
        dashboard_page = path == "/dashboard" or path.startswith("/dashboard/")
        # StaticFiles normalizes separators and dot segments before looking up a file.
        # Use the same canonical target for page-specific authorization on Windows.
        dashboard_target = posixpath.normpath(path.replace("\\", "/")).casefold()
        public_page = path in {
            "/dashboard/login.html", "/dashboard/style.css", "/dashboard/app.js"
        }
        public_auth = path in {"/api/auth/csrf", "/api/auth/login"}

        if method == "OPTIONS":
            return await call_next(request)
        if protected_api or (dashboard_page and not public_page):
            token = request.cookies.get(settings.cookie_name)
            session = await run_in_threadpool(get_session, token)
            user = session["user"] if session else None
            request.state.auth_session = session
            request.state.user = user
            if not public_auth and user is None:
                if dashboard_page:
                    destination = quote(path, safe="/")
                    response = RedirectResponse(f"/dashboard/login.html?next={destination}", status_code=303)
                else:
                    response = _error("Authentication required", 401)
                response.headers["Cache-Control"] = "no-store"
                response.headers["X-Content-Type-Options"] = "nosniff"
                return response

            if not public_auth:
                roles = READ_ROLES
                if path.startswith("/api/users") or dashboard_target == "/dashboard/users.html":
                    roles = frozenset({"superuser"})
                elif method == "DELETE":
                    roles = frozenset({"superuser"})
                elif method not in {"GET", "HEAD"} and path != "/api/auth/logout":
                    roles = WRITE_ROLES
                if user["role"] not in roles:
                    return _error("Insufficient permissions", 403)

            if method not in {"GET", "HEAD"}:
                # Check role before CSRF, while still requiring CSRF for login.
                if not valid_csrf(session, request.headers.get("X-CSRF-Token")):
                    return _error("Invalid or missing CSRF token", 403)
                origin = request.headers.get("origin")
                own_origin = f"{request.url.scheme}://{request.url.netloc}"
                if origin and origin != own_origin and origin not in settings.allowed_origins:
                    return _error("Untrusted request origin", 403)

        # A small, flat dashboard has a fixed set of public assets and HTML pages.
        # Reject filesystem aliases (including Windows short names/ADS) altogether.
        dashboard_paths = {
            "/dashboard", "/dashboard/", "/dashboard/index.html",
            "/dashboard/login.html", "/dashboard/scan.html", "/dashboard/history.html",
            "/dashboard/policy.html", "/dashboard/users.html",
            "/dashboard/style.css", "/dashboard/app.js",
        }
        if dashboard_page and path not in dashboard_paths:
            return _error("Page not found", 404)

        response = await call_next(request)
        if protected_api or dashboard_page:
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


def set_session_cookie(response, token, settings):
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response, settings):
    response.delete_cookie(
        key=settings.cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
