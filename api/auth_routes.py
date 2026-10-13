"""Browser-session login and Super User account administration."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from auth import service
from auth.web import clear_session_cookie, set_session_cookie


router = APIRouter(prefix="/api", tags=["Authentication"])
Role = Literal["superuser", "operator", "viewer"]


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128)


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    role: Role


class UpdateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    is_active: StrictBool | None = None


@router.get("/auth/csrf")
def csrf(request: Request, response: Response):
    settings = request.app.state.auth_settings
    session = request.state.auth_session
    if session is None:
        session = service.create_session(ttl_seconds=settings.session_ttl_seconds)
        set_session_cookie(response, session["token"], settings)
    return {"csrf_token": session["csrf_token"]}


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    settings = request.app.state.auth_settings
    peer_ip = request.client.host if request.client else "unknown"
    try:
        user = service.authenticate(
            payload.username, payload.password, peer_ip,
            max_attempts=settings.login_max_attempts,
            window_seconds=settings.login_window_seconds,
        )
    except service.RateLimitError as error:
        raise HTTPException(
            status_code=429, detail=str(error), headers={"Retry-After": str(error.retry_after)}
        ) from error
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    try:
        session = service.create_session(
            user_id=user["id"], ttl_seconds=settings.session_ttl_seconds,
            replacing_token=request.cookies.get(settings.cookie_name),
        )
    except ValueError as error:
        raise HTTPException(status_code=401, detail="Invalid username or password") from error
    set_session_cookie(response, session["token"], settings)
    return {"user": service.get_user(user["id"]), "csrf_token": session["csrf_token"]}


@router.get("/auth/me")
def me(request: Request):
    return {
        "user": request.state.user,
        "csrf_token": request.state.auth_session["csrf_token"],
    }


@router.post("/auth/logout")
def logout(request: Request, response: Response):
    settings = request.app.state.auth_settings
    service.revoke_session(request.cookies.get(settings.cookie_name))
    clear_session_cookie(response, settings)
    return {"message": "Logged out"}


@router.get("/users")
def users():
    return {"users": service.list_users()}


@router.post("/users", status_code=201)
def create_user(payload: CreateUserRequest, request: Request):
    try:
        user = service.create_user(
            payload.username, payload.password, payload.role, actor_id=request.state.user["id"]
        )
    except service.ConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"user": user}


@router.get("/users/audit")
def audit():
    return {"events": service.list_audit_events()}


@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: UpdateUserRequest, request: Request, response: Response):
    changes = payload.model_dump(exclude_unset=True)
    try:
        user = service.update_user(user_id, changes, actor_id=request.state.user["id"])
    except service.ConflictError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user_id == request.state.user["id"] and any(
        user[key] != request.state.user[key] for key in changes
    ):
        clear_session_cookie(response, request.app.state.auth_settings)
    return {"user": user}
