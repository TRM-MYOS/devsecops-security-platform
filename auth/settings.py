"""Explicit settings for cookie sessions and trusted browser origins."""

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


def _positive_integer(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class Settings:
    cookie_secure: bool
    allowed_origins: tuple[str, ...]
    session_ttl_seconds: int = 28800
    login_max_attempts: int = 5
    login_window_seconds: int = 900
    cookie_name: str = "devsecops_session"
    environment: str = "development"

    @classmethod
    def from_environment(cls):
        environment = os.environ.get("DEVSECOPS_ENV", "development").lower()
        if environment not in {"development", "production"}:
            raise ValueError("DEVSECOPS_ENV must be development or production")
        production = environment == "production"
        secure_value = os.environ.get(
            "DEVSECOPS_COOKIE_SECURE", "true" if production else "false"
        ).lower()
        if secure_value not in {"true", "false", "1", "0"}:
            raise ValueError("DEVSECOPS_COOKIE_SECURE must be true or false")
        cookie_secure = secure_value in {"true", "1"}
        if production and not cookie_secure:
            raise ValueError("Production requires DEVSECOPS_COOKIE_SECURE=true and HTTPS")

        default_origins = "" if production else "http://127.0.0.1:8000,http://localhost:8000"
        origins = tuple(
            origin.strip()
            for origin in os.environ.get("DEVSECOPS_ALLOWED_ORIGINS", default_origins).split(",")
            if origin.strip()
        )
        for origin in origins:
            parts = urlsplit(origin)
            if (
                parts.scheme not in {"http", "https"}
                or not parts.hostname
                or "*" in origin
                or parts.username
                or parts.password
                or parts.path
                or parts.query
                or parts.fragment
            ):
                raise ValueError("DEVSECOPS_ALLOWED_ORIGINS must contain explicit HTTP(S) origins")
        return cls(
            environment=environment,
            cookie_secure=cookie_secure,
            allowed_origins=origins,
            session_ttl_seconds=_positive_integer("DEVSECOPS_SESSION_TTL_SECONDS", 28800),
            login_max_attempts=_positive_integer("DEVSECOPS_LOGIN_MAX_ATTEMPTS", 5),
            login_window_seconds=_positive_integer("DEVSECOPS_LOGIN_WINDOW_SECONDS", 900),
        )
