"""Settings, read once from environment variables.

Every variable is documented in .env.example; the reasoning behind the
defaults is in docs/decisions.md. Validation happens here, at startup, so a
misconfiguration fails the container immediately instead of surfacing as a
confusing error on a user's first tool call.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

AuthMode = Literal["resource", "proxy", "wordpress"]

# Callback URLs ChatGPT's connectors use (the same defaults as the "Enable
# Abilities for MCP" plugin), Claude's, and loopback for local clients
# (Claude Code, MCP Inspector). A loopback pattern without a port matches any
# port (fastmcp.server.auth.redirect_validation).
DEFAULT_REDIRECT_ALLOWLIST = (
    "https://chatgpt.com/connector/oauth/*",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chatgpt.com/backend-api/aip/connectors/links/oauth/callback",
    "https://chat.openai.com/connector_platform_oauth_redirect",
    "https://chat.openai.com/aip/*/oauth/callback",
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
)

# Client ID Metadata Documents (claude.ai identifies itself by URL instead
# of registering, D9).
DEFAULT_CIMD_ALLOWLIST = (
    "https://claude.ai/oauth/mcp-oauth-client-metadata",
    "https://claude.ai/oauth/claude-code-client-metadata",
)


class ConfigError(ValueError):
    """Raised for missing or invalid settings."""


def _require(env: dict[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise ConfigError(f"{key} is required (see .env.example).")
    return value


def _choice(env: dict[str, str], key: str, default: str, allowed: tuple[str, ...]) -> str:
    value = (env.get(key, "").strip() or default).lower()
    if value not in allowed:
        raise ConfigError(f"{key}={value!r} is invalid; expected one of {', '.join(allowed)}.")
    return value


def _flag(env: dict[str, str], key: str, default: bool) -> bool:
    return _choice(env, key, "on" if default else "off", ("on", "off")) == "on"


def _int(env: dict[str, str], key: str, default: int, *, minimum: int = 0) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{key}={raw!r} is not an integer.") from None
    if value < minimum:
        raise ConfigError(f"{key}={value} must be at least {minimum}.")
    return value


def _list(env: dict[str, str], key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Comma-separated list; unset means the default, set-but-empty means none."""
    if key not in env:
        return default
    return tuple(item.strip() for item in env[key].split(",") if item.strip())


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _url(env: dict[str, str], key: str, *, allow_http: bool = False) -> str:
    value = _require(env, key).rstrip("/")
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError(f"{key}={value!r} is not an http(s) URL.")
    if parts.query or parts.fragment:
        raise ConfigError(f"{key}={value!r} must not have a query or fragment.")
    if parts.scheme == "http" and not (allow_http or _is_loopback(parts.hostname)):
        raise ConfigError(f"{key}={value!r} must use https (credentials travel over it).")
    return value


def _is_https_or_loopback(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" or _is_loopback(parts.hostname)


def _redirect_patterns(patterns: tuple[str, ...]) -> tuple[str, ...]:
    """Wildcards in the path only (D9): a host wildcard would let anyone who
    can register a matching domain receive authorization codes."""
    for pattern in patterns:
        parts = urlsplit(pattern)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            raise ConfigError(f"OAUTH_REDIRECT_ALLOWLIST entry {pattern!r} is not an http(s) URL.")
        if "*" in parts.netloc:
            raise ConfigError(f"OAUTH_REDIRECT_ALLOWLIST entry {pattern!r} has a wildcard in the host; "
                              "wildcards are only allowed in the path.")
        if parts.scheme == "http" and not _is_loopback(parts.hostname):
            raise ConfigError(f"OAUTH_REDIRECT_ALLOWLIST entry {pattern!r}: plain http is only allowed "
                              "for loopback addresses.")
        if parts.username or parts.password or parts.fragment:
            raise ConfigError(f"OAUTH_REDIRECT_ALLOWLIST entry {pattern!r} must not contain "
                              "credentials or a fragment.")
    return patterns


@dataclass(frozen=True)
class WordPressSettings:
    url: str
    rest_prefix: str
    ca_file: str | None
    timeout: int
    ability_allow: tuple[str, ...]
    ability_deny: tuple[str, ...]
    # Only abilities with meta.mcp.public = true, as the WordPress MCP
    # Adapter does (D1).
    mcp_public_only: bool
    ability_cache_ttl: int
    ability_max: int


@dataclass(frozen=True)
class OAuthServerSettings:
    """AUTH_MODE=wordpress: this server is the OAuth authorization server."""

    jwt_signing_key: str
    storage_key: str
    state_dir: str
    dcr_enabled: bool
    redirect_allowlist: tuple[str, ...]
    cimd_allowlist: tuple[str, ...]
    app_name: str
    access_token_ttl: int
    refresh_token_ttl: int
    credential_recheck: int
    allowed_roles: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class Settings:
    auth_mode: AuthMode
    base_url: str
    wordpress: WordPressSettings
    # resource / proxy
    oidc_issuer: str | None
    oidc_jwks_uri: str | None
    mcp_audience: str
    oidc_client_id: str | None
    oidc_client_secret: str | None
    jwt_signing_key: str | None
    # wordpress
    oauth: OAuthServerSettings | None
    host: str
    port: int


def _load_oauth_server(env: dict[str, str], base_url: str) -> OAuthServerSettings:
    signing_key = _require(env, "OAUTH_JWT_SIGNING_KEY")
    if len(signing_key) < 32:
        raise ConfigError("OAUTH_JWT_SIGNING_KEY must be at least 32 characters "
                          "(e.g. `openssl rand -base64 48`).")
    storage_key = _require(env, "OAUTH_STORAGE_KEY")
    try:
        Fernet(storage_key)
    except (ValueError, TypeError):
        raise ConfigError("OAUTH_STORAGE_KEY must be a Fernet key (32 url-safe base64-encoded bytes), e.g. "
                          "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
                          ) from None
    access_ttl = _int(env, "OAUTH_ACCESS_TOKEN_TTL", 3600, minimum=60)
    refresh_ttl = _int(env, "OAUTH_REFRESH_TOKEN_TTL", 30 * 24 * 3600, minimum=access_ttl)
    return OAuthServerSettings(
        jwt_signing_key=signing_key,
        storage_key=storage_key,
        state_dir=env.get("OAUTH_STATE_DIR", "").strip() or "/data/oauth",
        dcr_enabled=_flag(env, "OAUTH_DCR_ENABLED", False),
        redirect_allowlist=_redirect_patterns(_list(env, "OAUTH_REDIRECT_ALLOWLIST", DEFAULT_REDIRECT_ALLOWLIST)),
        cimd_allowlist=_list(env, "OAUTH_CIMD_ALLOWLIST", DEFAULT_CIMD_ALLOWLIST),
        app_name=env.get("OAUTH_APP_NAME", "").strip() or f"MCP ({urlsplit(base_url).hostname})",
        access_token_ttl=access_ttl,
        refresh_token_ttl=refresh_ttl,
        credential_recheck=_int(env, "WP_CREDENTIAL_RECHECK", 60),
        allowed_roles=_list(env, "WP_ALLOWED_ROLES"),
    )


def load(env: dict[str, str] | None = None) -> Settings:
    env = dict(os.environ if env is None else env)

    auth_mode = _choice(env, "AUTH_MODE", "resource", ("resource", "proxy", "wordpress"))
    base_url = _url(env, "BASE_URL", allow_http=_flag(env, "BASE_URL_ALLOW_HTTP", False))
    if auth_mode != "resource" and not _is_https_or_loopback(base_url):
        # Here BASE_URL is an OAuth issuer, which the MCP SDK refuses over
        # plain http on anything but loopback (D4), BASE_URL_ALLOW_HTTP or not.
        raise ConfigError(f"AUTH_MODE={auth_mode} requires an https BASE_URL "
                          f"(plain http only on localhost), got {base_url!r}.")

    rest_prefix = env.get("WP_REST_PREFIX", "/wp-json").strip()
    wordpress = WordPressSettings(
        url=_url(env, "WORDPRESS_URL", allow_http=_flag(env, "WORDPRESS_ALLOW_HTTP", False)),
        # "" = sites without pretty permalinks (?rest_route=).
        rest_prefix="/" + rest_prefix.strip("/") if rest_prefix else "",
        ca_file=env.get("WORDPRESS_CA_FILE", "").strip() or None,
        timeout=_int(env, "WORDPRESS_TIMEOUT", 30, minimum=1),
        ability_allow=_list(env, "ABILITY_ALLOW", ("*",)),
        ability_deny=_list(env, "ABILITY_DENY"),
        mcp_public_only=_flag(env, "ABILITY_MCP_PUBLIC_ONLY", True),
        ability_cache_ttl=_int(env, "ABILITY_CACHE_TTL", 300),
        ability_max=_int(env, "ABILITY_MAX", 1000, minimum=1),
    )

    oidc_client_id = env.get("OIDC_CLIENT_ID", "").strip() or None
    oidc_client_secret = env.get("OIDC_CLIENT_SECRET", "").strip() or None
    oidc_issuer = None
    oauth = None
    if auth_mode in ("resource", "proxy"):
        oidc_issuer = _require(env, "OIDC_ISSUER").rstrip("/")
        if auth_mode == "proxy" and not (oidc_client_id and oidc_client_secret):
            raise ConfigError("AUTH_MODE=proxy requires OIDC_CLIENT_ID and OIDC_CLIENT_SECRET.")
    else:
        oauth = _load_oauth_server(env, base_url)

    return Settings(
        auth_mode=auth_mode,
        base_url=base_url,
        wordpress=wordpress,
        oidc_issuer=oidc_issuer,
        oidc_jwks_uri=env.get("OIDC_JWKS_URI", "").strip() or None,
        mcp_audience=env.get("MCP_AUDIENCE", "").strip() or "mcp-wordpress",
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
        jwt_signing_key=env.get("JWT_SIGNING_KEY", "").strip() or None,
        oauth=oauth,
        host=env.get("HOST", "").strip() or "0.0.0.0",
        port=_int(env, "PORT", 8000, minimum=1),
    )
