"""The MCP server: `whoami` plus one tool per WordPress ability (abilities.py)."""

from __future__ import annotations

import logging
import time
from urllib.parse import urlsplit

from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken, AuthProvider
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__
from .abilities import AbilityCache, AbilityFilter, AbilityProvider, AbilityRuntime
from .auth import build_auth
from .config import Settings
from .credentials import CredentialResolver
from .wordpress import WordPressClient, WordPressError

logger = logging.getLogger(__name__)

MCP_PATH = "/mcp"
AS_METADATA_PATH = "/.well-known/oauth-authorization-server"
STATIC_TOOLS = ("whoami",)


class EndpointPaths:
    """Forgive the two endpoint URLs people configure by mistake, and serve
    the authorization server metadata where MCP clients look for it.

    - `/mcp/` is served as `/mcp`. Starlette would otherwise redirect it to
      `/mcp`, built from the internal Host and without a reverse proxy's
      stripped prefix, which no client can reach.
    - `/` gets a 404 that names the actual endpoint instead of an empty one.
    - With BASE_URL at a path (`https://host/prefix`), the issuer has that
      path, and MCP clients ask for its metadata at
      `/.well-known/oauth-authorization-server/prefix` (RFC 8414 path
      insertion) at the host's root. FastMCP serves it without the suffix,
      so that request is answered as `/.well-known/oauth-authorization-server`
      (docs/mcp-authorization.md).
    """

    def __init__(self, app: ASGIApp, endpoint: str, prefix: str = "") -> None:
        self.app = app
        self.endpoint = endpoint
        self.as_metadata_alias = AS_METADATA_PATH + prefix if prefix else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            if scope["path"] == MCP_PATH + "/":
                scope = {**scope, "path": MCP_PATH, "raw_path": MCP_PATH.encode()}
            elif scope["path"] == self.as_metadata_alias:
                scope = {**scope, "path": AS_METADATA_PATH, "raw_path": AS_METADATA_PATH.encode()}
            elif scope["path"] == "/":
                response = PlainTextResponse(f"Not the MCP endpoint. Use {self.endpoint}\n", status_code=404)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def client_settings(settings: Settings) -> list[str]:
    """What to configure where for this setup, logged at startup."""
    base = settings.base_url.rstrip("/")
    endpoint = base + MCP_PATH
    lines = ["MCP client settings:", f"  URL:  {endpoint}"]
    if settings.auth_mode == "wordpress":
        oauth = settings.oauth
        lines += [
            "  claude.ai: Settings > Connectors > Add custom connector, URL above, no client id/secret",
            "  Users sign in with their WordPress account and approve an Application Password "
            f"named {oauth.app_name!r}",
            f"  Dynamic Client Registration (ChatGPT): {'on' if oauth.dcr_enabled else 'off (OAUTH_DCR_ENABLED)'}",
            f"  WordPress must allow redirects to {base}/wp/callback (https, or WP_ENVIRONMENT_TYPE=local)",
        ]
    else:
        lines += [
            "  Open WebUI: Type MCP (Streamable HTTP), Auth: OAuth (forwards the user's Keycloak token)",
            f"  Tokens must come from {settings.oidc_issuer} with {settings.mcp_audience!r} in aud",
            "  WordPress: MCP Bearer Auth (or another bearer plugin) with MCP_BEARER_ISSUER="
            f"{settings.oidc_issuer} and MCP_BEARER_AUDIENCE={settings.mcp_audience}",
        ]
        if settings.auth_mode == "proxy":
            lines.append(f"  AUTH_MODE=proxy: Keycloak client {settings.oidc_client_id!r} needs the redirect URI "
                         f"{base}/auth/callback")
    return lines


def http_middleware(settings: Settings) -> list[Middleware]:
    """ASGI middleware for the HTTP app (`run()` and `http_app()` alike)."""
    base = settings.base_url.rstrip("/")
    return [Middleware(EndpointPaths, endpoint=base + MCP_PATH, prefix=urlsplit(base).path)]


def build_wordpress_client(settings: Settings) -> WordPressClient:
    wp = settings.wordpress
    return WordPressClient(wp.url, rest_prefix=wp.rest_prefix, timeout=wp.timeout, verify=wp.ca_file or True)


def create_server(settings: Settings, *, auth: AuthProvider | None = None, wp: WordPressClient | None = None,
                  resolver: CredentialResolver | None = None, cache: AbilityCache | None = None) -> FastMCP:
    wp = wp or build_wordpress_client(settings)
    if auth is None or resolver is None:
        auth, resolver = build_auth(settings, wp)
    cache = cache or AbilityCache(ttl=settings.wordpress.ability_cache_ttl)
    runtime = AbilityRuntime(wp, resolver, cache)
    filt = AbilityFilter(settings.wordpress.ability_allow, settings.wordpress.ability_deny,
                         settings.wordpress.mcp_public_only)
    provider = AbilityProvider(runtime, filt, max_items=settings.wordpress.ability_max, reserved=STATIC_TOOLS)

    mcp = FastMCP(
        "mcp-wordpress-oauth",
        version=__version__,
        instructions=(
            f"Tools for the WordPress site {settings.wordpress.url}, acting as the signed-in WordPress "
            "user with that user's permissions. Each tool other than whoami is a WordPress ability. "
            "Tools marked destructive change or delete content: confirm with the user first."
        ),
        auth=auth,
        providers=[provider],
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    @mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": False})
    async def whoami(token: AccessToken = CurrentAccessToken()) -> dict:
        """Show which WordPress user you act as, with which roles, and how many
        WordPress abilities are available to you as tools."""
        try:
            cred = await resolver.credential(token)
            me = await wp.whoami(cred)
            tools = await provider.tools_for(token)
        except WordPressError as exc:
            raise await runtime.tool_error(token, exc) from None
        return {
            "site": settings.wordpress.url,
            "user_id": me.get("id"),
            "username": me.get("username") or me.get("slug"),
            "name": me.get("name"),
            "roles": me.get("roles"),
            "auth_mode": settings.auth_mode,
            "ability_tools": len(tools),
            "ability_filter": filt.describe(),
            "expires_in_seconds": int(token.expires_at - time.time()) if token.expires_at else None,
        }

    return mcp
