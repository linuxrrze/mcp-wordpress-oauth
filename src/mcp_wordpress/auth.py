"""Inbound authentication: which bearer tokens this MCP server accepts, and
how a verified token becomes the credential WordPress sees (D4).

- ``resource`` (default): a pure OAuth resource server for Keycloak access
  tokens with MCP_AUDIENCE in `aud`. The same token goes on to WordPress,
  where sso-login-oidc's bearer feature maps it to the linked user (D5, D6).
- ``proxy``: additionally runs FastMCP's OIDCProxy against Keycloak for MCP
  clients that insist on the MCP authorization flow (DCR). Tools still get
  the upstream Keycloak token; directly forwarded tokens keep working.
- ``wordpress``: this server is the authorization server itself, and users
  sign in with their WordPress account; see wp_oauth.py (D7, D8).
"""

from __future__ import annotations

import logging

import httpx2
from fastmcp.server.auth import AccessToken, AuthProvider, RemoteAuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier

from .config import ConfigError, Settings
from .credentials import BearerResolver, CredentialResolver
from .wordpress import WordPressClient

logger = logging.getLogger(__name__)


def discovery_document(issuer: str, timeout: float = 10.0) -> dict:
    """The issuer's OIDC discovery document, with its `issuer` checked.

    A mismatch almost always means Keycloak is reached under a different
    hostname than the one it puts in tokens (internal http://keycloak:8080
    vs. public https://sso.example.com); every token would then fail the
    `iss` check, so the server refuses to start instead.
    """
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = httpx2.get(url, timeout=timeout)
        resp.raise_for_status()
        document = resp.json()
    except (httpx2.HTTPError, ValueError) as exc:
        raise ConfigError(
            f"Could not load OIDC discovery from {url}: {exc}. If Keycloak is only "
            "reachable from this container under an internal URL, keep OIDC_ISSUER "
            "set to the public issuer and set OIDC_JWKS_URI to the internal "
            ".../protocol/openid-connect/certs URL."
        ) from exc
    if document.get("issuer", "").rstrip("/") != issuer:
        raise ConfigError(
            f"OIDC_ISSUER={issuer!r} but the discovery document says issuer="
            f"{document.get('issuer')!r}. OIDC_ISSUER must be the exact `iss` "
            "value in the tokens (Keycloak: <public frontend URL>/realms/<realm>)."
        )
    return document


def build_token_verifier(settings: Settings, *, jwks_uri: str | None = None, public_key: str | None = None) -> JWTVerifier:
    """Signature, issuer, expiry and audience check for Keycloak access tokens.
    No scopes: what a user may do is WordPress' decision (D5)."""
    if public_key is None and jwks_uri is None:
        jwks_uri = settings.oidc_jwks_uri or discovery_document(settings.oidc_issuer)["jwks_uri"]
    return JWTVerifier(
        jwks_uri=jwks_uri,
        public_key=public_key,
        issuer=settings.oidc_issuer,
        audience=settings.mcp_audience,
    )


class ProxyAcceptingDirectTokens(OIDCProxy):
    """OIDCProxy that also accepts Keycloak access tokens presented directly
    (Open WebUI's "OAuth" auth type forwards the user's own SSO token)."""

    def __init__(self, *, direct_verifier: JWTVerifier, **kwargs) -> None:
        super().__init__(token_verifier=direct_verifier, **kwargs)
        self._direct_verifier = direct_verifier

    async def load_access_token(self, token: str) -> AccessToken | None:  # type: ignore[override]
        access = await super().load_access_token(token)
        if access is not None:
            return access
        return await self._direct_verifier.verify_token(token)


def build_auth(settings: Settings, wp: WordPressClient, verifier: JWTVerifier | None = None
               ) -> tuple[AuthProvider, CredentialResolver]:
    if settings.auth_mode == "wordpress":
        from .wp_oauth import GrantResolver, WordPressAuthServer

        server = WordPressAuthServer(settings, wp)
        return server, GrantResolver(server.grants, server.verifier)

    verifier = verifier or build_token_verifier(settings)
    resolver = BearerResolver(settings.mcp_audience)
    if settings.auth_mode == "resource":
        # RFC 9728 protected-resource metadata naming Keycloak as the
        # authorization server, so a spec-compliant client can find it.
        return RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[settings.oidc_issuer],
            base_url=settings.base_url,
            resource_name="mcp-wordpress-oauth",
        ), resolver

    proxy = ProxyAcceptingDirectTokens(
        direct_verifier=verifier,
        config_url=f"{settings.oidc_issuer}/.well-known/openid-configuration",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        base_url=settings.base_url,
        # Keep FastMCP's consent screen (D9): any DCR client can register an
        # arbitrary redirect URI.
        require_authorization_consent=True,
        # Explicit key: the default derives from the client secret, so
        # rotating it would silently invalidate every session.
        jwt_signing_key=settings.jwt_signing_key,
    )
    proxy.update_default_scopes(["openid", "email", "profile"])
    return proxy, resolver
