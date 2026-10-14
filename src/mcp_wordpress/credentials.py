"""From the verified MCP access token to the credential WordPress accepts.

One resolver per AUTH_MODE family:
- BearerResolver (resource, proxy): the Keycloak access token itself goes to
  WordPress, where a bearer plugin (MCP Bearer Auth) maps it to the matching
  WordPress user (D5, D6).
- GrantResolver (wordpress, in wp_oauth.py): the token points at a stored
  Application Password grant.
"""

from __future__ import annotations

from typing import Protocol

from fastmcp.server.auth import AccessToken

from .wordpress import WPCredential


class CredentialResolver(Protocol):
    async def credential(self, token: AccessToken) -> WPCredential: ...

    def user_key(self, token: AccessToken) -> str:
        """Stable per-user key for caches; never the secret itself."""
        ...

    async def on_unauthorized(self, token: AccessToken) -> None:
        """WordPress answered 401 for this user's credential."""
        ...

    def unauthorized_hint(self) -> str: ...


class BearerResolver:
    def __init__(self, audience: str) -> None:
        self.audience = audience

    async def credential(self, token: AccessToken) -> WPCredential:
        return WPCredential("bearer", token.token)

    def user_key(self, token: AccessToken) -> str:
        claims = token.claims or {}
        return f"{claims.get('iss')}|{claims.get('sub') or token.subject}"

    async def on_unauthorized(self, token: AccessToken) -> None:
        pass  # nothing stored; the next request carries a fresh token anyway

    def unauthorized_hint(self) -> str:
        return (
            "WordPress did not accept your sign-in token. WordPress needs a plugin that accepts bearer "
            f"tokens from this server's issuer with audience {self.audience!r} (e.g. MCP Bearer Auth, "
            "wordpress-plugin/ in this server's repository), and your WordPress account must match your "
            "SSO account (usually: log in to WordPress with SSO once)."
        )
