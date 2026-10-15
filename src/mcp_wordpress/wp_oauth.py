"""AUTH_MODE=wordpress: this server is its own OAuth 2.1 authorization server
and WordPress Application Passwords are the credential (D7, D8).

Built on FastMCP's OAuthProxy with a synthetic "upstream" instead of a real
IdP, so FastMCP's consent page, browser-binding cookie, CIMD, DCR, PKCE,
token issuing, refresh and encrypted storage are reused unchanged:

- upstream authorize = WordPress' own /wp-admin/authorize-application.php.
  The user logs in to WordPress, approves "MCP" and WordPress redirects back
  to our callback with a freshly created Application Password.
- our callback checks the consent binding, the site and the credential, then
  stores a `Grant` (Fernet-encrypted) and hands its id to OAuthProxy as the
  "upstream code".
- upstream token endpoint = `WordPressGrantClient`, in-process: grant id in,
  grant id out (as both the upstream access and refresh token).
- `WordPressGrantVerifier` turns a grant id back into an AccessToken, and
  re-checks the Application Password against WordPress now and then, so
  revoking it in the WordPress profile ends the MCP session too.

The hooks used (`_build_upstream_authorize_url`, `_create_upstream_oauth_client`,
`_handle_idp_callback`, `get_client`, `revoke_token`) are OAuthProxy
internals; fastmcp is pinned to <5 and tests/test_wp_oauth.py covers each one.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from cryptography.fernet import Fernet
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient, _matches_registered_redirect_uri
from fastmcp.server.auth.oauth_proxy.ui import create_error_html
from fastmcp.server.auth.oauth_proxy.upstream import OAuthError
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.filetree import (
    FileTreeStore,
    FileTreeV1CollectionSanitizationStrategy,
    FileTreeV1KeySanitizationStrategy,
)
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from mcp.server.auth.provider import RefreshToken
from mcp.server.auth.settings import RevocationOptions
from mcp.shared.auth import InvalidRedirectUriError
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from .config import Settings
from .wordpress import WordPressClient, WordPressError, WPCredential, WPUnauthorized

logger = logging.getLogger(__name__)

CALLBACK_PATH = "/wp/callback"
GRANT_COLLECTION = "wp-grants"


class Grant(BaseModel):
    """One user's authorization: the Application Password WordPress created
    for this MCP login. Stored encrypted; never logged or shown."""

    grant_id: str
    client_id: str  # the MCP client this connection was made for
    user_id: int
    user_login: str
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)
    app_password: str = Field(repr=False)
    app_password_uuid: str | None = None
    created_at: float

    def credential(self) -> WPCredential:
        return WPCredential("basic", self.app_password, self.user_login)


def build_store(state_dir: str, storage_key: str) -> AsyncKeyValue:
    path = Path(state_dir)
    path.mkdir(parents=True, exist_ok=True)
    files = FileTreeStore(
        data_directory=path,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(path),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(path),
    )
    # A wrong key reads as "not found" (users sign in again) rather than an
    # error on every request.
    return FernetEncryptionWrapper(key_value=files, fernet=Fernet(storage_key), raise_on_decryption_error=False)


class GrantStore:
    def __init__(self, store: AsyncKeyValue, ttl: int) -> None:
        self._grants = PydanticAdapter[Grant](key_value=store, pydantic_model=Grant,
                                              default_collection=GRANT_COLLECTION, raise_on_validation_error=False)
        self.ttl = ttl

    async def get(self, grant_id: str) -> Grant | None:
        if not grant_id:
            return None
        return await self._grants.get(key=grant_id)

    async def put(self, grant: Grant) -> None:
        await self._grants.put(key=grant.grant_id, value=grant, ttl=self.ttl)

    async def delete(self, grant_id: str) -> None:
        await self._grants.delete(key=grant_id)


class WordPressGrantClient:
    """Stands in for OAuthProxy's upstream token client (same duck type as
    fastmcp's AsyncOAuth2Client). The "code" and "refresh token" are grant
    ids; they never leave this process."""

    client_secret = None

    def __init__(self, grants: GrantStore, access_ttl: int, refresh_ttl: int) -> None:
        self.grants = grants
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl

    async def _tokens(self, grant_id: str | None) -> dict[str, Any]:
        grant = await self.grants.get(grant_id or "")
        if grant is None:
            raise OAuthError(error="invalid_grant", description="WordPress authorization not found or revoked")
        await self.grants.put(grant)  # extend its lifetime with the session
        return {"access_token": grant.grant_id, "refresh_token": grant.grant_id, "token_type": "Bearer",
                "expires_in": self.access_ttl, "refresh_expires_in": self.refresh_ttl}

    async def fetch_token(self, url: str, *, code: str | None = None, **_: Any) -> dict[str, Any]:
        return await self._tokens(code)

    async def refresh_token(self, url: str, *, refresh_token: str | None = None, **_: Any) -> dict[str, Any]:
        return await self._tokens(refresh_token)

    async def aclose(self) -> None:
        pass


class WordPressGrantVerifier(TokenVerifier):
    """Grant id -> AccessToken. Every WP_CREDENTIAL_RECHECK seconds the
    Application Password is checked against WordPress (users/me): a 401
    means it was revoked, so the grant is dropped and the token stops
    working (HTTP 401; the refresh then fails with invalid_grant and the
    client signs in again). WordPress being unreachable is not a reason to
    sign anyone out."""

    def __init__(self, grants: GrantStore, wp: WordPressClient, *, recheck: int,
                 allowed_roles: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.grants = grants
        self.wp = wp
        self.recheck = recheck
        self.allowed_roles = allowed_roles
        self._checked: dict[str, float] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        grant = await self.grants.get(token)
        if grant is None:
            return None
        if time.monotonic() - self._checked.get(grant.grant_id, float("-inf")) >= self.recheck:
            try:
                me = await self.wp.whoami(grant.credential())
            except WPUnauthorized:
                logger.info("Application Password of WordPress user %s was revoked; dropping the grant",
                            grant.user_login)
                await self.drop(grant.grant_id)
                return None
            except WordPressError as exc:
                logger.warning("Could not re-check WordPress user %s: %s", grant.user_login, exc)
            else:
                roles = [r for r in me.get("roles") or [] if isinstance(r, str)]
                if self.allowed_roles and roles and not set(roles) & set(self.allowed_roles):
                    logger.info("WordPress user %s no longer has an allowed role", grant.user_login)
                    await self.drop(grant.grant_id)
                    return None
                self._checked[grant.grant_id] = time.monotonic()
                if len(self._checked) > 10_000:
                    self._checked.clear()
        return AccessToken(
            token=grant.grant_id,
            client_id=grant.client_id,
            scopes=[],
            subject=str(grant.user_id),
            claims={"sub": str(grant.user_id), "wp_user_id": grant.user_id, "wp_user_login": grant.user_login,
                    "name": grant.display_name, "wp_roles": grant.roles},
        )

    async def drop(self, grant_id: str) -> None:
        self._checked.pop(grant_id, None)
        await self.grants.delete(grant_id)


class GrantResolver:
    """CredentialResolver for AUTH_MODE=wordpress: the AccessToken carries a
    grant id; the grant holds the user's Application Password."""

    def __init__(self, grants: GrantStore, verifier: WordPressGrantVerifier) -> None:
        self.grants = grants
        self.verifier = verifier

    async def credential(self, token: AccessToken) -> WPCredential:
        from fastmcp.exceptions import ToolError

        grant = await self.grants.get(token.token)
        if grant is None:
            raise ToolError("Your WordPress authorization is gone (revoked or expired). Reconnect this MCP server.")
        return grant.credential()

    def user_key(self, token: AccessToken) -> str:
        return f"wp-user:{(token.claims or {}).get('wp_user_id') or token.subject}"

    async def on_unauthorized(self, token: AccessToken) -> None:
        await self.verifier.drop(token.token)

    def unauthorized_hint(self) -> str:
        return ("The Application Password this connection uses was revoked in WordPress "
                "(Users > Profile > Application Passwords). Reconnect this MCP server to sign in again.")


class RegisteredRedirectClient(ProxyDCRClient):
    """A DCR client that may only use the redirect URIs it registered (the
    loopback port may vary, as OAuth 2.1 allows), as the MCP spec requires.
    With an allowlist configured, FastMCP's ProxyDCRClient checks only the
    allowlist, so a client registered for one allowlisted callback could have
    codes sent to another (D9, docs/mcp-authorization.md)."""

    def validate_redirect_uri(self, redirect_uri):  # type: ignore[override]
        if redirect_uri is not None and not _matches_registered_redirect_uri(redirect_uri, self.redirect_uris):
            raise InvalidRedirectUriError(f"Redirect URI '{redirect_uri}' is not registered for this client.")
        return super().validate_redirect_uri(redirect_uri)


class WordPressAuthServer(OAuthProxy):
    def __init__(self, settings: Settings, wp: WordPressClient, *, store: AsyncKeyValue | None = None) -> None:
        oauth = settings.oauth
        assert oauth is not None
        store = store if store is not None else build_store(oauth.state_dir, oauth.storage_key)
        self.grants = GrantStore(store, oauth.refresh_token_ttl)
        self.wp = wp
        self.oauth_settings = oauth
        self.site_url = settings.wordpress.url
        # Stable per deployment: WordPress shows it as the app's id, and lists
        # every login from this server under it.
        self.app_id = str(uuid.uuid5(uuid.NAMESPACE_URL, settings.base_url))
        self.verifier = WordPressGrantVerifier(self.grants, wp, recheck=oauth.credential_recheck,
                                               allowed_roles=oauth.allowed_roles)
        super().__init__(
            upstream_authorization_endpoint=f"{self.site_url}/wp-admin/authorize-application.php",
            upstream_token_endpoint="urn:mcp-wordpress:grant",  # in-process, never fetched
            upstream_client_id=self.app_id,
            token_verifier=self.verifier,
            base_url=settings.base_url,
            redirect_path=CALLBACK_PATH,
            allowed_client_redirect_uris=list(oauth.redirect_allowlist),
            client_storage=store,
            jwt_signing_key=oauth.jwt_signing_key,
            # Always (D9): any DCR or CIMD client could otherwise receive a
            # code for a user who merely has a WordPress session.
            require_authorization_consent=True,
            fallback_refresh_token_expiry_seconds=oauth.refresh_token_ttl,
            fastmcp_access_token_expiry_seconds=oauth.access_token_ttl,
            enable_cimd=bool(oauth.cimd_allowlist),
            # Our own PKCE towards the in-process upstream would be pointless.
            forward_pkce=False,
        )
        # OAuthProxy always enables DCR; ChatGPT needs it, claude.ai doesn't (CIMD).
        assert self.client_registration_options is not None
        self.client_registration_options.enabled = oauth.dcr_enabled
        # Revocation deletes the Application Password in WordPress.
        self.revocation_options = RevocationOptions(enabled=True)

    # ── Clients ───────────────────────────────────────────────────────────────

    async def get_client(self, client_id: str):  # type: ignore[override]
        if client_id == self._upstream_client_id:
            # OAuthProxy would synthesise a client for its upstream client id
            # that may use any redirect URI; ours is public (the app_id).
            return None
        if self._cimd_manager is not None and self._cimd_manager.is_cimd_client_id(client_id):
            if client_id not in self.oauth_settings.cimd_allowlist:
                logger.warning("Client metadata document %s is not in OAUTH_CIMD_ALLOWLIST", client_id)
                return None
        client = await super().get_client(client_id)
        if type(client) is ProxyDCRClient and client.cimd_document is None:
            # CIMD clients are already held to their document's redirect URIs.
            return RegisteredRedirectClient.model_validate(client.model_dump())
        return client

    # ── Upstream = WordPress authorize-application.php ────────────────────────

    def _create_upstream_oauth_client(self) -> WordPressGrantClient:  # type: ignore[override]
        return WordPressGrantClient(self.grants, self.oauth_settings.access_token_ttl,
                                    self.oauth_settings.refresh_token_ttl)

    def _callback_url(self, txn_id: str) -> str:
        return f"{str(self.base_url).rstrip('/')}{self._redirect_path}?{urlencode({'state': txn_id})}"

    def _build_upstream_authorize_url(self, txn_id: str, transaction: dict[str, Any]) -> str:
        callback = self._callback_url(txn_id)
        # WordPress redirects to reject_url unchanged (it only appends
        # success=false to a reject_url it derives itself), so say it here.
        query = {"app_name": self.oauth_settings.app_name, "app_id": self.app_id,
                 "success_url": callback, "reject_url": callback + "&success=false"}
        return f"{self._upstream_authorization_endpoint}?{urlencode(query)}"

    async def _handle_idp_callback(self, request: Request) -> HTMLResponse | RedirectResponse:
        """WordPress' answer: ?state=…&site_url=…&user_login=…&password=…
        on approval, ?state=…&success=false on rejection. Translated into the
        code/error callback OAuthProxy expects."""
        params = request.query_params
        txn_id = params.get("state", "")
        if params.get("success") == "false":
            return await super()._handle_idp_callback(_with_query(request, {
                "state": txn_id, "error": "access_denied",
                "error_description": "The connection was rejected in WordPress"}))

        password = params.get("password", "")
        user_login = params.get("user_login", "")
        if not (txn_id and password and user_login):
            return _error_page("WordPress did not return an Application Password.", 400)
        cred = WPCredential("basic", password, user_login)

        transaction = await self._transaction_store.get(key=txn_id)
        if transaction is None:
            # Unknown or expired state. Don't touch WordPress: the URL is
            # attacker-controlled, and calling WordPress with its credentials
            # would let anyone use this server to try passwords.
            return _error_page("Invalid or expired authorization transaction. Please connect again.", 400)
        consent_ok = bool(transaction.consent_token) and self._verify_consent_binding_cookie(
            request, txn_id, transaction.consent_token)
        if not consent_ok:
            # Either a stale/forged link or a different browser than the one
            # that approved the consent screen. WordPress has already created
            # the Application Password, so delete it again.
            logger.warning("WordPress callback without a matching consent binding (transaction %s)", txn_id[:8])
            await self._discard(cred)
            return _error_page("Authorization session mismatch. This can happen if you followed a link "
                               "from another person or your session expired. Please connect again.", 403)

        site_url = params.get("site_url", "")
        if not _same_site(site_url, self.site_url):
            logger.warning("WordPress callback for site %r, expected %r", site_url, self.site_url)
            await self._discard(cred)
            return _error_page("The Application Password is for a different WordPress site.", 400)

        try:
            me = await self.wp.whoami(cred)
            uuid_ = None
            try:
                uuid_ = (await self.wp.introspect_app_password(cred)).get("uuid")
            except WordPressError as exc:
                logger.info("Could not introspect the new Application Password: %s", exc)
        except WordPressError as exc:
            logger.warning("New Application Password for %s does not work: %s", user_login, exc)
            return _error_page(f"WordPress did not accept the new Application Password: {exc.message}", 502)

        roles = [r for r in me.get("roles") or [] if isinstance(r, str)]
        allowed = self.oauth_settings.allowed_roles
        if allowed and not set(roles) & set(allowed):
            logger.info("WordPress user %s (roles %s) is not in WP_ALLOWED_ROLES", user_login, roles)
            await self._discard(cred, uuid_)
            return await super()._handle_idp_callback(_with_query(request, {
                "state": txn_id, "error": "access_denied",
                "error_description": "Your WordPress role may not use this MCP server"}))

        grant = Grant(grant_id=secrets.token_urlsafe(32), client_id=transaction.client_id, user_id=int(me.get("id") or 0),
                      user_login=user_login,
                      display_name=str(me.get("name") or ""), roles=roles, app_password=password,
                      app_password_uuid=uuid_, created_at=time.time())
        await self.grants.put(grant)
        logger.info("WordPress user %s (id %s) connected", grant.user_login, grant.user_id)
        return await super()._handle_idp_callback(_with_query(request, {"state": txn_id, "code": grant.grant_id}))

    async def _discard(self, cred: WPCredential, uuid_: str | None = None) -> None:
        """Best effort: delete an Application Password we won't use."""
        try:
            if uuid_ is None:
                uuid_ = (await self.wp.introspect_app_password(cred)).get("uuid")
            if uuid_:
                await self.wp.delete_app_password(cred, uuid_)
        except WordPressError as exc:
            logger.warning("Could not delete an unused Application Password: %s", exc)

    # ── Revocation ────────────────────────────────────────────────────────────

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:  # type: ignore[override]
        grant_id: str | None = None
        if isinstance(token, RefreshToken):
            try:
                jti = self.jwt_issuer.verify_token(token.token, expected_token_use="refresh")["jti"]
                mapping = await self._jti_mapping_store.get(key=jti)
                upstream = await self._upstream_token_store.get(key=mapping.upstream_token_id) if mapping else None
                grant_id = upstream.refresh_token if upstream else None
            except Exception:  # an invalid token: nothing to revoke upstream
                grant_id = None
        else:
            grant_id = token.token  # load_access_token returns the verified grant
        await super().revoke_token(token)
        grant = await self.grants.get(grant_id or "")
        if grant is None:
            return
        await self.verifier.drop(grant.grant_id)
        await self._discard(grant.credential(), grant.app_password_uuid)
        logger.info("WordPress user %s disconnected (Application Password deleted)", grant.user_login)


def _with_query(request: Request, query: dict[str, str]) -> Request:
    """The same request (cookies included) with a different query string."""
    scope = dict(request.scope)
    scope["query_string"] = urlencode(query).encode()
    return Request(scope, request.receive)


def _same_site(a: str, b: str) -> bool:
    """WordPress' site_url against WORDPRESS_URL (scheme aside: WordPress may
    report http behind a TLS-terminating proxy)."""
    pa, pb = urlsplit(a.rstrip("/")), urlsplit(b.rstrip("/"))
    return (pa.scheme in ("http", "https") and bool(pa.hostname)
            and (pa.hostname, pa.path) == (pb.hostname, pb.path))


def _error_page(message: str, status: int) -> HTMLResponse:
    return HTMLResponse(create_error_html(error_title="Authorization Error", error_message=message),
                        status_code=status)
