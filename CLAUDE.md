# Codebase guide

MCP server (FastMCP 4.1) exposing a WordPress 6.9+ site's **Abilities** as
MCP tools, one per ability, executed **as the signed-in WordPress user**.
Three inbound auth modes (`AUTH_MODE`): `resource` (Keycloak token forwarded
to WordPress, accepted by the bundled MCP Bearer Auth plugin or any
equivalent), `proxy` (FastMCP
OIDCProxy + the same), `wordpress` (this server is the OAuth 2.1 server;
credential = per-user Application Password, stored encrypted).

Sibling of `~/git/mcp-mail-oauth`; Docker, CI, test and versioning
conventions come from there. The WordPress side of `resource`/`proxy` is
`wordpress-plugin/mcp-bearer-auth` (PHP, its own tests; independent of any
OIDC login plugin, D6). sso-login-oidc has an equivalent feature of its own.

**`docs/decisions.md` (D1–D13) is the source of truth for *why*.** Read the
relevant decision before changing auth, credential handling, client
admission or the ability→tool mapping, and update it when you change one.

## Layout

| Path | Contents |
|---|---|
| `src/mcp_wordpress/config.py` | `load(env)` → frozen `Settings`/`WordPressSettings`/`OAuthServerSettings`; all env vars and validation (`ConfigError`) |
| `src/mcp_wordpress/wordpress.py` | `WordPressClient` (REST calls with a `WPCredential`), `Ability` + method rule, `WordPressError` hierarchy, `encode_php_query` |
| `src/mcp_wordpress/abilities.py` | Ability → tool: `tool_name`, schema wrapping, `AbilityFilter`, `AbilityCache`, `AbilityTool`, `AbilityProvider` (per-request, per-user tool list) |
| `src/mcp_wordpress/credentials.py` | `CredentialResolver` protocol; `BearerResolver` (resource/proxy) |
| `src/mcp_wordpress/auth.py` | `build_auth()` → (AuthProvider, CredentialResolver) per mode |
| `src/mcp_wordpress/wp_oauth.py` | `AUTH_MODE=wordpress`: `WordPressAuthServer(OAuthProxy)`, `Grant`, `GrantStore`, `WordPressGrantClient`, `WordPressGrantVerifier`, `GrantResolver` |
| `src/mcp_wordpress/server.py` | `create_server()`: provider, `whoami`, `/healthz`, `EndpointPaths`, startup client-settings log |
| `tests/fake_wp.py` | `FakeWordPress`: Abilities API, users/me, Application Passwords, bearer feature, behind `httpx2.MockTransport` |
| `wordpress-plugin/mcp-bearer-auth/` | WordPress plugin: `Bearer_Auth` (hooks, routes, error contract), `Token_Verifier` (JWKS, claims), `User_Resolver` (meta/email/login), `Config` (`MCP_BEARER_*` constants); PHPUnit + Brain Monkey tests |
| `test-stack/` | WordPress + Keycloak + MCP Bearer Auth + both server modes in Docker; `e2e.py` |

## Key patterns

- **The user's credential, always** (D5). Every WordPress call takes a
  `WPCredential` resolved from the current `AccessToken`; there is no
  service account. Don't add one.
- **Tool list is per request** (D2). `AbilityProvider._list_tools/_get_tool`
  read `get_access_token()`; no token → no ability tools. Cache key is
  `resolver.user_key(token)`, never the secret.
- **WordPress errors → `ToolError`** with WP's code/message
  (`AbilityRuntime.tool_error`); a 401 invalidates the cache and calls
  `resolver.on_unauthorized`. Messages are shown to users: no credentials.
- **wordpress mode overrides OAuthProxy internals** (D7). Any FastMCP
  upgrade must keep `tests/test_wp_oauth.py` green; the callback must check
  the consent binding before anything else and delete Application
  Passwords it won't use.
- The method rule (`Ability.method`) mirrors WP's run controller (D3); GET
  and DELETE input goes PHP-bracket-encoded into the query string.

## Gotchas

- `httpx2`, not `httpx`.
- MCP SDK v2 field names (`read_only_hint`, not `readOnlyHint`).
- FastMCP returns **401** (not 400) for `invalid_grant` at `/token`.
- The SDK's `/revoke` requires a `client_secret` form field, even empty,
  for public clients.
- Never log Application Passwords, tokens or the `/wp/callback` query
  string (D8). The uvicorn access log is off on purpose.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

`conftest.py`: `make_token(subject, audience, issuer, expires_in)`,
`fake_wp` (alice admin + bob author matching SSO subjects, carol unmatched
editor; four abilities), `serve(app)` (runs the lifespan), `rpc`/`call`/
`tool_names`. Extend `FakeWordPress` rather than mocking calls.
`test_wp_oauth.py` drives the full browser flow (register → authorize →
consent → WordPress approval → callback → token → MCP).

WordPress plugin (needs PHP 8.1+ and Composer; this dev box has neither
installed, a static PHP CLI from dl.static-php.dev works):

```bash
cd wordpress-plugin/mcp-bearer-auth && composer install && composer test && composer phpcs
```

Its security checks each have a test that fails without them (verified by
removing each check); keep it that way when adding one. The fake WordPress
in `tests/fake_wp.py` mirrors the plugin's error contract (`mcp_bearer_*`).

End to end (needs Docker, which this dev box doesn't have; CI runs it):

```bash
docker compose -f test-stack/docker-compose.yml up -d --build
docker compose -f test-stack/docker-compose.yml run --rm e2e
docker compose -f test-stack/docker-compose.yml down -v
```

## CI and releases

As mcp-mail (`docs/ci.md`): tests, Trivy, integration matrix
(`resource`, `wordpress`), image build → scan → smoke test → push → tag.
Version from conventional commit subjects (`scripts/next_version.py`).
