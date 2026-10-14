# Design decisions

Each decision lists its context, what was chosen and why, and what it costs.
The sibling project `mcp-mail-oauth` is called "mcp-mail" below; several
decisions are ports of its own.

The target setups:

> **A.** Users sign in to **Open WebUI** with **Keycloak**. Open WebUI calls
> this MCP server with the user's Keycloak token. **WordPress** (with the
> bundled MCP Bearer Auth plugin) trusts the same realm.
>
> **B.** Users connect **claude.ai** or **ChatGPT** to this server as a custom
> connector and sign in with their **WordPress** account. No Keycloak.

---

## D1. Scope: WordPress Abilities, nothing else

**Context.** WordPress 6.9 ships the Abilities API: plugins register
*abilities* (name, label, description, JSON input/output schema,
annotations, permission callback) and core exposes them under
`/wp-abilities/v1`. "Enable Abilities for MCP" (EAM) registers a broad set
for posts, pages, media, comments, users and site info and lets the admin
switch each one on or off. WordPress' own MCP Adapter publishes abilities
flagged `meta.mcp.public`.

**Decision.** The tools are WordPress abilities: nothing hand-written on
top of the core REST API (only `whoami`). By default only abilities with
`meta.mcp.public = true` are offered (`ABILITY_MCP_PUBLIC_ONLY`), the same
rule as the MCP Adapter, narrowed further by `ABILITY_ALLOW`/`ABILITY_DENY`
globs.

**Consequences.** What the assistant can do is administered in WordPress
(EAM's settings page, other plugins' abilities), not here. A site without
abilities offers only `whoami`.

---

## D2. One MCP tool per ability, per user

**Context.** The alternatives were forwarding to the MCP Adapter (the model
then sees three meta-tools: discover, get-info, execute) or a fixed curated
tool set.

**Decision.** Each ability becomes a real MCP tool (`core/get-site-info` →
`core-get-site-info`) with the ability's schemas and annotations. The list
comes from a FastMCP `Provider` (`abilities.AbilityProvider`), which FastMCP
calls on every `tools/list` and `tools/call` with the caller's token in
context, so each user sees what WordPress lists *for them*. The list is
cached per user for `ABILITY_CACHE_TTL` (300 s), LRU-bounded, one load at
a time per user.

- Non-object input schemas are wrapped as `{"input": …}` (MCP arguments are
  always an object); missing schemas become an empty object.
- Non-object output schemas are wrapped as `{"result": …}`.
- Name collisions after mapping (`a-b/c` vs `a/b-c`): the first by name
  wins, the other is logged and skipped. `whoami` can't be shadowed.

**Consequences.** Models see well-described, typed tools. Changes in
WordPress show up within the cache TTL. WordPress' list endpoint does not
evaluate permission callbacks (they may depend on input), so most users see
the same list and a forbidden call is a tool error with WordPress' message.

---

## D3. HTTP method follows the ability's annotations

**Context.** WordPress' run controller (`WP_REST_Abilities_V1_Run_Controller`)
insists on a method: `readonly` → GET, `destructive` and `idempotent` →
DELETE, everything else POST, and answers 405 `rest_ability_invalid_method`
otherwise. GET and DELETE read `input` from the query string.

**Decision.** `Ability.method` implements that rule; GET/DELETE input is
encoded PHP-style (`input[a][b]=1`, `input[l][]=x`, booleans as 1/0).

**Consequences.** A query string can't express empty arrays/objects; those
are omitted. The test stack's e2e run confirms the rule against real
WordPress.

---

## D4. Three inbound auth modes

| `AUTH_MODE` | Client authenticates with | WordPress credential |
|---|---|---|
| `resource` (default) | Keycloak access token (`aud` ∋ `MCP_AUDIENCE`) | the same token, via the MCP Bearer Auth plugin (D6) |
| `proxy` | FastMCP OIDCProxy session (or a direct Keycloak token) | the upstream Keycloak token |
| `wordpress` | this server's own OAuth 2.1 tokens | the user's Application Password |

**Why not reuse EAM's OAuth server?** Its tokens are HS256 JWTs bound to
EAM's own MCP route and an Application Password whose plaintext it throws
away; a service outside WordPress can't present them anywhere else.

**Consequences.** `resource`/`proxy` need the bearer feature in WordPress
(D6) and store nothing; `wordpress` needs no WordPress plugin besides core
but stores secrets (D8).

---

## D5. WordPress decides; no service account

Every WordPress call carries the calling user's own credential. There is
no admin or service account, and this server enforces no scopes or roles of
its own (except the optional `WP_ALLOWED_ROLES` gate in `wordpress` mode):
what a user may do is exactly what WordPress lets that user do. WordPress
errors become tool errors with WordPress' code and message; a 401 also
drops the user's cached tool list and, in `wordpress` mode, the grant.

---

## D6. WordPress side: a bundled, login-plugin-independent bearer plugin

**Context.** WordPress has no way to accept an OIDC access token. Most
OIDC login plugins only handle the browser login, and the one that does
accept bearer tokens (sso-login-oidc) would make this server depend on one
particular login plugin. The plugin must also map the token to a user, and
each login plugin records that link differently.

**Decision.** This repository ships its own small WordPress plugin,
`wordpress-plugin/mcp-bearer-auth`. It does only the bearer part, and it
reads the user mapping from whatever the login plugin left behind.
- **Hooks:** `determine_current_user` and `rest_authentication_errors`,
  only on REST routes under `/wp-abilities/v1/` and `/mcp/`, plus
  `GET /wp/v2/users/me` (filterable). Path tricks and method overrides are
  refused.
- **Token checks:** an asymmetric signature from the issuer's JWKS (keys
  cached, refetched on an unknown `kid` at most every 5 minutes), plus
  `iss`, `aud` (= `MCP_AUDIENCE`), `exp`, `sub`, and access-token type.
- **User matching** (`MCP_BEARER_USER_MATCH`): `meta:<key>` (the login
  plugin's stored subject; refused if two users share it), `email` (only
  with `email_verified`), or `login`. Nothing is provisioned.
- **Configuration:** constants in `wp-config.php`, not an options page.
  Whoever can change them decides which tokens log in as whom.

The server depends only on the contract: `Authorization: Bearer` on those
routes, with the user's own permissions, and a 401 with a message
otherwise. Any plugin that fulfils it works, including sso-login-oidc's
built-in feature.

**Consequences.** The integration stack and CI need no other repository.
PHP code with a JWT dependency (firebase/php-jwt 7) lives here, with its own
tests and phpcs in CI, and every security check is covered by a test that
fails without it. php-jwt classes are global: if another plugin loads an
older 6.x first, that copy is used, and its API is compatible.

---

## D7. `AUTH_MODE=wordpress`: OAuthProxy with a synthetic upstream

**Context.** Being an OAuth 2.1 server for claude.ai and ChatGPT needs
metadata, DCR, CIMD, PKCE, a consent screen with browser binding,
token issuing, refresh, revocation and encrypted storage. FastMCP's
`OAuthProvider` base has only routes; `OAuthProxy` has all of it.

**Decision.** `wp_oauth.WordPressAuthServer` subclasses `OAuthProxy`:

- the "upstream authorize URL" is WordPress' `authorize-application.php`
  (`app_id` = uuid5 of `BASE_URL`, `success_url` =
  `/wp/callback?state=<txn>`, `reject_url` = the same plus `&success=false`,
  since WordPress uses a given `reject_url` unchanged);
- the callback checks the consent binding cookie **first**, then that
  `site_url` is `WORDPRESS_URL`, that the new password works (`users/me`),
  the role gate, and stores a `Grant`; its id is handed to OAuthProxy as
  the upstream code;
- the "upstream token client" is in-process: grant id → grant id;
- `WordPressGrantVerifier` turns the grant id into an `AccessToken`.

**Consequences.** These are OAuthProxy internals (`_build_upstream_authorize_url`,
`_create_upstream_oauth_client`, `_handle_idp_callback`, `get_client`,
`revoke_token`). `fastmcp` is pinned `<5` and `tests/test_wp_oauth.py`
exercises each hook with the full browser flow.

---

## D8. Application Passwords: storage and lifecycle

- Stored only Fernet-encrypted (`OAUTH_STORAGE_KEY`) under
  `OAUTH_STATE_DIR`, together with client registrations and sessions; a
  wrong key reads as "not found" (users sign in again).
- Re-checked against WordPress at most every `WP_CREDENTIAL_RECHECK`
  seconds and on every 401: revoked in the WordPress profile → the grant is
  dropped → HTTP 401 → refresh fails with `invalid_grant` → the client
  signs in again. WordPress being unreachable signs no one out.
- `/revoke` deletes the Application Password in WordPress. A session that
  simply expires leaves it in the user's profile (named `OAUTH_APP_NAME`),
  where they can delete it.
- **Known exposure:** WordPress delivers the new password in the callback's
  query string. The server's access log is off; a reverse proxy in front
  must not log query strings for `/wp/callback`.

---

## D9. Client admission

- The consent screen is always on (`require_authorization_consent=True`)
  in `proxy` and `wordpress` mode: any DCR or CIMD client could otherwise
  obtain a code for a user who merely has a live WordPress/Keycloak session.
- `wordpress` mode: DCR is off by default (`OAUTH_DCR_ENABLED`); ChatGPT
  needs it, claude.ai doesn't (it identifies itself with a CIMD URL).
- Redirect URIs must match `OAUTH_REDIRECT_ALLOWLIST` (defaults: ChatGPT's
  and Claude's callbacks, the same list EAM uses, plus loopback on any
  port). Wildcards only in the path; a host wildcard would let anyone who
  registers a matching domain receive codes.
- CIMD client ids must be in `OAUTH_CIMD_ALLOWLIST`.
- OAuthProxy would accept its "upstream client id" (here the public
  `app_id`) as a client with any redirect URI; `get_client` refuses it.

---

## D10. Stateless HTTP

As mcp-mail: streamable HTTP with `stateless_http=True`; restarts and
replicas need no session affinity. In `wordpress`/`proxy` mode, OAuth state
lives in the file store, so replicas need a shared volume.

---

## D11. Versioning from git tags

As mcp-mail: setuptools-scm reads `vX.Y.Z` tags; CI injects the version
into Docker builds (`ARG VERSION`), where `.git` isn't in the context.
`scripts/next_version.py` derives the next version from conventional
commit subjects.

---

## D12. FastMCP 4, httpx2, compatible-range pins

FastMCP 4.1 (MCP SDK v2) with `httpx2`. Dependencies are pinned to
compatible ranges because D7 builds on internals that change between
majors. MCP SDK v2 field names (`read_only_hint`, …) are used throughout.

---

## D13. Container image

Non-root (uid 10001), Debian security updates applied at build, Trivy in
CI fails on fixable HIGH/CRITICAL findings not listed in `.trivyignore`
(each entry with a reason and review date).
