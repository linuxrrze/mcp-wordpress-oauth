# MCP authorization specification: where this server stands

This compares the server with the **draft** MCP authorization
specification ([Overview](https://modelcontextprotocol.io/specification/draft/basic/authorization),
[Authorization Server Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery),
[Client Registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration),
[Security Considerations](https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations)).

| | |
|---|---|
| Spec revision | `modelcontextprotocol/modelcontextprotocol@00c3f2e` (2026-09-22) |
| Server | `main` after `v0.1.1`, with the fixes for 2 and 3 below: FastMCP 4.1.0, MCP SDK 2.3.0 |
| Checked on | 2026-10-15 |

**How it was checked.** The server was run in each `AUTH_MODE` with the
test suite's fakes (a locally signed "Keycloak", `tests/fake_wp.py`). Each
mode was then probed: the 401 challenges, both well-known documents,
`/authorize` with bad input, the whole code flow, the token's claims,
refresh, and refresh-token reuse. FastMCP's code was read where the
behaviour lives there. In `resource` mode, and for the upstream half of
`proxy` mode, Keycloak plays the authorization server, so those rows
describe what Keycloak must be configured to do. They were not tested here.
The spec is a draft. Re-check this page when it or FastMCP changes.

## Roles per mode

| `AUTH_MODE` | MCP server (resource server) | Authorization server | What reaches WordPress |
|---|---|---|---|
| `resource` | this server | Keycloak | **the client's own token** (via MCP Bearer Auth, D6) |
| `proxy` | this server | this server (FastMCP OIDCProxy), with Keycloak upstream | the upstream Keycloak token; for clients that bypass the proxy, the client's own token |
| `wordpress` | this server | this server (`WordPressAuthServer`, D7) | the user's Application Password |

## Summary

- **`wordpress` mode** meets every authorization-server MUST of the draft,
  now including the exact redirect-URI match for DCR clients
  ([2](#2-exact-redirect-uri-match-for-dcr-clients-fixed)). It also
  meets most SHOULDs: S256-only PKCE (required), RFC 9207 `iss` in
  every authorization response, RFC 8707 `resource` checking, tokens bound
  to the MCP endpoint, rotated refresh tokens, CIMD with a trust
  allowlist, DCR off by default, and a consent screen that shows the
  redirect URI.
- **`proxy` mode** is the same FastMCP authorization server, so it has the
  same properties. Its exception is that it also accepts Keycloak tokens
  presented directly, which are then forwarded
  ([deviation 1](#1-token-passthrough-to-wordpress-resource-mode-proxy-for-direct-tokens)).
- **`resource` mode** is correct as a resource server: RFC 9728 metadata,
  `WWW-Authenticate` with `resource_metadata`, and issuer, audience and
  expiry checks. But it **deliberately breaks the spec's ban on token
  passthrough**: the client's Keycloak token goes on to WordPress. That is
  the point of the mode (D4–D6) and is explained below.

## Requirement by requirement

**Status:** **Yes** = met, **Partly** = met with a caveat, **No** = not met,
**IdP** = up to Keycloak's configuration, **n/a** = not applicable.

### Resource server (all modes)

| Requirement | Level | `resource` | `proxy` | `wordpress` | Notes |
|---|---|---|---|---|---|
| Serve RFC 9728 Protected Resource Metadata with at least one entry in `authorization_servers` | MUST | Yes | Yes | Yes | At `/.well-known/oauth-protected-resource/mcp` (path-suffixed form). `resource` = `BASE_URL/mcp`. The root form returns 404, which is allowed: one mechanism suffices and both the header and the path-suffixed URI are served. |
| 401 with `WWW-Authenticate: Bearer resource_metadata="…"` | MUST (one of two mechanisms) | Yes | Yes | Yes | Also on invalid tokens, together with `error="invalid_token"`. |
| `scope` in the `WWW-Authenticate` challenge | SHOULD | No | No | No | By design: the server defines no scopes, and WordPress decides what a user may do (D5). `scopes_supported` is `[]` (`proxy`: `openid email profile`, for the Keycloak login). |
| Validate access tokens (OAuth 2.1 §5.2); invalid or expired → 401 | MUST | Yes | Yes | Yes | Signature, `iss`, `exp`, `aud`. Probed: wrong `aud`, wrong `iss`, expired and garbage tokens all get 401. |
| Accept only tokens issued for this server (audience) | MUST | Partly | Yes | Yes | `wordpress`/`proxy`: `aud` = `BASE_URL/mcp`, the RFC 9728 `resource`. `resource`: `aud` must contain `MCP_AUDIENCE` (default `mcp-wordpress`), a logical name that **WordPress also accepts**. The token is therefore valid at two resources by design ([deviation 1](#1-token-passthrough-to-wordpress-resource-mode-proxy-for-direct-tokens)). |
| Do not pass the client's token on to upstream APIs | MUST NOT | **No** | Partly | Yes | [Deviation 1](#1-token-passthrough-to-wordpress-resource-mode-proxy-for-direct-tokens). |
| Tokens only in the `Authorization` header, never in the query | MUST | Yes | Yes | Yes | `bearer_methods_supported: ["header"]`. `?access_token=` gets 401. |
| 403 + `insufficient_scope` for missing scopes | SHOULD | n/a | n/a | n/a | No scopes (D5). WordPress refusing an ability is a tool error carrying WordPress' message, not an HTTP 403. |
| `offline_access` not in the challenge or in `scopes_supported` | SHOULD NOT | Yes | Yes | Yes | |
| Secure token storage; no tokens in logs | MUST | Yes | Yes | Yes | Nothing stored in `resource`. In `proxy`/`wordpress`, the OAuth state and Application Passwords are Fernet-encrypted (D8). No tokens or `/wp/callback` query strings in logs; the access log is off. |

### Authorization server (`proxy`, `wordpress`; `resource` → Keycloak)

| Requirement | Level | `resource` | `proxy` / `wordpress` | Notes |
|---|---|---|---|---|
| OAuth 2.1 for public and confidential clients | MUST | IdP | Yes | Authorization code + refresh token. Client auth `none` or `private_key_jwt`. |
| RFC 8414 metadata or OIDC Discovery | MUST (one) | IdP | Yes | `/.well-known/oauth-authorization-server`. Keycloak serves OIDC Discovery at `<issuer>/.well-known/openid-configuration`, the path-appended form the spec lists. Under a path prefix, also at the RFC 8414 path-insertion address; the reverse proxy needs two routes ([3](#3-discovery-under-a-path-prefix-fixed-needs-two-proxy-routes)). |
| All endpoints over HTTPS | MUST | IdP | Yes | Config refuses a non-https `BASE_URL` in these modes (plain http only on loopback, D4). |
| PKCE; `code_challenge_methods_supported` advertised | MUST | IdP | Yes | Only `S256` is advertised and accepted. `/authorize` without a challenge, or with `plain`, returns `invalid_request`. A wrong verifier gets `invalid_grant`. |
| RFC 9207: `iss` in authorization responses, including errors; `authorization_response_iss_parameter_supported: true` | SHOULD (MUST advertise if sent) | IdP | Yes | Probed in `wordpress` mode: `iss` is present on success and on `invalid_request`/`invalid_target`, and it equals the metadata `issuer`. `proxy` mode uses the same FastMCP code and advertises the same support. |
| RFC 8707 `resource` honoured | (client MUST send) | IdP | Yes | A foreign `resource` gets `invalid_target`. Tokens carry `aud` = `BASE_URL/mcp`. In `resource` mode the audience comes from a Keycloak audience mapper, not from `resource`. |
| Exact redirect-URI match against registered values | MUST | IdP | Yes | DCR clients: the URIs they registered, with the loopback port allowed to vary as OAuth 2.1 permits. In `wordpress` mode the URI must also be in `OAUTH_REDIRECT_ALLOWLIST` ([2](#2-exact-redirect-uri-match-for-dcr-clients-fixed)). CIMD clients: the document's `redirect_uris` and, in `wordpress` mode, the allowlist. |
| Redirect URIs are loopback or HTTPS | MUST | IdP | Yes | `OAUTH_REDIRECT_ALLOWLIST` refuses plain http except on loopback, and wildcards in the host (D9). |
| Short-lived access tokens | SHOULD | IdP | Yes | `wordpress`: 1 h (`OAUTH_ACCESS_TOKEN_TTL`); refresh 30 days. |
| Rotate refresh tokens for public clients | MUST | IdP | Yes | Probed: refresh issues a new refresh token, and reusing the old one gets `invalid_grant`. |
| User consent per dynamically registered client (confused deputy) | MUST (proxies) | n/a | Yes | The consent screen is always on (D9). It is bound to the browser by a cookie, and the WordPress callback checks that binding first (D7). |
| Consent shows the redirect URI's hostname | MUST | IdP | Yes | It shows "Credentials will be sent to: \<redirect URI\>". |
| Extra warning for loopback-only redirect URIs | SHOULD | IdP | No | FastMCP's consent page shows the URI but no specific warning. |
| Revocation | (OAuth 2.1) | IdP | Yes | `/revoke`. In `wordpress` mode it also deletes the Application Password (D8). In `proxy` mode it is offered only if the upstream discovery document lists a `revocation_endpoint` (Keycloak's does). |

### Client registration

| Requirement | Level | `resource` | `proxy` | `wordpress` | Notes |
|---|---|---|---|---|---|
| Client ID Metadata Documents supported, `client_id_metadata_document_supported: true` | SHOULD | IdP | Yes | Yes | claude.ai uses CIMD. |
| CIMD: fetched document's `client_id` equals the URL | MUST | IdP | Partly | Partly | FastMCP compares after stripping a trailing `/`, a tolerance the spec doesn't grant. |
| CIMD: valid JSON, required fields, redirect URIs validated | MUST | IdP | Yes | Yes | |
| CIMD: cache by HTTP caching headers | SHOULD | IdP | Yes | Yes | FastMCP honours `Cache-Control`, `ETag` and `Last-Modified`. |
| CIMD: SSRF precautions | SHOULD | IdP | Yes | Yes | FastMCP fetches over HTTPS only, pins DNS, blocks private, loopback and link-local addresses, follows no redirects, and caps size and time. `wordpress` mode additionally fetches only URLs listed in `OAUTH_CIMD_ALLOWLIST`, checked before any fetch. `proxy` mode has no allowlist. |
| CIMD trust policy (domain allowlist) | MAY | IdP | No | Yes | `OAUTH_CIMD_ALLOWLIST` (default: claude.ai's two documents). |
| Dynamic Client Registration (deprecated) | MAY | IdP | Yes (on) | Yes (off by default) | `OAUTH_DCR_ENABLED`. ChatGPT needs it (D9). |
| Pre-registration | (client side) | Yes | n/a | n/a | Open WebUI in `resource` mode is a pre-registered Keycloak client that forwards the user's SSO token. It doesn't run the MCP flow at all. |

## Deviations and fixes

### 1. Token passthrough to WordPress (`resource` mode; `proxy` for direct tokens)

> MCP servers **MUST NOT** accept or transit any other tokens. […] The MCP
> server **MUST NOT** pass through the token it received from the MCP
> client. (Overview §Token Handling; Security Considerations §Access Token
> Privilege Restriction)

In `resource` mode the server forwards the bearer token it received to
WordPress, and the MCP Bearer Auth plugin logs the user in with it. This is
the mode's purpose (D4–D6). Open WebUI already holds the user's Keycloak
token, and WordPress should see that very user and no service account
(D5).

What limits the exposure:
- The token must carry `MCP_AUDIENCE` (default `mcp-wordpress`), which only
  this server and the WordPress plugin accept. It is not a general Keycloak
  token. The plugin also checks the signature, issuer, expiry and token
  type.
- WordPress accepts it only on the Abilities and MCP routes plus
  `GET /wp/v2/users/me`, never for cookies, wp-admin or other REST routes
  (D6).

What remains: the token is valid at two resources (this server and those
WordPress routes). Anyone who obtains it, whether a log, a compromised MCP
server or a client that sends it elsewhere, can call WordPress directly as
that user until it expires. The spec's rule exists to prevent exactly this.

`proxy` mode keeps the tokens apart for clients that use its own
OAuth flow: the client gets a FastMCP token (`aud` = `BASE_URL/mcp`), and
the server presents a separate upstream Keycloak token to WordPress, as the
spec allows. But `ProxyAcceptingDirectTokens` also accepts Keycloak tokens
presented directly (for Open WebUI) and forwards those, so it inherits
deviation 1 for them.

**Spec-conformant alternatives** (none implemented):
- `wordpress` mode, if users can sign in with their WordPress account.
- RFC 8693 token exchange: the server trades the client's token at
  Keycloak for a token whose audience is WordPress only, and the plugin
  stops accepting `mcp-wordpress`. Keycloak supports token exchange, but
  this needs Keycloak and plugin configuration and another round-trip per
  token.
- `proxy` mode without direct tokens, for MCP clients that do the OAuth
  flow (not Open WebUI's "forward my SSO token" mode).

### 2. Exact redirect-URI match for DCR clients (fixed)

> Authorization servers **MUST** validate exact redirect URIs against
> pre-registered values. (Security Considerations §Open Redirection)

In `wordpress` mode, `OAUTH_REDIRECT_ALLOWLIST` is passed to FastMCP as
`allowed_client_redirect_uris`. With that set, FastMCP's `ProxyDCRClient`
checks a DCR client's `redirect_uri` at `/authorize` against the allowlist
only. Until this fix, a client registered with
`http://localhost:3000/callback` could start a flow with
`http://localhost:3999/other`, or with another platform's allowlisted
callback.

`WordPressAuthServer.get_client` now hands FastMCP a
`RegisteredRedirectClient` for every DCR client. That client first
requires the `redirect_uri` to be one it registered (FastMCP's own
matcher: exact, except that the port of a loopback URI may vary, as OAuth
2.1 allows), then applies the allowlist as before. CIMD clients were
already held to their document's `redirect_uris` and are unchanged.
`tests/test_wp_oauth.py::test_authorize_only_with_a_registered_redirect_uri`
covers it and fails without the check.

### 3. Discovery under a path prefix (fixed; needs two proxy routes)

With `BASE_URL` at a path (e.g. `https://ai.example.com/mcp/wordpress`),
the issuer has a path. For such an issuer, the spec has clients try only
these:
1. `https://ai.example.com/.well-known/oauth-authorization-server/mcp/wordpress`
2. `https://ai.example.com/.well-known/openid-configuration/mcp/wordpress`
3. `https://ai.example.com/mcp/wordpress/.well-known/openid-configuration`

FastMCP serves the metadata only at
`<BASE_URL>/.well-known/oauth-authorization-server`, which isn't on that
list. The server now also answers address 1. `EndpointPaths` maps
`/.well-known/oauth-authorization-server<prefix>` onto the metadata route
(`tests/test_reverse_proxy.py`, `proxy` and `wordpress` mode).

Addresses at the host's root never reach the app on their own, though.
The reverse proxy must forward two paths to the app **unchanged** (README,
"Serving under a path"):
- `/.well-known/oauth-protected-resource/mcp/wordpress/mcp`: protected
  resource metadata, all modes. This is the URL in the `WWW-Authenticate`
  header.
- `/.well-known/oauth-authorization-server/mcp/wordpress`: authorization
  server metadata (`proxy`, `wordpress`).

Deployments at the host root (`https://mcp-wp.example.com`) need nothing.

### 4. Smaller points

- **Issuer with a trailing slash.** The issuer is `https://host/`, which
  is how FastMCP and pydantic normalise URLs. It is consistent everywhere
  (metadata `issuer`, `authorization_servers`, `iss` in responses), so
  RFC 9207 string comparison works. The spec recommends the form without
  the slash for interoperability.
- **No `scope` in challenges, no `insufficient_scope`.** These are
  deliberate (D5): permissions live in WordPress and surface as tool
  errors.
- **CIMD `client_id` comparison** tolerates a trailing `/` (FastMCP).
- **No loopback-specific warning** on the consent page (a SHOULD).

## Client side

This server is not an MCP client. The client MUSTs, such as sending
`resource`, PKCE, `iss` validation and the discovery order, apply to
claude.ai, ChatGPT and Open WebUI. Two of them interact with the modes:
- Open WebUI in `resource` mode doesn't run the MCP authorization flow. It
  forwards the user's Keycloak token, which is the source of deviation 1.
- A spec-following client in `resource` mode discovers Keycloak through
  the protected resource metadata. For its token to be accepted, its
  Keycloak client needs the `mcp-wordpress` audience mapper, because
  Keycloak doesn't set `aud` from the RFC 8707 `resource` parameter by
  default.
