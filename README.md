# mcp-wordpress-oauth

An MCP server that gives an AI assistant a WordPress site's **Abilities** as
tools, one tool per ability, and runs every call **as the signed-in WordPress
user**, with that user's own permissions. It needs no admin or service
account.

It needs WordPress 6.9+ (Abilities API). Abilities come from plugins such as
[Enable Abilities for MCP](https://wordpress.org/plugins/enable-abilities-for-mcp/),
and admins switch them on and off in WordPress.

## Three ways to sign in (`AUTH_MODE`)

| Mode | For | Users sign in with | Server stores |
|---|---|---|---|
| `resource` (default) | Open WebUI + Keycloak | their Keycloak SSO login, forwarded by Open WebUI | nothing |
| `proxy` | MCP clients that need the MCP OAuth flow (DCR) + Keycloak | Keycloak, via this server | client registrations, sessions |
| `wordpress` | claude.ai, ChatGPT, Claude Code; no Keycloak | their WordPress account (Application Password) | encrypted Application Passwords, sessions |

### `resource`: one Keycloak token end to end

```mermaid
sequenceDiagram
    participant OW as Open WebUI
    participant MCP as mcp-wordpress-oauth
    participant WP as WordPress + sso-login-oidc

    OW->>MCP: tools/call, Bearer (user's Keycloak token)
    Note over MCP: Verifies signature, issuer,<br/>audience mcp-wordpress
    MCP->>WP: /wp-abilities/v1/…/run, Bearer (same token)
    Note over WP: sso-login-oidc bearer feature:<br/>same checks, (iss, sub) → linked user
    WP-->>MCP: Result, as that user
    MCP-->>OW: Tool result
```

This mode needs the **bearer token feature of sso-login-oidc** (Settings > SSO
Login OIDC > Advanced): enable it, set the audience to `mcp-wordpress` and
use the same provider as `OIDC_ISSUER`. Each user must have signed in to
WordPress with SSO once, which links their accounts. Keycloak tokens need
`mcp-wordpress` in `aud` (audience mapper). Some Apache/CGI setups drop the
`Authorization` header before PHP sees it. If WordPress answers every call
as if no one were signed in, add
`SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1` to `.htaccess`.

### `wordpress`: this server is the OAuth server

```mermaid
sequenceDiagram
    actor U as User
    participant C as claude.ai / ChatGPT
    participant MCP as mcp-wordpress-oauth
    participant WP as WordPress

    C->>MCP: /authorize (CIMD or registered client)
    MCP->>U: Consent screen
    U->>WP: authorize-application.php: log in, approve "MCP"
    WP->>MCP: /wp/callback with a new Application Password
    Note over MCP: Checks consent cookie, site, password;<br/>stores it encrypted
    MCP->>C: code → access + refresh token
    C->>MCP: tools/call
    MCP->>WP: run ability, Basic auth (user's Application Password)
```

- **claude.ai:** Settings > Connectors > Add custom connector, with
  `https://<BASE_URL>/mcp`. Claude identifies itself by its client metadata
  URL, which is in `OAUTH_CIMD_ALLOWLIST` by default.
- **ChatGPT:** needs Dynamic Client Registration. Set `OAUTH_DCR_ENABLED=on`.
  Its callback URLs are in `OAUTH_REDIRECT_ALLOWLIST` by default.
- Users find the connection in their WordPress profile under *Application
  Passwords* (named `OAUTH_APP_NAME`). Revoking it there ends the MCP
  session within `WP_CREDENTIAL_RECHECK` seconds.
- WordPress only creates Application Passwords over HTTPS. Both the site
  and `BASE_URL` must be HTTPS.

## Run

```bash
cp .env.example .env    # set BASE_URL, WORDPRESS_URL, AUTH_MODE and its settings
docker compose up -d
```

Put a TLS reverse proxy in front. In `wordpress` mode, it must **not log query
strings** for `/wp/callback`: WordPress sends the new Application Password
there (docs/decisions.md, D8). The server's own access log is off.

The MCP endpoint is `BASE_URL + /mcp`. On startup, the server logs the
client settings to use. `GET /healthz` needs no token.

## Tools

- `whoami`: which WordPress user you act as, your roles, and how many
  abilities you have as tools.
- One tool per ability that WordPress lists for you, for example
  `core-get-site-info` for `core/get-site-info`. Tools use the ability's label,
  description, JSON schemas and annotations (read-only, destructive,
  idempotent). Which abilities qualify:
  - `ABILITY_MCP_PUBLIC_ONLY=on` (default): only abilities flagged
    `meta.mcp.public`, like WordPress' MCP Adapter.
  - `ABILITY_ALLOW` / `ABILITY_DENY`: globs such as `core/*,ewpa/*`; deny wins.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The unit and HTTP tests need neither Keycloak nor WordPress. The end-to-end
stack with real WordPress, Keycloak and sso-login-oidc is in `test-stack/`
(Docker).

Why things are the way they are: [docs/decisions.md](docs/decisions.md).
