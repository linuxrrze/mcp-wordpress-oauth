# Disposable test stack

Keycloak, WordPress 6.9 (with the MCP Bearer Auth plugin from
`../wordpress-plugin`, "Enable Abilities for MCP" and a set of test abilities) and this server in both
`AUTH_MODE=resource` and `AUTH_MODE=wordpress`, plus end-to-end checks of
both chains. Use it to try the setup, to compare against your own
configuration, or to reproduce a problem. CI runs the same checks before
every release.

```bash
docker compose -f test-stack/docker-compose.yml up -d --build
docker compose -f test-stack/docker-compose.yml run --rm e2e
docker compose -f test-stack/docker-compose.yml down -v          # removes everything
```

`run --rm e2e` also starts the stack if it isn't up yet. `E2E_MODE=resource`
or `E2E_MODE=wordpress` runs only one mode's checks (default: both).

The stack is self-contained. **MCP Bearer Auth** comes from
`wordpress-plugin/mcp-bearer-auth` in this repository; service `bearer-plugin`
copies it and runs `composer install` on the copy. No OIDC login plugin is
installed: `wp-setup` stores alice's and bob's Keycloak subjects in the user
meta key OpenID Connect Generic uses
(`MCP_BEARER_USER_MATCH=meta:openid-connect-generic-subject-identity`), the
way a first SSO login would.

```mermaid
flowchart LR
    e2e["e2e runner<br/>(Open WebUI + browser)"] -- "Keycloak token" --> res["mcp-resource :8000<br/>AUTH_MODE=resource"]
    e2e -- "OAuth 2.1 flow,<br/>its own tokens" --> wpm["mcp-wp :8001<br/>AUTH_MODE=wordpress"]
    res -- "same Keycloak token<br/>(Bearer)" --> wp["wordpress<br/>WP 6.9 + MCP Bearer Auth"]
    wpm -- "Application Password<br/>(Basic)" --> wp
    wp -- "JWKS" --> kc["keycloak :8080<br/>realm wp"]
    res -- "JWKS" --> kc
    e2e -- "password grant" --> kc
    e2e -- "wp-login,<br/>authorize-application.php" --> wp
```

## What gets started

| Service | What it is |
|---|---|
| `init` | Writes the realm to import (`init/prepare.sh`) |
| `keycloak` | Keycloak 26, dev mode, realm `wp`: users `alice`, `bob`, `carol` (password = username, fixed ids); client `openwebui` with an audience mapper for `mcp-wordpress`; client `other` without one |
| `bearer-plugin` | MCP Bearer Auth from `../wordpress-plugin/mcp-bearer-auth`, with `composer install --no-dev`, into a volume |
| `db` | MariaDB for WordPress |
| `wordpress` | `wordpress:6.9-apache`, `WP_ENVIRONMENT_TYPE=local` (Application Passwords and bearer auth over plain HTTP), `MCP_BEARER_*` constants, the must-use plugin [`wordpress/e2e-abilities.php`](wordpress/e2e-abilities.php) |
| `wp-setup` | wp-cli: installs WordPress, users alice (administrator), bob (author), carol (editor), activates MCP Bearer Auth and "Enable Abilities for MCP", stores alice's and bob's Keycloak subjects in user meta (carol: none) ([`wordpress/wp-setup.sh`](wordpress/wp-setup.sh), [`wordpress/provision.php`](wordpress/provision.php)) |
| `mcp-resource` | This server, `AUTH_MODE=resource`, built from the working tree |
| `mcp-wp` | This server, `AUTH_MODE=wordpress`, DCR on |
| `e2e` | [`e2e.py`](e2e.py), run on demand |

Containers talk to each other by service name, and those names are also the
URLs that appear in tokens (`iss` = `http://keycloak:8080/realms/wp`) and
WordPress' site URL (`http://wordpress`). `mcp-wp` is the exception: as an
OAuth issuer its `BASE_URL` must be https or loopback, so it is
`http://localhost:8001` (OAuth redirects go to
`http://localhost:8001/wp/callback`), and `e2e` runs in `mcp-wp`'s network
namespace to reach it there. The e2e runner plays the browser, so the host
doesn't need to resolve anything. To click through by hand, map `keycloak`
and `wordpress` to 127.0.0.1 in your hosts file and use the ports from the
compose file (8080, 8081, 8001).

`EAM=off` skips installing "Enable Abilities for MCP" (it needs internet
access from the wp-setup container); the checks only use the test abilities.

## The test abilities

Each returns `{method, input, user}`: the HTTP method WordPress' run
controller received, the input it saw, and the user it ran as.

| Ability | Annotations | Method | Input |
|---|---|---|---|
| `e2e/get-info` | readonly | GET | object (query string `input[a][b]=…`) |
| `e2e/update-note` | – | POST | object (JSON body) |
| `e2e/delete-note` | destructive, idempotent | DELETE | integer (`?input=7`) |
| `e2e/echo-text` | – | POST | string (wrapped as `{"input": …}` by the MCP tool) |
| `e2e/editor-only` | readonly | GET | none; runs only for `edit_others_posts` |
| `e2e/editor-tools` | readonly | GET | none; only *listed* for `edit_others_posts` |
| `e2e/not-public` | readonly | – | not `meta.mcp.public`, so never a tool |

## What the checks cover

In order; the first failure stops the run and names the failing link.

**`AUTH_MODE=resource`**

1. Keycloak issues alice, bob and carol tokens; alice's has `mcp-wordpress` in `aud`.
2. WordPress itself accepts alice's token on `/wp/v2/users/me` (bearer feature,
   `Authorization` header reaches PHP), ignores it on a route that isn't
   allowlisted (`/wp/v2/settings`: 401), and refuses a token from client
   `other` (no `mcp-wordpress` audience).
3. The MCP server: 401 with resource metadata without a token, 401 for the
   `other` token.
4. alice and bob get different tool lists (`e2e-editor-tools`), and
   `e2e-not-public` is never a tool.
5. `whoami` says alice, administrator.
6. The run controller's method rule and input encoding, against real
   WordPress: GET with a nested query string, POST with a JSON body (as bob),
   DELETE with a scalar, a wrapped string input.
7. bob running `e2e-editor-only` gets a tool error naming
   `rest_ability_cannot_execute`; alice may run it.
8. carol (no matching WordPress account) gets only `whoami`, and it explains
   what's missing.

**`AUTH_MODE=wordpress`**

1. Authorization server metadata: registration (DCR is on in the stack),
   revocation, CIMD. 401 without a token and for a Keycloak token.
2. DCR refuses a redirect URI outside the allowlist and accepts a loopback one.
3. bob logs in to WordPress, approves the consent screen, and **rejects** in
   `authorize-application.php`: the MCP client gets `error=access_denied`
   with its state.
4. alice does the same and **approves**: WordPress creates an Application
   Password and sends it to `/wp/callback`; the client gets a code, then
   access and refresh tokens.
5. With that token: the e2e tools, `whoami` as alice, a POST and a DELETE
   ability running as alice (Basic auth with the Application Password).
6. Refresh works.
7. `/revoke` deletes the Application Password in WordPress (Basic auth with
   it now fails), and both the access and the refresh token stop working.

## When something fails

```bash
docker compose -f test-stack/docker-compose.yml logs wp-setup wordpress mcp-resource mcp-wp
docker compose -f test-stack/docker-compose.yml exec wordpress tail -n 50 /var/www/html/wp-content/debug.log
```

`wp-setup` failing usually means MCP Bearer Auth didn't load (`bearer-plugin`
couldn't run `composer install`) or wordpress.org wasn't reachable (`EAM=off`).
