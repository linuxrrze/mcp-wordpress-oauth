# MCP Bearer Auth (WordPress plugin)

This plugin lets mcp-wordpress-oauth (`AUTH_MODE=resource` or `proxy`) act as
a WordPress user by presenting **that user's own access token** from your
OIDC provider (Keycloak, Authentik, Entra ID, …):

```
Authorization: Bearer <access token>
```

It works alongside any plugin that handles browser login, because it only
reads what that plugin stores. You don't need it for `AUTH_MODE=wordpress`,
which uses core Application Passwords.

## What it accepts

- **Routes:** only REST requests on `/wp-abilities/v1/…`, `/mcp/…` and
  `GET /wp/v2/users/me`. You can change this list with the
  `mcp_bearer_auth_routes` filter. Cookies, wp-admin, XML-RPC and every other
  REST route are left alone. A request that already has a user (cookie or
  Application Password) is never touched.
- **Tokens:** the token must be signed with an asymmetric algorithm (RS*,
  PS*, ES256/384 or EdDSA) by a key from the issuer's JWKS. Its `iss` must
  equal `MCP_BEARER_ISSUER` and its `aud` must contain `MCP_BEARER_AUDIENCE`.
  It also needs `exp` and `sub`, and must be an access token: ID and logout
  tokens are refused.
- **Users:** the token's user must be an existing WordPress user, found as
  configured below. Nothing is created or linked here.
- **HTTPS:** requests and key downloads must use HTTPS, except when
  `WP_ENVIRONMENT_TYPE` is `local`.

## Configuration (`wp-config.php`)

```php
define( 'MCP_BEARER_ISSUER', 'https://sso.example.com/realms/main' ); // exactly the tokens' iss
define( 'MCP_BEARER_USER_MATCH', 'meta:_sso_oidc_subject' );           // see below
// Optional:
define( 'MCP_BEARER_AUDIENCE', 'mcp-wordpress' );       // default; = the MCP server's MCP_AUDIENCE
define( 'MCP_BEARER_JWKS_URI', '' );                    // default: from the issuer's discovery document
define( 'MCP_BEARER_LOGIN_CLAIM', 'preferred_username' );
define( 'MCP_BEARER_REQUIRED_SCOPE', '' );
```

`MCP_BEARER_USER_MATCH` sets how a token finds its WordPress user:

| Value | Matches | Use when |
|---|---|---|
| `meta:<key>` | the user whose meta `<key>` equals the token's `sub` | your login plugin stores the subject. This is the most robust option, because subjects never change or get reassigned. |
| `email` | the user with the token's `email`, if `email_verified` is `true` | your login plugin matches by email, and the provider verifies addresses |
| `login` | the user whose `user_login` equals the `MCP_BEARER_LOGIN_CLAIM` claim | users can't pick that name themselves at the provider |

Subject meta keys of common login plugins:

| Login plugin | `MCP_BEARER_USER_MATCH` |
|---|---|
| sso-login-oidc | `meta:_sso_oidc_subject` |
| OpenID Connect Generic Client | `meta:openid-connect-generic-subject-identity` |

With `meta:` matching, a user must have signed in through the login plugin
once, so that the subject is stored. If two users carry the same subject, the
plugin refuses the token rather than picking one.

If the plugin isn't configured, it refuses bearer tokens on its routes, and
administrators see a notice that names the problem.

## Errors

| Status | Code | When |
|---|---|---|
| 401 | `mcp_bearer_invalid` | The token was refused (signature, issuer, audience, expiry, type), or the plugin isn't configured |
| 401 | `mcp_bearer_unmatched` | The token is valid, but no WordPress user matches it |
| 403 | `mcp_bearer_scope` | The token lacks `MCP_BEARER_REQUIRED_SCOPE` |
| 403 | `mcp_bearer_forbidden` | The user was refused: not a member of this site on multisite, or refused by the `mcp_bearer_auth_user` filter |
| 403 | `mcp_bearer_https` | The request used plain HTTP outside a local environment |

## Hooks

- **`mcp_bearer_auth_config`** (filter): the configuration array, as an
  alternative to the constants.
- **`mcp_bearer_auth_routes`** (filter): the accepted routes. Each entry has
  `prefix` or `route`, and optionally `methods`.
- **`mcp_bearer_auth_user`** (filter): return a `WP_Error` to refuse a matched
  user, for example a user deactivated by your login plugin.
- **`mcp_bearer_auth_failed`** (action): receives `$reason` and `$context`, for
  audit logs. The context never contains the token.

## Apache

Some Apache/CGI setups drop the `Authorization` header before PHP sees it.
If every bearer request is treated as anonymous, add this to `.htaccess`:

```
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
```

## Install and develop

You need the `vendor/` directory, which holds firebase/php-jwt.

- **Install:** use the zip that CI builds, or run `composer install --no-dev`
  in this directory.
- **Develop:** run `composer install`, then `composer test` and
  `composer phpcs`.

php-jwt classes are shared across plugins. If another plugin loads an older
php-jwt (6.x) first, that copy is used instead, and its API is compatible.
