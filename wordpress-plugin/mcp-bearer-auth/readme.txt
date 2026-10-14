=== MCP Bearer Auth ===
Tags: mcp, oidc, oauth, abilities, rest-api
Requires at least: 6.9
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 0.0.0-dev
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lets an MCP server act as a WordPress user by presenting that user's own access token from your OIDC provider.

== Description ==

MCP Bearer Auth lets [mcp-wordpress-oauth](https://github.com/linuxrrze/mcp-wordpress-oauth) (`AUTH_MODE=resource` or `proxy`) call WordPress as the signed-in user, with that user's own access token from your OIDC provider (Keycloak, Authentik, Entra ID, ...) in an `Authorization: Bearer` header.

* Only REST requests on `/wp-abilities/v1/...`, `/mcp/...` and `GET /wp/v2/users/me` are affected. Cookies, wp-admin, XML-RPC and every other route are left alone.
* Tokens must be signed with an asymmetric key from the issuer's JWKS, carry the configured issuer and audience, and be access tokens.
* The token's user must already exist in WordPress, matched by a subject stored by your login plugin, a verified email, or the login name. Nothing is created or linked.
* Works alongside any OIDC login plugin.

You don't need it for `AUTH_MODE=wordpress`, which uses core Application Passwords.

== Installation ==

1. Upload `mcp-bearer-auth.zip` from the plugin's [GitHub release](https://github.com/linuxrrze/mcp-wordpress-oauth/releases) under Plugins > Add New > Upload Plugin, and activate it.
2. Configure it in `wp-config.php`, at least `MCP_BEARER_ISSUER` (exactly the tokens' `iss`) and `MCP_BEARER_USER_MATCH` (`meta:<key>`, `email` or `login`). All options are in the plugin's README.md.
3. Later versions arrive through Dashboard > Updates like any other plugin. Use "Enable auto-updates" on the Plugins screen, or set `MCP_BEARER_AUTO_UPDATE` to `true` in `wp-config.php`.

Set `MCP_BEARER_UPDATE_CHECK` to `false` if the site must not contact GitHub.

== Frequently Asked Questions ==

= Every bearer request is treated as anonymous =

Some Apache/CGI setups drop the `Authorization` header. Add `SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1` to `.htaccess`.

= Which errors can the MCP server see? =

401 `mcp_bearer_invalid` (token refused or plugin not configured), 401 `mcp_bearer_unmatched` (no matching user), 403 `mcp_bearer_scope`, 403 `mcp_bearer_forbidden` and 403 `mcp_bearer_https`.

== Changelog ==

See the plugin's releases on GitHub (tags `mcp-bearer-auth-v*`).
