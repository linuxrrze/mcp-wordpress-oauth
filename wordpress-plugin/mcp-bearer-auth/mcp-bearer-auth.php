<?php
/**
 * Plugin Name:       MCP Bearer Auth
 * Plugin URI:        https://github.com/linuxrrze/mcp-wordpress-oauth/tree/main/wordpress-plugin/mcp-bearer-auth
 * Description:       Lets an MCP server act as a WordPress user by presenting that user's own access token from your OIDC provider (Authorization: Bearer), on the Abilities and MCP REST routes only. Works next to any OIDC login plugin.
 * Version:           0.0.0-dev
 * Requires at least: 6.9
 * Requires PHP:      8.1
 * Author:            Marcel Ritter
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mcp-bearer-auth
 * Update URI:        https://github.com/linuxrrze/mcp-wordpress-oauth
 *
 * Configuration: constants in wp-config.php, see README.md.
 *
 * CI stamps the release version (tag mcp-bearer-auth-vX.Y.Z) into the zip;
 * a checkout says 0.0.0-dev. Updates come from the plugin releases of the
 * repository in the header above (src/Updater.php).
 *
 * @package MCPBearerAuth
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! is_readable( __DIR__ . '/vendor/autoload.php' ) ) {
	add_action(
		'admin_notices',
		static function () {
			if ( current_user_can( 'activate_plugins' ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'MCP Bearer Auth is missing its vendor/ directory. Install a release zip, or run composer install --no-dev in the plugin directory.', 'mcp-bearer-auth' ) . '</p></div>';
			}
		}
	);
	return;
}

require_once __DIR__ . '/vendor/autoload.php';

( new MCPBearerAuth\Bearer_Auth() )->register_hooks();
( new MCPBearerAuth\Updater( __FILE__ ) )->register_hooks();
