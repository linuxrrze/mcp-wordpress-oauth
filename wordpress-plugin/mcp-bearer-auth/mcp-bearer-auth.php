<?php
/**
 * Plugin Name:       MCP Bearer Auth
 * Description:       Lets an MCP server act as a WordPress user by presenting that user's own access token from your OIDC provider (Authorization: Bearer), on the Abilities and MCP REST routes only. Works next to any OIDC login plugin.
 * Version:           0.1.0
 * Requires at least: 6.9
 * Requires PHP:      8.1
 * Author:            Marcel Ritter
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mcp-bearer-auth
 *
 * Configuration: constants in wp-config.php, see README.md.
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
