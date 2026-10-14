<?php
/**
 * MCP Bearer Auth for the test stack, run by wp-setup.sh via
 * `wp eval-file`.
 *
 * The plugin is configured by MCP_BEARER_* constants (WORDPRESS_CONFIG_EXTRA
 * in docker-compose.yml). Here: store alice's and bob's Keycloak subjects
 * (fixed ids from init/prepare.sh) in the user meta key an OIDC login plugin
 * (OpenID Connect Generic) keeps them in, as a first SSO login would.
 * carol stays unmatched.
 *
 * @package mcp-wordpress-oauth test stack
 */

use MCPBearerAuth\Config;

if ( ! class_exists( Config::class ) ) {
	WP_CLI::error( 'MCP Bearer Auth is not loaded (plugin inactive or vendor/ missing).' );
}

$config = Config::load();
if ( is_wp_error( $config ) ) {
	WP_CLI::error( 'MCP Bearer Auth configuration: ' . $config->get_error_message() );
}
if ( 'meta' !== $config->user_match ) {
	WP_CLI::error( 'The test stack expects MCP_BEARER_USER_MATCH=meta:<key>.' );
}

$subjects = array(
	'alice' => '00000000-0000-4000-8000-0000000a11ce',
	'bob'   => '00000000-0000-4000-8000-000000000b0b',
);
foreach ( $subjects as $login => $subject ) {
	$user = get_user_by( 'login', $login );
	if ( ! $user ) {
		WP_CLI::error( "No WordPress user {$login}." );
	}
	update_user_meta( $user->ID, $config->meta_key, $subject );
}
$carol = get_user_by( 'login', 'carol' );
if ( $carol ) {
	delete_user_meta( $carol->ID, $config->meta_key );
}

WP_CLI::success( "MCP Bearer Auth: issuer {$config->issuer}, audience {$config->audience}, alice and bob matched by {$config->meta_key}." );
