<?php
/**
 * sso-login-oidc settings for the test stack, run by wp-setup.sh via
 * `wp eval-file`. Goes through the plugin's own Sanitizer and Settings, as
 * the settings page would:
 *
 * - one provider, `keycloak`, for the realm the e2e runner gets tokens from;
 * - bearer token authentication on, audience mcp-wordpress (what this
 *   server's MCP_AUDIENCE is, and what Keycloak's audience mapper adds);
 * - alice and bob linked to their Keycloak subjects (fixed ids from
 *   init/prepare.sh), the way a first SSO login would link them. carol
 *   stays unlinked.
 *
 * @package mcp-wordpress-oauth test stack
 */

use SSOLoginOIDC\Settings\Sanitizer;
use SSOLoginOIDC\Settings\Settings;
use SSOLoginOIDC\Users\User_Provisioner;

$issuer = 'http://keycloak:8080/realms/wp';

Settings::update(
	Sanitizer::sanitize_full(
		array(
			'providers' => array(
				'default_id' => 'keycloak',
				'rows'       => array(
					array(
						'id'                 => 'keycloak',
						'label'              => 'Keycloak',
						'issuer'             => $issuer,
						'client_id'          => 'wordpress',
						'client_secret'      => 'not-used-by-the-e2e-run',
						'scopes'             => 'openid email profile',
						'client_auth_method' => 'client_secret_basic',
						'enabled'            => true,
					),
				),
			),
			'bearer'    => array(
				'enabled'        => true,
				'provider_id'    => 'keycloak',
				'audience'       => 'mcp-wordpress',
				'required_scope' => '',
			),
		),
		Settings::all()
	)
);

$bearer = Settings::get( 'bearer' );
if ( empty( $bearer['enabled'] ) || 'mcp-wordpress' !== ( $bearer['audience'] ?? '' ) ) {
	WP_CLI::error( 'sso-login-oidc did not keep the bearer settings: ' . wp_json_encode( $bearer ) . ' (plugin version without the bearer feature?)' );
}
if ( ! class_exists( 'SSOLoginOIDC\\Auth\\Bearer_Auth' ) ) {
	WP_CLI::error( 'sso-login-oidc has no Auth\\Bearer_Auth: SSO_PLUGIN_DIR must point at a version with the bearer feature.' );
}

$links = array(
	'alice' => '00000000-0000-4000-8000-0000000a11ce',
	'bob'   => '00000000-0000-4000-8000-000000000b0b',
);
foreach ( $links as $login => $subject ) {
	$user = get_user_by( 'login', $login );
	if ( ! $user ) {
		WP_CLI::error( "No WordPress user {$login}." );
	}
	update_user_meta( $user->ID, User_Provisioner::META_ISSUER, $issuer );
	update_user_meta( $user->ID, User_Provisioner::META_SUBJECT, $subject );
}
$carol = get_user_by( 'login', 'carol' );
if ( $carol ) {
	delete_user_meta( $carol->ID, User_Provisioner::META_ISSUER );
	delete_user_meta( $carol->ID, User_Provisioner::META_SUBJECT );
}

WP_CLI::success( 'sso-login-oidc: provider keycloak, bearer on (audience mcp-wordpress), alice and bob linked.' );
