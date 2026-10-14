<?php
/**
 * Settings from wp-config.php constants.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth;

/**
 * The plugin's configuration. Constants, not an options page: whoever can
 * change these decides which tokens log in as which users, so they belong
 * with the other secrets in wp-config.php, not in the database.
 *
 * - MCP_BEARER_ISSUER         (required) the tokens' `iss`, exactly.
 * - MCP_BEARER_USER_MATCH     (required) how a token finds its user:
 *                             "meta:<key>" (user meta <key> = `sub`),
 *                             "email" (verified `email` claim) or
 *                             "login" (MCP_BEARER_LOGIN_CLAIM = user_login).
 * - MCP_BEARER_AUDIENCE       `aud` the token must contain (mcp-wordpress).
 * - MCP_BEARER_JWKS_URI       keys URL; default: from the issuer's discovery.
 * - MCP_BEARER_LOGIN_CLAIM    claim for "login" matching (preferred_username).
 * - MCP_BEARER_REQUIRED_SCOPE scope the token must carry (none).
 *
 * All of it can also be set with the `mcp_bearer_auth_config` filter.
 */
final class Config {

	/**
	 * Asymmetric signatures only: a shared-secret (HS*) token could be
	 * minted by anyone holding the secret, i.e. by more than the provider.
	 */
	const ALGORITHMS = array( 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'EdDSA' );

	/**
	 * Issuer (`iss`), without trailing slash.
	 *
	 * @var string
	 */
	public $issuer;

	/**
	 * Required audience.
	 *
	 * @var string
	 */
	public $audience;

	/**
	 * JWKS URL, or '' for discovery.
	 *
	 * @var string
	 */
	public $jwks_uri;

	/**
	 * "meta", "email" or "login".
	 *
	 * @var string
	 */
	public $user_match;

	/**
	 * User meta key holding the subject ("meta" matching).
	 *
	 * @var string
	 */
	public $meta_key;

	/**
	 * Claim holding the user_login ("login" matching).
	 *
	 * @var string
	 */
	public $login_claim;

	/**
	 * Scope the token must carry, or ''.
	 *
	 * @var string
	 */
	public $required_scope;

	/**
	 * Read and validate the configuration.
	 *
	 * @return Config|\WP_Error
	 */
	public static function load() {
		$raw = array(
			'issuer'         => self::constant( 'MCP_BEARER_ISSUER' ),
			'audience'       => self::constant( 'MCP_BEARER_AUDIENCE', 'mcp-wordpress' ),
			'jwks_uri'       => self::constant( 'MCP_BEARER_JWKS_URI' ),
			'user_match'     => self::constant( 'MCP_BEARER_USER_MATCH' ),
			'login_claim'    => self::constant( 'MCP_BEARER_LOGIN_CLAIM', 'preferred_username' ),
			'required_scope' => self::constant( 'MCP_BEARER_REQUIRED_SCOPE' ),
		);

		/**
		 * Filters the configuration read from the MCP_BEARER_* constants.
		 *
		 * @param array $raw issuer, audience, jwks_uri, user_match, login_claim, required_scope.
		 */
		$raw = (array) apply_filters( 'mcp_bearer_auth_config', $raw );

		return self::from_array( $raw );
	}

	/**
	 * Validate a configuration array.
	 *
	 * @param array $raw See load().
	 * @return Config|\WP_Error
	 */
	public static function from_array( array $raw ) {
		$config                 = new self();
		$config->issuer         = rtrim( trim( (string) ( $raw['issuer'] ?? '' ) ), '/' );
		$config->audience       = trim( (string) ( $raw['audience'] ?? '' ) );
		$config->jwks_uri       = trim( (string) ( $raw['jwks_uri'] ?? '' ) );
		$config->login_claim    = trim( (string) ( $raw['login_claim'] ?? '' ) );
		$config->required_scope = trim( (string) ( $raw['required_scope'] ?? '' ) );
		$match                  = trim( (string) ( $raw['user_match'] ?? '' ) );

		if ( '' === $config->issuer || ! self::is_url( $config->issuer ) ) {
			return self::error( 'MCP_BEARER_ISSUER must be the http(s) URL of your provider, exactly as in the tokens\' iss claim.' );
		}

		if ( '' !== $config->jwks_uri && ! self::is_url( $config->jwks_uri ) ) {
			return self::error( 'MCP_BEARER_JWKS_URI must be an http(s) URL.' );
		}

		if ( '' === $config->audience ) {
			return self::error( 'MCP_BEARER_AUDIENCE must not be empty: a token meant for any other service would be accepted.' );
		}

		if ( 0 === strpos( $match, 'meta:' ) && '' !== trim( substr( $match, 5 ) ) ) {
			$config->user_match = 'meta';
			$config->meta_key   = trim( substr( $match, 5 ) );
		} elseif ( in_array( $match, array( 'email', 'login' ), true ) ) {
			$config->user_match = $match;
			$config->meta_key   = '';
		} else {
			return self::error( 'MCP_BEARER_USER_MATCH must be "meta:<user meta key>", "email" or "login".' );
		}

		if ( 'login' === $config->user_match && '' === $config->login_claim ) {
			return self::error( 'MCP_BEARER_LOGIN_CLAIM must not be empty.' );
		}

		return $config;
	}

	/**
	 * A constant's value, or the default when it isn't defined.
	 *
	 * @param string $name    Constant name.
	 * @param string $fallback Default.
	 * @return string
	 */
	private static function constant( $name, $fallback = '' ) {
		return defined( $name ) ? (string) constant( $name ) : $fallback;
	}

	/**
	 * Whether a value is an absolute http(s) URL.
	 *
	 * @param string $url Value.
	 * @return bool
	 */
	private static function is_url( $url ) {
		$scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );

		return in_array( $scheme, array( 'http', 'https' ), true ) && '' !== (string) wp_parse_url( $url, PHP_URL_HOST );
	}

	/**
	 * A configuration error.
	 *
	 * @param string $message Message for administrators.
	 * @return \WP_Error
	 */
	private static function error( $message ) {
		return new \WP_Error( 'mcp_bearer_config', $message );
	}
}
