<?php
/**
 * Bearer token authentication for the Abilities and MCP REST routes.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth;

/**
 * Hooks into WordPress' authentication.
 *
 * Deliberately narrow:
 * - only REST requests on the routes in ROUTES (filterable), never cookies,
 *   wp-admin, XML-RPC or other REST routes;
 * - the token's `aud` must contain MCP_BEARER_AUDIENCE, so a token issued
 *   for anything else (including this site's own login client) is refused;
 * - only existing users (User_Resolver), nothing is provisioned;
 * - HTTPS, except in a local environment.
 *
 * Requests without a bearer token, with Application Password (Basic) auth
 * or already authenticated by an earlier callback are never touched.
 *
 * Errors (the MCP server shows the message to the user):
 * - 401 mcp_bearer_invalid      token refused (signature, issuer, audience,
 *                               expiry, type), or the plugin isn't configured
 * - 401 mcp_bearer_unmatched    valid token, no matching WordPress user
 * - 403 mcp_bearer_scope        required scope missing
 * - 403 mcp_bearer_forbidden    user refused (other site, filter)
 * - 403 mcp_bearer_https        plain http outside a local environment
 */
class Bearer_Auth {

	/**
	 * REST routes accepting a bearer token. `prefix` matches the route and
	 * everything below it, `route` matches exactly; `methods` (optional)
	 * limits the HTTP methods.
	 */
	const ROUTES = array(
		array( 'prefix' => '/wp-abilities/v1/' ),
		array( 'prefix' => '/mcp/' ),
		array(
			'route'   => '/wp/v2/users/me',
			'methods' => array( 'GET' ),
		),
	);

	/**
	 * Why the bearer token of the current request was refused.
	 *
	 * @var \WP_Error|null
	 */
	private $error = null;

	/**
	 * Configuration loader (replaceable in tests).
	 *
	 * @var callable
	 */
	private $load_config;

	/**
	 * Constructor.
	 *
	 * @param callable|null $load_config Returns Config|WP_Error.
	 */
	public function __construct( $load_config = null ) {
		$this->load_config = $load_config ?? array( Config::class, 'load' );
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		// After cookies (10) and Application Passwords (20).
		add_filter( 'determine_current_user', array( $this, 'determine_current_user' ), 30 );
		// Before the REST cookie/nonce check (100), like core's own
		// Application Password errors (90).
		add_filter( 'rest_authentication_errors', array( $this, 'rest_authentication_errors' ), 90 );
		add_action( 'admin_notices', array( $this, 'admin_notice' ) );
	}

	/**
	 * The `determine_current_user` filter.
	 *
	 * @param int|false $user_id User ID found by earlier callbacks, if any.
	 * @return int|false
	 */
	public function determine_current_user( $user_id ) {
		$this->error = null;

		if ( ! empty( $user_id ) || ! self::is_rest_request() ) {
			return $user_id;
		}

		$token = self::bearer_token();

		if ( null === $token || ! self::route_allowed( self::current_route(), self::current_method() ) ) {
			return $user_id;
		}

		$result = $this->authenticate( $token );

		if ( is_wp_error( $result ) ) {
			$this->error = $result;
			return $user_id;
		}

		return $result;
	}

	/**
	 * The `rest_authentication_errors` filter: a refused bearer token is an
	 * error response, not an anonymous request.
	 *
	 * @param \WP_Error|null|true $result Result of earlier checks.
	 * @return \WP_Error|null|true
	 */
	public function rest_authentication_errors( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}

		// WordPress determines the current user lazily, on a REST request
		// often only after this filter (in a permission callback). Make
		// determine_current_user run now, or a refused token would find no
		// error here and pass as an anonymous request.
		wp_get_current_user();

		return $this->error ?? $result;
	}

	/**
	 * Check a token and find its user.
	 *
	 * @param string $token Raw token.
	 * @return int|\WP_Error User ID, or the error response.
	 */
	public function authenticate( $token ) {
		if ( ! is_ssl() && 'local' !== wp_get_environment_type() ) {
			return self::fail( 'https_required', 'mcp_bearer_https', __( 'Bearer token authentication requires HTTPS.', 'mcp-bearer-auth' ), 403 );
		}

		$config = call_user_func( $this->load_config );

		if ( is_wp_error( $config ) ) {
			return self::fail( 'not_configured', 'mcp_bearer_invalid', __( 'Bearer token authentication is not configured on this site.', 'mcp-bearer-auth' ), 401 );
		}

		$claims = ( new Token_Verifier( $config ) )->verify( $token );

		if ( is_wp_error( $claims ) ) {
			return self::fail( $claims->get_error_code(), 'mcp_bearer_invalid', __( 'Invalid bearer token.', 'mcp-bearer-auth' ), 401 );
		}

		$context = array( 'subject' => (string) $claims['sub'] );

		if ( '' !== $config->required_scope && ! in_array( $config->required_scope, self::scopes( $claims ), true ) ) {
			return self::fail( 'missing_scope', 'mcp_bearer_scope', __( 'The bearer token lacks the required scope.', 'mcp-bearer-auth' ), 403, $context );
		}

		$user = ( new User_Resolver( $config ) )->resolve( $claims );

		if ( is_wp_error( $user ) ) {
			if ( in_array( $user->get_error_code(), array( 'unmatched', 'ambiguous' ), true ) ) {
				return self::fail( $user->get_error_code(), 'mcp_bearer_unmatched', __( 'No WordPress account matches this token\'s user.', 'mcp-bearer-auth' ), 401, $context );
			}

			return self::fail( $user->get_error_code(), 'mcp_bearer_forbidden', __( 'This account may not use bearer token authentication on this site.', 'mcp-bearer-auth' ), 403, $context );
		}

		return (int) $user->ID;
	}

	/**
	 * Show administrators a configuration error.
	 *
	 * @return void
	 */
	public function admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$config = call_user_func( $this->load_config );

		if ( is_wp_error( $config ) ) {
			/* translators: %s: configuration problem. */
			$message = sprintf( __( 'MCP Bearer Auth is not configured: %s', 'mcp-bearer-auth' ), $config->get_error_message() );
			echo '<div class="notice notice-warning"><p>' . esc_html( $message ) . '</p></div>';
		}
	}

	/**
	 * Report a refused token (never the token itself) and build the error.
	 *
	 * @param string $reason  Fixed reason.
	 * @param string $code    WP_Error code.
	 * @param string $message Message for the client.
	 * @param int    $status  HTTP status.
	 * @param array  $context Subject, if known.
	 * @return \WP_Error
	 */
	private static function fail( $reason, $code, $message, $status, array $context = array() ) {
		/**
		 * Fires when a bearer token is refused, e.g. for an audit log.
		 *
		 * @param string $reason  Fixed reason (signature, audience, unmatched, …).
		 * @param array  $context `subject` once the token is verified.
		 */
		do_action( 'mcp_bearer_auth_failed', $reason, $context );

		return new \WP_Error( $code, $message, array( 'status' => $status ) );
	}

	/**
	 * Scopes granted to a token: the space-separated `scope` claim (RFC
	 * 9068, Keycloak) or an `scp` list.
	 *
	 * @param array $claims Verified claims.
	 * @return string[]
	 */
	private static function scopes( array $claims ) {
		if ( isset( $claims['scope'] ) && is_string( $claims['scope'] ) ) {
			return preg_split( '/\s+/', trim( $claims['scope'] ), -1, PREG_SPLIT_NO_EMPTY );
		}

		if ( isset( $claims['scp'] ) && is_array( $claims['scp'] ) ) {
			return array_map( 'strval', array_filter( $claims['scp'], 'is_scalar' ) );
		}

		return array();
	}

	/**
	 * The bearer token of the current request, or null.
	 *
	 * @return string|null
	 */
	private static function bearer_token() {
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
			if ( isset( $_SERVER[ $key ] ) ) {
				$header = trim( (string) wp_unslash( $_SERVER[ $key ] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a token, compared byte for byte.

				if ( 0 !== stripos( $header, 'Bearer ' ) ) {
					return null;
				}

				$token = trim( substr( $header, 7 ) );

				return '' !== $token ? $token : null;
			}
		}

		return null;
	}

	/**
	 * Whether a bearer token may authenticate this route and method.
	 *
	 * Routes are compared exactly (case-sensitive), after refusing anything
	 * WordPress or a web server could resolve to another route than the one
	 * checked here: dot segments, empty segments, backslashes and
	 * percent-encoding. Failing closed only costs the bearer feature.
	 *
	 * @param string $route  REST route, e.g. "/wp-abilities/v1/abilities".
	 * @param string $method Effective HTTP method.
	 * @return bool
	 */
	public static function route_allowed( $route, $method ) {
		$route = (string) $route;

		if ( '' === $route || '/' !== $route[0] || false !== strpos( $route, '//' ) || preg_match( '#[\\\\%\x00-\x20]#', $route ) ) {
			return false;
		}

		foreach ( explode( '/', $route ) as $segment ) {
			if ( '.' === $segment || '..' === $segment ) {
				return false;
			}
		}

		/**
		 * Filters the REST routes that accept a bearer token.
		 *
		 * @param array $routes Entries with `prefix` (route and below) or
		 *                      `route` (exact), and optional `methods`.
		 */
		$allowed = apply_filters( 'mcp_bearer_auth_routes', self::ROUTES );

		foreach ( (array) $allowed as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			if ( isset( $entry['prefix'] ) && '' !== (string) $entry['prefix'] ) {
				$matches = 0 === strpos( $route, (string) $entry['prefix'] );
			} elseif ( isset( $entry['route'] ) ) {
				$matches = rtrim( $route, '/' ) === rtrim( (string) $entry['route'], '/' );
			} else {
				$matches = false;
			}

			if ( $matches && ( empty( $entry['methods'] ) || in_array( $method, array_map( 'strtoupper', (array) $entry['methods'] ), true ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether this is a REST API request.
	 *
	 * @return bool
	 */
	private static function is_rest_request() {
		if ( function_exists( 'wp_is_serving_rest_request' ) ) {
			return wp_is_serving_rest_request();
		}

		return defined( 'REST_REQUEST' ) && REST_REQUEST;
	}

	/**
	 * The REST route WordPress is about to serve (rest_api_loaded() reads
	 * the same query var).
	 *
	 * @return string
	 */
	private static function current_route() {
		global $wp;

		if ( ! is_object( $wp ) || ! isset( $wp->query_vars['rest_route'] ) || ! is_string( $wp->query_vars['rest_route'] ) ) {
			return '';
		}

		return $wp->query_vars['rest_route'];
	}

	/**
	 * The HTTP method the REST server will dispatch on. It honours a
	 * `_method` query parameter and the X-HTTP-Method-Override header even
	 * on GET, so a "GET only" route must look at them too: a GET carrying
	 * `_method=POST` would otherwise update the user's profile.
	 *
	 * @return string
	 */
	private static function current_method() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only, mirrors WP_REST_Server::serve_request().
		if ( isset( $_GET['_method'] ) ) {
			return strtoupper( sanitize_key( wp_unslash( $_GET['_method'] ) ) );
		}
		// phpcs:enable

		if ( isset( $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ) ) {
			return strtoupper( sanitize_key( wp_unslash( $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ) ) );
		}

		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
	}
}
