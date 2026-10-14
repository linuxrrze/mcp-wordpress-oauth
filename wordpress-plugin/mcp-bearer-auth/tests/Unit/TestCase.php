<?php
/**
 * Shared setup: a fake provider (RSA + EC keys, discovery, JWKS served
 * through a stubbed wp_remote_get), transients in memory, users in memory.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use Brain\Monkey;
use Brain\Monkey\Functions;
use Firebase\JWT\JWT;
use MCPBearerAuth\Config;
use PHPUnit\Framework\TestCase as Base;

abstract class TestCase extends Base {

	const ISSUER = 'https://sso.example.com/realms/wp';

	/** @var array<string, array{0: string, 1: array}> kid => [private PEM, public JWK] */
	protected static $keys = array();

	/** @var array<string, mixed> */
	protected $transients = array();

	/** @var string[] URLs fetched */
	protected $fetched = array();

	/** @var array JWKS the provider currently publishes */
	protected $jwks;

	/** @var bool */
	protected $provider_down = false;

	/** @var \WP_User[] */
	protected $users = array();

	/** @var array<int, array<string, string>> user id => meta */
	protected $meta = array();

	/** @var string */
	protected $environment = 'production';

	public static function setUpBeforeClass(): void {
		if ( self::$keys ) {
			return;
		}
		self::$keys['rsa-1'] = self::rsa_key( 'rsa-1' );
		self::$keys['rsa-2'] = self::rsa_key( 'rsa-2' );
		self::$keys['ec-1']  = self::ec_key( 'ec-1' );
	}

	private static function rsa_key( $kid ) {
		$key     = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
		openssl_pkey_export( $key, $pem );
		$details = openssl_pkey_get_details( $key );
		return array( $pem, array( 'kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256',
			'n' => self::b64( $details['rsa']['n'] ), 'e' => self::b64( $details['rsa']['e'] ) ) );
	}

	private static function ec_key( $kid ) {
		$key     = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
		openssl_pkey_export( $key, $pem );
		$details = openssl_pkey_get_details( $key );
		return array( $pem, array( 'kty' => 'EC', 'kid' => $kid, 'use' => 'sig', 'crv' => 'P-256',
			'x' => self::b64( $details['ec']['x'] ), 'y' => self::b64( $details['ec']['y'] ) ) );
	}

	protected static function b64( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
	}

	protected function setUp(): void {
		parent::setUp();
		Monkey\setUp();
		$this->jwks = array( 'keys' => array( self::$keys['rsa-1'][1], self::$keys['ec-1'][1] ) );

		Functions\stubs(
			array(
				'wp_parse_url'           => static function ( $url, $component = -1 ) {
					return parse_url( $url, $component );
				},
				'wp_json_encode'         => 'json_encode',
				'wp_unslash'             => static function ( $v ) {
					return $v;
				},
				'sanitize_key'           => static function ( $k ) {
					return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $k ) );
				},
				'is_wp_error'            => static function ( $v ) {
					return $v instanceof \WP_Error;
				},
				'__'                     => static function ( $text ) {
					return $text;
				},
				'is_ssl'                 => true,
				'is_multisite'           => false,
				'wp_is_serving_rest_request' => true,
				'wp_get_environment_type' => function () {
					return $this->environment;
				},
				'get_transient'          => function ( $key ) {
					return $this->transients[ $key ] ?? false;
				},
				'set_transient'          => function ( $key, $value ) {
					$this->transients[ $key ] = $value;
					return true;
				},
				'wp_remote_get'          => function ( $url ) {
					$this->fetched[] = $url;
					if ( $this->provider_down ) {
						return new \WP_Error( 'http_request_failed', 'down' );
					}
					if ( self::ISSUER . '/.well-known/openid-configuration' === $url ) {
						return array( 'code' => 200, 'body' => json_encode( array( 'issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER . '/certs' ) ) );
					}
					if ( 'https://sso.example.com/realms/renamed/.well-known/openid-configuration' === $url ) {
						// Reached under another name than the one in its tokens.
						return array( 'code' => 200, 'body' => json_encode( array( 'issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER . '/certs' ) ) );
					}
					if ( self::ISSUER . '/certs' === $url ) {
						return array( 'code' => 200, 'body' => json_encode( $this->jwks ) );
					}
					return array( 'code' => 404, 'body' => '' );
				},
				'wp_remote_retrieve_response_code' => static function ( $r ) {
					return $r['code'];
				},
				'wp_remote_retrieve_body' => static function ( $r ) {
					return $r['body'];
				},
				'get_user_by'            => function ( $field, $value ) {
					foreach ( $this->users as $user ) {
						if ( ( 'email' === $field && $user->user_email === $value ) || ( 'login' === $field && $user->user_login === $value ) ) {
							return $user;
						}
					}
					return false;
				},
				'get_users'              => function ( $args ) {
					$found = array();
					foreach ( $this->users as $user ) {
						if ( ( $this->meta[ $user->ID ][ $args['meta_key'] ] ?? null ) === $args['meta_value'] ) {
							$found[] = $user;
						}
					}
					return array_slice( $found, 0, $args['number'] );
				},
			)
		);

		$this->add_user( 1, 'alice', 'alice@example.com', array( 'oidc_sub' => 'kc-alice' ) );
		$this->add_user( 2, 'bob', 'bob@example.com', array( 'oidc_sub' => 'kc-bob' ) );
	}

	protected function tearDown(): void {
		Monkey\tearDown();
		parent::tearDown();
	}

	protected function add_user( $id, $login, $email, array $meta = array() ) {
		$user             = new \WP_User( $id, $login );
		$user->user_email = $email;
		$this->users[]    = $user;
		$this->meta[ $id ] = $meta;
		return $user;
	}

	protected function config( array $overrides = array() ) {
		$config = Config::from_array( array_merge( array(
			'issuer'      => self::ISSUER,
			'audience'    => 'mcp-wordpress',
			'user_match'  => 'meta:oidc_sub',
			'login_claim' => 'preferred_username',
		), $overrides ) );
		$this->assertInstanceOf( Config::class, $config );
		return $config;
	}

	/**
	 * A Keycloak-shaped access token.
	 */
	protected function token( array $claims = array(), $kid = 'rsa-1', $alg = 'RS256', array $header = array() ) {
		$claims = array_filter( array_merge( array(
			'iss'   => self::ISSUER,
			'aud'   => array( 'mcp-wordpress', 'account' ),
			'sub'   => 'kc-alice',
			'typ'   => 'Bearer',
			'exp'   => time() + 300,
			'iat'   => time(),
			'scope' => 'openid email',
			'email' => 'alice@example.com',
			'email_verified' => true,
			'preferred_username' => 'alice',
		), $claims ), static function ( $v ) {
			return null !== $v;
		} );
		return JWT::encode( $claims, self::$keys[ $kid ][0], $alg, $kid, $header ?: null );
	}
}
