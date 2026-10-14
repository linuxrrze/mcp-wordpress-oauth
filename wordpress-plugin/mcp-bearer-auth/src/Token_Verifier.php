<?php
/**
 * Access token verification against the provider's published keys.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Verifies a JWT access token: signature against the issuer's JWKS
 * (asymmetric algorithms only), issuer, audience, expiry, subject, and that
 * it is an access token rather than an ID or logout token.
 *
 * Discovery and keys are cached in transients. An unknown `kid` (key
 * rotation) triggers one refetch, at most every REFETCH_INTERVAL seconds,
 * so a stream of junk tokens can't make WordPress hammer the provider.
 */
class Token_Verifier {

	const CACHE_TTL        = HOUR_IN_SECONDS;
	const REFETCH_INTERVAL = 300;
	const LEEWAY           = 60;

	/**
	 * Key types each algorithm may use.
	 */
	const KEY_TYPES = array(
		'RS' => 'RSA',
		'PS' => 'RSA',
		'ES' => 'EC',
		'Ed' => 'OKP',
	);

	/**
	 * Configuration.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Constructor.
	 *
	 * @param Config $config Configuration.
	 */
	public function __construct( Config $config ) {
		$this->config = $config;
	}

	/**
	 * Verify a token.
	 *
	 * @param string $jwt Raw token.
	 * @return array|\WP_Error Verified claims, or why the token was refused
	 *                         (the error code is a fixed reason for logs).
	 */
	public function verify( $jwt ) {
		$parts  = explode( '.', (string) $jwt );
		$header = 3 === count( $parts ) ? json_decode( (string) self::b64( $parts[0] ), true ) : null;

		if ( ! is_array( $header ) ) {
			return self::refuse( 'malformed' );
		}

		$alg = (string) ( $header['alg'] ?? '' );

		if ( ! in_array( $alg, Config::ALGORITHMS, true ) ) {
			return self::refuse( 'algorithm' );
		}

		// Cross-token confusion: accept the plain `JWT` most providers emit
		// and RFC 9068's `at+jwt`; refuse anything typed as something else.
		if ( isset( $header['typ'] ) && ! in_array( strtolower( (string) $header['typ'] ), array( 'jwt', 'at+jwt', 'application/at+jwt' ), true ) ) {
			return self::refuse( 'token_type' );
		}

		$kid  = isset( $header['kid'] ) && is_scalar( $header['kid'] ) ? (string) $header['kid'] : null;
		$keys = $this->keys( $alg, $kid, false );

		if ( is_wp_error( $keys ) ) {
			return $keys;
		}

		if ( ! $keys && null !== $kid ) {
			$keys = $this->keys( $alg, $kid, true ); // Rotated keys.

			if ( is_wp_error( $keys ) ) {
				return $keys;
			}
		}

		if ( ! $keys ) {
			return self::refuse( 'unknown_key' );
		}

		$claims = $this->decode( (string) $jwt, $keys );

		if ( is_wp_error( $claims ) ) {
			return $claims;
		}

		return $this->check_claims( $claims );
	}

	/**
	 * Decode with the first key that verifies the signature.
	 *
	 * @param string $jwt  Raw token.
	 * @param Key[]  $keys Candidate keys (several only if the token has no kid).
	 * @return array|\WP_Error
	 */
	private function decode( $jwt, array $keys ) {
		$leeway      = JWT::$leeway;
		JWT::$leeway = self::LEEWAY;
		$reason      = 'signature';

		try {
			foreach ( $keys as $key ) {
				try {
					$payload = JWT::decode( $jwt, $key );

					return json_decode( (string) wp_json_encode( $payload ), true );
				} catch ( \Firebase\JWT\SignatureInvalidException $e ) {
					continue;
				} catch ( \Firebase\JWT\ExpiredException $e ) {
					$reason = 'expired';
					break;
				} catch ( \Firebase\JWT\BeforeValidException $e ) {
					$reason = 'not_yet_valid';
					break;
				} catch ( \Exception $e ) {
					$reason = 'malformed';
					break;
				}
			}
		} finally {
			JWT::$leeway = $leeway;
		}

		return self::refuse( $reason );
	}

	/**
	 * Claim checks the signature check doesn't cover.
	 *
	 * @param mixed $claims Decoded payload.
	 * @return array|\WP_Error
	 */
	private function check_claims( $claims ) {
		if ( ! is_array( $claims ) ) {
			return self::refuse( 'malformed' );
		}

		// Keycloak also types the payload: "Bearer" for access tokens, "ID"
		// for ID tokens, "Logout" for logout tokens.
		if ( isset( $claims['typ'] ) && 'bearer' !== strtolower( (string) $claims['typ'] ) ) {
			return self::refuse( 'token_type' );
		}

		// A logout token from a provider that types neither header nor payload.
		if ( isset( $claims['events'] ) ) {
			return self::refuse( 'token_type' );
		}

		if ( ! isset( $claims['iss'] ) || ! is_string( $claims['iss'] ) || rtrim( $claims['iss'], '/' ) !== $this->config->issuer ) {
			return self::refuse( 'issuer' );
		}

		$audiences = isset( $claims['aud'] ) && is_array( $claims['aud'] ) ? $claims['aud'] : array( $claims['aud'] ?? null );

		if ( ! in_array( $this->config->audience, array_map( 'strval', array_filter( $audiences, 'is_scalar' ) ), true ) ) {
			return self::refuse( 'audience' );
		}

		// JWT::decode() refuses an expired token, but not one without `exp`,
		// which would never expire.
		if ( ! isset( $claims['exp'] ) || ! is_numeric( $claims['exp'] ) ) {
			return self::refuse( 'no_expiry' );
		}

		if ( ! isset( $claims['sub'] ) || ! is_scalar( $claims['sub'] ) || '' === (string) $claims['sub'] ) {
			return self::refuse( 'no_subject' );
		}

		return $claims;
	}

	/**
	 * Keys that may verify a token with this algorithm and kid.
	 *
	 * @param string      $alg     Header algorithm (already allowlisted).
	 * @param string|null $kid     Header key id.
	 * @param bool        $refresh Fetch the JWKS again (rate limited).
	 * @return Key[]|\WP_Error
	 */
	private function keys( $alg, $kid, $refresh ) {
		$jwks = $this->jwks( $refresh );

		if ( is_wp_error( $jwks ) ) {
			return $jwks;
		}

		$kty  = self::KEY_TYPES[ substr( $alg, 0, 2 ) ] ?? null;
		$keys = array();

		foreach ( $jwks['keys'] as $jwk ) {
			if ( ! is_array( $jwk ) || ( $jwk['kty'] ?? null ) !== $kty || ( isset( $jwk['use'] ) && 'sig' !== $jwk['use'] ) ) {
				continue;
			}

			if ( null !== $kid && ( $jwk['kid'] ?? null ) !== $kid ) {
				continue;
			}

			// A key that names its algorithm is only used for that one.
			if ( isset( $jwk['alg'] ) && $jwk['alg'] !== $alg ) {
				continue;
			}

			$jwk['alg'] = $alg;

			try {
				$key = JWK::parseKey( $jwk );
			} catch ( \Exception $e ) {
				continue;
			}

			if ( null !== $key ) {
				$keys[] = $key;
			}
		}

		return $keys;
	}

	/**
	 * The issuer's key set.
	 *
	 * @param bool $refresh Fetch again, unless that happened recently.
	 * @return array|\WP_Error
	 */
	private function jwks( $refresh ) {
		$cache_key = 'mcp_bearer_jwks_' . md5( $this->config->issuer . '|' . $this->config->jwks_uri );
		$cached    = get_transient( $cache_key );

		if ( is_array( $cached ) && ( ! $refresh || time() - (int) $cached['fetched'] < self::REFETCH_INTERVAL ) ) {
			return $cached['jwks'];
		}

		$uri = $this->config->jwks_uri;

		if ( '' === $uri ) {
			$discovery = $this->discovery();

			if ( is_wp_error( $discovery ) ) {
				return $discovery;
			}

			$uri = $discovery['jwks_uri'];
		}

		$jwks = self::fetch_json( $uri );

		if ( is_wp_error( $jwks ) ) {
			return is_array( $cached ) ? $cached['jwks'] : $jwks;
		}

		if ( ! isset( $jwks['keys'] ) || ! is_array( $jwks['keys'] ) ) {
			return self::refuse( 'provider_unavailable' );
		}

		set_transient(
			$cache_key,
			array(
				'jwks'    => $jwks,
				'fetched' => time(),
			),
			self::CACHE_TTL
		);

		return $jwks;
	}

	/**
	 * The issuer's discovery document, with its issuer checked.
	 *
	 * @return array|\WP_Error
	 */
	private function discovery() {
		$cache_key = 'mcp_bearer_discovery_' . md5( $this->config->issuer );
		$cached    = get_transient( $cache_key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$document = self::fetch_json( $this->config->issuer . '/.well-known/openid-configuration' );

		if ( is_wp_error( $document ) ) {
			return $document;
		}

		// A mismatch means the provider is reached under another name than
		// the one in its tokens: every token would fail the issuer check.
		if ( rtrim( (string) ( $document['issuer'] ?? '' ), '/' ) !== $this->config->issuer || empty( $document['jwks_uri'] ) || ! is_string( $document['jwks_uri'] ) ) {
			return self::refuse( 'provider_unavailable' );
		}

		set_transient( $cache_key, $document, self::CACHE_TTL );

		return $document;
	}

	/**
	 * GET a JSON document. Plain http only in a local environment: keys
	 * fetched over plain http could be swapped for an attacker's.
	 *
	 * @param string $url URL.
	 * @return array|\WP_Error
	 */
	private static function fetch_json( $url ) {
		if ( 'https' !== strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) ) && 'local' !== wp_get_environment_type() ) {
			return self::refuse( 'provider_unavailable' );
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'headers'     => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return self::refuse( 'provider_unavailable' );
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		return is_array( $body ) ? $body : self::refuse( 'provider_unavailable' );
	}

	/**
	 * Base64url decode.
	 *
	 * @param string $value Encoded.
	 * @return string|false
	 */
	private static function b64( $value ) {
		return base64_decode( strtr( $value, '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- JWT segments.
	}

	/**
	 * A refused token.
	 *
	 * @param string $reason Fixed reason.
	 * @return \WP_Error
	 */
	private static function refuse( $reason ) {
		return new \WP_Error( $reason, $reason );
	}
}
