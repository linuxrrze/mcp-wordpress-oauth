<?php
/**
 * One test per check of Token_Verifier.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use Firebase\JWT\JWT;
use MCPBearerAuth\Token_Verifier;

class TokenVerifierTest extends TestCase {

	private function verify( $token, array $config = array() ) {
		return ( new Token_Verifier( $this->config( $config ) ) )->verify( $token );
	}

	private function assertRefused( $reason, $result ) {
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $reason, $result->get_error_code() );
	}

	public function test_valid_rs256_token() {
		$claims = $this->verify( $this->token() );
		$this->assertIsArray( $claims );
		$this->assertSame( 'kc-alice', $claims['sub'] );
	}

	public function test_valid_es256_token() {
		$this->assertIsArray( $this->verify( $this->token( array(), 'ec-1', 'ES256' ) ) );
	}

	public function test_audience_as_string() {
		$this->assertIsArray( $this->verify( $this->token( array( 'aud' => 'mcp-wordpress' ) ) ) );
	}

	public function test_wrong_audience() {
		$this->assertRefused( 'audience', $this->verify( $this->token( array( 'aud' => array( 'account' ) ) ) ) );
	}

	public function test_missing_audience() {
		$this->assertRefused( 'audience', $this->verify( $this->token( array( 'aud' => null ) ) ) );
	}

	public function test_wrong_issuer() {
		$this->assertRefused( 'issuer', $this->verify( $this->token( array( 'iss' => 'https://evil.example/realms/wp' ) ) ) );
	}

	public function test_issuer_trailing_slash_is_tolerated() {
		$this->assertIsArray( $this->verify( $this->token( array( 'iss' => self::ISSUER . '/' ) ) ) );
	}

	public function test_expired() {
		$this->assertRefused( 'expired', $this->verify( $this->token( array( 'exp' => time() - 120 ) ) ) );
	}

	public function test_expiry_within_leeway() {
		$this->assertIsArray( $this->verify( $this->token( array( 'exp' => time() - 30 ) ) ) );
	}

	public function test_not_yet_valid() {
		$this->assertRefused( 'not_yet_valid', $this->verify( $this->token( array( 'nbf' => time() + 600 ) ) ) );
	}

	public function test_no_expiry() {
		$this->assertRefused( 'no_expiry', $this->verify( $this->token( array( 'exp' => null ) ) ) );
	}

	public function test_no_subject() {
		$this->assertRefused( 'no_subject', $this->verify( $this->token( array( 'sub' => null ) ) ) );
	}

	public function test_id_token_is_refused() {
		$this->assertRefused( 'token_type', $this->verify( $this->token( array( 'typ' => 'ID' ) ) ) );
	}

	public function test_logout_token_is_refused() {
		$this->assertRefused( 'token_type', $this->verify( $this->token( array( 'typ' => null, 'events' => array( 'x' => array() ) ) ) ) );
	}

	public function test_header_type_other_than_jwt_is_refused() {
		$this->assertRefused( 'token_type', $this->verify( $this->token( array(), 'rsa-1', 'RS256', array( 'typ' => 'logout+jwt' ) ) ) );
	}

	public function test_at_jwt_header_type_is_accepted() {
		$this->assertIsArray( $this->verify( $this->token( array(), 'rsa-1', 'RS256', array( 'typ' => 'at+jwt' ) ) ) );
	}

	public function test_hs256_is_refused_even_with_the_public_key_as_secret() {
		// Classic algorithm confusion: HMAC "signed" with the public key.
		$public = openssl_pkey_get_details( openssl_pkey_get_private( self::$keys['rsa-1'][0] ) )['key'];
		$token  = JWT::encode( array( 'iss' => self::ISSUER, 'aud' => 'mcp-wordpress', 'sub' => 'kc-alice', 'exp' => time() + 60 ), $public, 'HS256', 'rsa-1' );
		$this->assertRefused( 'algorithm', $this->verify( $token ) );
	}

	public function test_none_algorithm_is_refused() {
		$token = self::b64( '{"alg":"none","kid":"rsa-1"}' ) . '.' . self::b64( json_encode( array( 'iss' => self::ISSUER, 'aud' => 'mcp-wordpress', 'sub' => 'x', 'exp' => time() + 60 ) ) ) . '.';
		$this->assertRefused( 'algorithm', $this->verify( $token ) );
	}

	public function test_signature_by_an_unknown_key() {
		// rsa-2 isn't published; a token claiming kid rsa-1 but signed by rsa-2.
		$token = JWT::encode( array( 'iss' => self::ISSUER, 'aud' => 'mcp-wordpress', 'sub' => 'kc-alice', 'exp' => time() + 60 ), self::$keys['rsa-2'][0], 'RS256', 'rsa-1' );
		$this->assertRefused( 'signature', $this->verify( $token ) );
	}

	public function test_tampered_payload() {
		list( $h, , $s ) = explode( '.', $this->token() );
		$payload         = self::b64( json_encode( array( 'iss' => self::ISSUER, 'aud' => 'mcp-wordpress', 'sub' => 'kc-bob', 'exp' => time() + 60 ) ) );
		$this->assertRefused( 'signature', $this->verify( "$h.$payload.$s" ) );
	}

	public function test_key_type_must_match_algorithm() {
		// An ES256 header pointing at the RSA key.
		$token = $this->token( array(), 'ec-1', 'ES256' );
		list( , $p, $s ) = explode( '.', $token );
		$h = self::b64( json_encode( array( 'alg' => 'ES256', 'kid' => 'rsa-1', 'typ' => 'JWT' ) ) );
		$this->assertRefused( 'unknown_key', $this->verify( "$h.$p.$s" ) );
	}

	public function test_key_with_other_alg_is_not_used() {
		$this->jwks['keys'][0]['alg'] = 'RS512';
		$this->assertRefused( 'unknown_key', $this->verify( $this->token() ) );
	}

	public function test_encryption_keys_are_not_used() {
		$this->jwks['keys'][0]['use'] = 'enc';
		$this->assertRefused( 'unknown_key', $this->verify( $this->token() ) );
	}

	public function test_malformed() {
		$this->assertRefused( 'malformed', $this->verify( 'not-a-jwt' ) );
		$this->assertRefused( 'malformed', $this->verify( 'a.b.c' ) );
	}

	public function test_keys_are_cached() {
		$this->verify( $this->token() );
		$this->verify( $this->token( array( 'sub' => 'kc-bob' ) ) );
		$this->assertSame( array( self::ISSUER . '/.well-known/openid-configuration', self::ISSUER . '/certs' ), $this->fetched );
	}

	public function test_rotated_key_is_fetched_once() {
		$this->verify( $this->token() );
		$this->transients[ array_keys( $this->transients )[1] ]['fetched'] -= 600; // Cache older than the refetch interval.
		$this->jwks['keys'][] = self::$keys['rsa-2'][1];
		$this->assertIsArray( $this->verify( $this->token( array(), 'rsa-2' ) ) );
		$this->assertCount( 3, $this->fetched );
	}

	public function test_unknown_kid_refetch_is_rate_limited() {
		$this->verify( $this->token() );
		$this->assertRefused( 'unknown_key', $this->verify( $this->token( array(), 'rsa-2' ) ) );
		$this->assertRefused( 'unknown_key', $this->verify( $this->token( array(), 'rsa-2' ) ) );
		$this->assertCount( 2, $this->fetched ); // No refetch within REFETCH_INTERVAL.
	}

	public function test_explicit_jwks_uri_skips_discovery() {
		$this->assertIsArray( $this->verify( $this->token(), array( 'jwks_uri' => self::ISSUER . '/certs' ) ) );
		$this->assertSame( array( self::ISSUER . '/certs' ), $this->fetched );
	}

	public function test_provider_down() {
		$this->provider_down = true;
		$this->assertRefused( 'provider_unavailable', $this->verify( $this->token() ) );
	}

	public function test_plain_http_provider_only_in_local_environment() {
		$config = array( 'jwks_uri' => 'http://keycloak:8080/certs' );
		$this->assertRefused( 'provider_unavailable', $this->verify( $this->token(), $config ) );
		$this->assertSame( array(), $this->fetched );
	}

	public function test_discovery_issuer_must_match() {
		$renamed = 'https://sso.example.com/realms/renamed';
		$this->assertRefused( 'provider_unavailable', $this->verify( $this->token( array( 'iss' => $renamed ) ), array( 'issuer' => $renamed ) ) );
		$this->assertSame( array( $renamed . '/.well-known/openid-configuration' ), $this->fetched );
	}
}
