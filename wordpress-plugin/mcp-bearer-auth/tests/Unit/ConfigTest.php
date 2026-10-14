<?php
/**
 * Configuration validation.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use MCPBearerAuth\Config;

class ConfigTest extends TestCase {

	private function load( array $raw ) {
		return Config::from_array( array_merge( array( 'issuer' => self::ISSUER, 'audience' => 'mcp-wordpress', 'user_match' => 'email', 'login_claim' => 'preferred_username' ), $raw ) );
	}

	public function test_valid() {
		$config = $this->load( array( 'issuer' => self::ISSUER . '/', 'user_match' => 'meta:_sso_oidc_subject' ) );
		$this->assertSame( self::ISSUER, $config->issuer );
		$this->assertSame( 'meta', $config->user_match );
		$this->assertSame( '_sso_oidc_subject', $config->meta_key );
	}

	/**
	 * @dataProvider invalid
	 */
	public function test_invalid( array $raw ) {
		$this->assertInstanceOf( \WP_Error::class, $this->load( $raw ) );
	}

	public function invalid() {
		return array(
			'no issuer'         => array( array( 'issuer' => '' ) ),
			'issuer not a URL'  => array( array( 'issuer' => 'sso.example.com' ) ),
			'empty audience'    => array( array( 'audience' => '' ) ),
			'no user match'     => array( array( 'user_match' => '' ) ),
			'unknown match'     => array( array( 'user_match' => 'id' ) ),
			'meta without key'  => array( array( 'user_match' => 'meta:' ) ),
			'bad jwks uri'      => array( array( 'jwks_uri' => 'file:///etc/passwd' ) ),
			'empty login claim' => array( array( 'user_match' => 'login', 'login_claim' => '' ) ),
		);
	}

	public function test_load_without_constants_is_an_error() {
		$this->assertInstanceOf( \WP_Error::class, Config::load() );
	}
}
