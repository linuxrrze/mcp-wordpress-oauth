<?php
/**
 * User matching.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use MCPBearerAuth\User_Resolver;

class UserResolverTest extends TestCase {

	private function resolve( array $claims, $match = 'meta:oidc_sub' ) {
		$claims = array_merge( array( 'sub' => 'kc-alice', 'email' => 'alice@example.com', 'email_verified' => true, 'preferred_username' => 'alice' ), $claims );
		return ( new User_Resolver( $this->config( array( 'user_match' => $match ) ) ) )->resolve( $claims );
	}

	private function assertCode( $code, $result ) {
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( $code, $result->get_error_code() );
	}

	public function test_meta_match() {
		$this->assertSame( 2, $this->resolve( array( 'sub' => 'kc-bob' ) )->ID );
	}

	public function test_meta_no_match() {
		$this->assertCode( 'unmatched', $this->resolve( array( 'sub' => 'kc-nobody' ) ) );
	}

	public function test_meta_match_ignores_email() {
		// A token whose email is alice's but whose subject is unknown.
		$this->assertCode( 'unmatched', $this->resolve( array( 'sub' => 'kc-mallory' ) ) );
	}

	public function test_two_users_with_the_same_subject_are_refused() {
		$this->add_user( 3, 'alice2', 'a2@example.com', array( 'oidc_sub' => 'kc-alice' ) );
		$this->assertCode( 'ambiguous', $this->resolve( array() ) );
	}

	public function test_email_match_requires_verified_email() {
		$this->assertSame( 1, $this->resolve( array( 'sub' => 'x' ), 'email' )->ID );
		$this->assertCode( 'unmatched', $this->resolve( array( 'email_verified' => false ), 'email' ) );
		$this->assertCode( 'unmatched', $this->resolve( array( 'email_verified' => 'true' ), 'email' ) );
		$this->assertCode( 'unmatched', $this->resolve( array( 'email' => 'nobody@example.com' ), 'email' ) );
	}

	public function test_login_match() {
		$this->assertSame( 2, $this->resolve( array( 'preferred_username' => 'bob' ), 'login' )->ID );
		$this->assertCode( 'unmatched', $this->resolve( array( 'preferred_username' => null ), 'login' ) );
	}

	public function test_multisite_requires_membership() {
		Functions\when( 'is_multisite' )->justReturn( true );
		Functions\when( 'is_user_member_of_blog' )->justReturn( false );
		Functions\when( 'is_super_admin' )->justReturn( false );
		$this->assertCode( 'not_a_member', $this->resolve( array() ) );
		Functions\when( 'is_super_admin' )->justReturn( true );
		$this->assertSame( 1, $this->resolve( array() )->ID );
		Functions\when( 'is_super_admin' )->justReturn( false );
		Functions\when( 'is_user_member_of_blog' )->justReturn( true );
		$this->assertSame( 1, $this->resolve( array() )->ID );
	}

	public function test_filter_can_refuse() {
		Filters\expectApplied( 'mcp_bearer_auth_user' )->once()->andReturn( new \WP_Error( 'deactivated', 'x' ) );
		$this->assertCode( 'deactivated', $this->resolve( array() ) );
	}
}
