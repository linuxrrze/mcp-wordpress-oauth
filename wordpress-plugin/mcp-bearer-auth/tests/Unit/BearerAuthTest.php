<?php
/**
 * The WordPress hooks: which requests are touched and the error contract.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use Brain\Monkey\Actions;
use Brain\Monkey\Functions;
use MCPBearerAuth\Bearer_Auth;

class BearerAuthTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$_SERVER = array( 'REQUEST_METHOD' => 'GET' );
		$_GET    = array();
		$GLOBALS['wp'] = (object) array( 'query_vars' => array( 'rest_route' => '/wp-abilities/v1/abilities' ) );
	}

	private function auth( array $config = array() ) {
		return new Bearer_Auth( function () use ( $config ) {
			return $this->config( $config );
		} );
	}

	private function request( $token, $route = '/wp-abilities/v1/abilities', $method = 'GET' ) {
		$_SERVER['HTTP_AUTHORIZATION'] = null === $token ? null : 'Bearer ' . $token;
		if ( null === $token ) {
			unset( $_SERVER['HTTP_AUTHORIZATION'] );
		}
		$_SERVER['REQUEST_METHOD']        = $method;
		$GLOBALS['wp']->query_vars['rest_route'] = $route;
	}

	private function assertError( $code, $status, $auth ) {
		$error = $auth->rest_authentication_errors( null );
		$this->assertInstanceOf( \WP_Error::class, $error );
		$this->assertSame( $code, $error->get_error_code() );
		$this->assertSame( $status, $error->get_error_data()['status'] );
	}

	public function test_valid_token_logs_in_the_matched_user() {
		$auth = $this->auth();
		$this->request( $this->token( array( 'sub' => 'kc-bob' ) ) );
		$this->assertSame( 2, $auth->determine_current_user( false ) );
		$this->assertNull( $auth->rest_authentication_errors( null ) );
	}

	public function test_invalid_token_is_a_401_not_anonymous() {
		$auth = $this->auth();
		$this->request( $this->token( array( 'aud' => 'account' ) ) );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertError( 'mcp_bearer_invalid', 401, $auth );
	}

	public function test_unmatched_user() {
		$auth = $this->auth();
		$this->request( $this->token( array( 'sub' => 'kc-nobody' ) ) );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertError( 'mcp_bearer_unmatched', 401, $auth );
	}

	public function test_required_scope() {
		$auth = $this->auth( array( 'required_scope' => 'mcp:wordpress' ) );
		$this->request( $this->token() );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertError( 'mcp_bearer_scope', 403, $auth );
		$this->request( $this->token( array( 'scope' => 'openid mcp:wordpress' ) ) );
		$this->assertSame( 1, $auth->determine_current_user( false ) );
	}

	public function test_refusal_is_reported_without_the_token() {
		Actions\expectDone( 'mcp_bearer_auth_failed' )->once()->with( 'unmatched', array( 'subject' => 'kc-nobody' ) );
		$auth = $this->auth();
		$this->request( $this->token( array( 'sub' => 'kc-nobody' ) ) );
		$auth->determine_current_user( false );
	}

	public function test_not_configured() {
		$auth = new Bearer_Auth( static function () {
			return new \WP_Error( 'mcp_bearer_config', 'x' );
		} );
		$this->request( $this->token() );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertError( 'mcp_bearer_invalid', 401, $auth );
	}

	public function test_https_required_outside_local() {
		Functions\when( 'is_ssl' )->justReturn( false );
		$auth = $this->auth();
		$this->request( $this->token() );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertError( 'mcp_bearer_https', 403, $auth );
		$this->environment = 'local';
		$this->assertSame( 1, $auth->determine_current_user( false ) );
	}

	public function test_already_authenticated_is_untouched() {
		$auth = $this->auth();
		$this->request( $this->token( array( 'sub' => 'kc-bob' ) ) );
		$this->assertSame( 7, $auth->determine_current_user( 7 ) );
	}

	public function test_basic_auth_is_untouched() {
		$auth = $this->auth();
		$this->request( null );
		$_SERVER['HTTP_AUTHORIZATION'] = 'Basic YWxpY2U6eHh4';
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertNull( $auth->rest_authentication_errors( null ) );
	}

	public function test_non_rest_request_is_untouched() {
		Functions\when( 'wp_is_serving_rest_request' )->justReturn( false );
		$auth = $this->auth();
		$this->request( $this->token() );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertNull( $auth->rest_authentication_errors( null ) );
	}

	public function test_other_routes_ignore_the_token() {
		$auth = $this->auth();
		$this->request( $this->token(), '/wp/v2/users' );
		$this->assertFalse( $auth->determine_current_user( false ) );
		$this->assertNull( $auth->rest_authentication_errors( null ) );
	}

	public function test_redirect_authorization_header() {
		$auth = $this->auth();
		$this->request( null );
		$_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = 'Bearer ' . $this->token();
		$this->assertSame( 1, $auth->determine_current_user( false ) );
	}

	public function test_refusal_found_when_the_user_is_determined_lazily() {
		// As in WordPress: nothing has asked for the current user before the
		// rest_authentication_errors filter runs.
		$auth = $this->auth();
		Functions\when( 'wp_get_current_user' )->alias( static function () use ( $auth ) {
			$auth->determine_current_user( false );
		} );
		$this->request( $this->token( array( 'sub' => 'kc-nobody' ) ) );
		$this->assertError( 'mcp_bearer_unmatched', 401, $auth );
	}

	public function test_earlier_errors_are_kept() {
		$auth    = $this->auth();
		$earlier = new \WP_Error( 'earlier', 'x' );
		$this->request( $this->token( array( 'aud' => 'account' ) ) );
		$auth->determine_current_user( false );
		$this->assertSame( $earlier, $auth->rest_authentication_errors( $earlier ) );
	}

	/**
	 * @dataProvider routes
	 */
	public function test_route_allowed( $route, $method, $allowed ) {
		$this->assertSame( $allowed, Bearer_Auth::route_allowed( $route, $method ) );
	}

	public function routes() {
		return array(
			array( '/wp-abilities/v1/abilities', 'GET', true ),
			array( '/wp-abilities/v1/abilities/core/get-site-info/run', 'DELETE', true ),
			array( '/mcp/mcp-adapter-default-server', 'POST', true ),
			array( '/wp/v2/users/me', 'GET', true ),
			array( '/wp/v2/users/me', 'POST', false ),
			array( '/wp/v2/users/me/application-passwords', 'GET', false ),
			array( '/wp/v2/users', 'GET', false ),
			array( '/wp-abilities/v1/../../wp/v2/users', 'GET', false ),
			array( '/wp-abilities/v1/./x', 'GET', false ),
			array( '//wp-abilities/v1/abilities', 'GET', false ),
			array( '/wp-abilities/v1//abilities', 'GET', false ),
			array( '/wp-abilities/v1/%2e%2e/x', 'GET', false ),
			array( '/wp-abilities/v1\\x', 'GET', false ),
			array( '/WP-ABILITIES/v1/abilities', 'GET', false ),
			array( '', 'GET', false ),
			array( '/wp-abilities/v10/abilities', 'GET', false ),
		);
	}

	public function test_method_override_counts_for_get_only_routes() {
		$auth = $this->auth();
		$this->request( $this->token(), '/wp/v2/users/me', 'GET' );
		$_GET['_method'] = 'POST';
		$this->assertFalse( $auth->determine_current_user( false ) );
		unset( $_GET['_method'] );
		$_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] = 'PUT';
		$this->assertFalse( $auth->determine_current_user( false ) );
		unset( $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] );
		$this->assertSame( 1, $auth->determine_current_user( false ) );
	}

	public function test_routes_filter() {
		\Brain\Monkey\Filters\expectApplied( 'mcp_bearer_auth_routes' )->andReturn( array( array( 'prefix' => '/custom/' ) ) );
		$this->assertTrue( Bearer_Auth::route_allowed( '/custom/x', 'GET' ) );
		$this->assertFalse( Bearer_Auth::route_allowed( '/wp-abilities/v1/abilities', 'GET' ) );
	}
}
