<?php
/**
 * Unit test bootstrap: no WordPress, Brain Monkey for its functions and
 * minimal stand-ins for the few core classes the plugin uses.
 *
 * @package MCPBearerAuth
 */

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

define( 'ABSPATH', '/tmp/' );
define( 'HOUR_IN_SECONDS', 3600 );

class WP_Error {
	private $code;
	private $message;
	private $data;

	public function __construct( $code = '', $message = '', $data = '' ) {
		$this->code    = $code;
		$this->message = $message;
		$this->data    = $data;
	}

	public function get_error_code() {
		return $this->code;
	}

	public function get_error_message() {
		return $this->message;
	}

	public function get_error_data() {
		return $this->data;
	}
}

class WP_User {
	public $ID;
	public $user_login;
	public $user_email = '';

	public function __construct( $id = 0, $login = '' ) {
		$this->ID         = $id;
		$this->user_login = $login;
	}
}
