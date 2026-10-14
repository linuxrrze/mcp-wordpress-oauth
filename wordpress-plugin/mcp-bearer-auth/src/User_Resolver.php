<?php
/**
 * From verified claims to a WordPress user.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth;

/**
 * Finds the existing WordPress user a token belongs to. Never creates or
 * links accounts: that is the login plugin's job.
 *
 * - "meta:<key>": the user whose meta <key> equals the token's `sub`. Use
 *   the key your OIDC login plugin stores the subject under, e.g.
 *   `_sso_oidc_subject` (sso-login-oidc) or
 *   `openid-connect-generic-subject-identity` (OpenID Connect Generic).
 *   The most robust choice: subjects never change or get reassigned.
 * - "email": the user with the token's `email`, only if `email_verified`
 *   is true. Only as trustworthy as the provider's verification.
 * - "login": the user whose user_login equals MCP_BEARER_LOGIN_CLAIM
 *   (preferred_username). Only if users can't choose that name themselves
 *   at the provider.
 */
class User_Resolver {

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
	 * The user for these claims.
	 *
	 * @param array $claims Verified claims.
	 * @return \WP_User|\WP_Error Error code `unmatched` or `ambiguous`.
	 */
	public function resolve( array $claims ) {
		switch ( $this->config->user_match ) {
			case 'meta':
				$user = $this->by_meta( (string) $claims['sub'] );
				break;
			case 'email':
				$user = ( true === ( $claims['email_verified'] ?? null ) && isset( $claims['email'] ) && is_string( $claims['email'] ) )
					? get_user_by( 'email', $claims['email'] )
					: false;
				break;
			default:
				$login = $claims[ $this->config->login_claim ] ?? null;
				$user  = is_string( $login ) && '' !== $login ? get_user_by( 'login', $login ) : false;
		}

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		if ( ! $user instanceof \WP_User ) {
			return new \WP_Error( 'unmatched', 'unmatched' );
		}

		// Multisite: only members of this site (or super admins).
		if ( is_multisite() && ! is_user_member_of_blog( $user->ID ) && ! is_super_admin( $user->ID ) ) {
			return new \WP_Error( 'not_a_member', 'not_a_member' );
		}

		/**
		 * Filters the user a bearer token authenticates as. Return a WP_Error
		 * to refuse (e.g. deactivated accounts in your login plugin).
		 *
		 * @param \WP_User|\WP_Error $user   The matched user.
		 * @param array              $claims Verified claims.
		 */
		return apply_filters( 'mcp_bearer_auth_user', $user, $claims );
	}

	/**
	 * The one user with meta key = subject.
	 *
	 * @param string $subject Token subject.
	 * @return \WP_User|false|\WP_Error
	 */
	private function by_meta( $subject ) {
		$users = get_users(
			array(
				'meta_key'    => $this->config->meta_key, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- one lookup per API request.
				'meta_value'  => $subject, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'      => 2,
				'count_total' => false,
				'blog_id'     => 0,
			)
		);

		if ( count( $users ) > 1 ) {
			// Two accounts claim the same subject: refuse rather than pick one.
			return new \WP_Error( 'ambiguous', 'ambiguous' );
		}

		return $users ? $users[0] : false;
	}
}
