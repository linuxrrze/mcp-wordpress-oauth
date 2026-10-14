<?php
/**
 * Plugin Name: mcp-wordpress-oauth e2e abilities
 * Description: Test-only abilities for test-stack/e2e.py. Each one answers
 *              with the HTTP method WordPress' run controller received, the
 *              input it saw, and the user it ran as, so the e2e run can
 *              confirm the method rule and the PHP-bracket query encoding
 *              (src/mcp_wordpress/wordpress.py) against real WordPress.
 *
 * Installed as a must-use plugin by test-stack/docker-compose.yml.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'wp_abilities_api_categories_init',
	static function () {
		wp_register_ability_category(
			'e2e',
			array(
				'label'       => 'E2E',
				'description' => 'mcp-wordpress-oauth end-to-end test abilities.',
			)
		);
	}
);

/**
 * What every e2e ability returns.
 *
 * @param mixed $input The ability input, as WordPress passed it.
 * @return array
 */
function mcp_e2e_report( $input ) {
	$user = wp_get_current_user();
	return array(
		'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
		'input'  => $input,
		'user'   => $user->exists() ? $user->user_login : null,
	);
}

add_action(
	'wp_abilities_api_init',
	static function () {
		$report = array(
			'type'       => 'object',
			'properties' => array(
				'method' => array( 'type' => 'string' ),
				// Any JSON value (an empty PHP array would serialise as []).
				'input'  => array( 'type' => array( 'object', 'array', 'string', 'integer', 'number', 'boolean', 'null' ) ),
				'user'   => array( 'type' => array( 'string', 'null' ) ),
			),
		);
		$base   = array(
			'category'            => 'e2e',
			'output_schema'       => $report,
			'execute_callback'    => 'mcp_e2e_report',
			'permission_callback' => static function () {
				return is_user_logged_in();
			},
		);
		$meta   = static function ( array $annotations ) {
			return array(
				'annotations'  => $annotations,
				'show_in_rest' => true,
				'mcp'          => array( 'public' => true ),
			);
		};

		// readonly -> GET, input in the query string (input[a][b]=..).
		wp_register_ability(
			'e2e/get-info',
			$base + array(
				'label'        => 'E2E get info',
				'description'  => 'Read-only: echoes its input.',
				'input_schema' => array(
					'type'       => 'object',
					'properties' => array(
						'fields' => array(
							'type'  => 'array',
							'items' => array( 'type' => 'string' ),
						),
						'filter' => array(
							'type'       => 'object',
							'properties' => array(
								'status' => array( 'type' => 'string' ),
								'sticky' => array( 'type' => 'boolean' ),
							),
						),
					),
				),
				'meta'         => $meta(
					array(
						'readonly'   => true,
						'idempotent' => true,
					)
				),
			)
		);

		// Neither readonly nor destructive -> POST, input as JSON body.
		wp_register_ability(
			'e2e/update-note',
			$base + array(
				'label'        => 'E2E update note',
				'description'  => 'Write: echoes its input.',
				'input_schema' => array(
					'type'       => 'object',
					'properties' => array(
						'title' => array( 'type' => 'string' ),
						'count' => array( 'type' => 'integer' ),
						'draft' => array( 'type' => 'boolean' ),
					),
					'required'   => array( 'title' ),
				),
				'meta'         => $meta( array() ),
			)
		);

		// destructive + idempotent -> DELETE, scalar input (?input=7).
		wp_register_ability(
			'e2e/delete-note',
			$base + array(
				'label'        => 'E2E delete note',
				'description'  => 'Destructive and idempotent: echoes its input.',
				'input_schema' => array( 'type' => 'integer' ),
				'meta'         => $meta(
					array(
						'destructive' => true,
						'idempotent'  => true,
					)
				),
			)
		);

		// Scalar input with POST: the MCP tool wraps it as {"input": ...}.
		wp_register_ability(
			'e2e/echo-text',
			$base + array(
				'label'        => 'E2E echo text',
				'description'  => 'Write with a string input.',
				'input_schema' => array( 'type' => 'string' ),
				'meta'         => $meta( array() ),
			)
		);

		// Listed for everyone, runnable by editors and up: a permission
		// check at run time (403 for bob, an author).
		wp_register_ability(
			'e2e/editor-only',
			array(
				'label'               => 'E2E editor only',
				'description'         => 'Runs only for users who can edit others\' posts.',
				'permission_callback' => static function () {
					return current_user_can( 'edit_others_posts' );
				},
			) + $base + array( 'meta' => $meta( array( 'readonly' => true ) ) )
		);

		// Only LISTED for editors and up (see the rest_post_dispatch filter
		// below), so the tool list differs per user: WordPress' list
		// endpoint itself doesn't filter by permission.
		wp_register_ability(
			'e2e/editor-tools',
			array(
				'permission_callback' => static function () {
					return current_user_can( 'edit_others_posts' );
				},
			) + $base + array(
				'label'       => 'E2E editor tools',
				'description' => 'Only listed for editors and up.',
				'meta'        => $meta( array( 'readonly' => true ) ),
			)
		);

		// Not exposed to MCP (meta.mcp.public false): filtered out by this
		// server's default ABILITY_MCP_PUBLIC_ONLY=on.
		wp_register_ability(
			'e2e/not-public',
			$base + array(
				'label'       => 'E2E not public',
				'description' => 'show_in_rest but not mcp.public.',
				'meta'        => array(
					'annotations'  => array( 'readonly' => true ),
					'show_in_rest' => true,
				),
			)
		);
	}
);

// Hide e2e/editor-tools from the abilities list for users below editor.
// Filtering the response (after authentication) rather than registering the
// ability conditionally keeps this independent of when the abilities
// registry happens to initialise.
add_filter(
	'rest_post_dispatch',
	static function ( $response, $server, $request ) {
		if ( '/wp-abilities/v1/abilities' !== $request->get_route() || current_user_can( 'edit_others_posts' )
			|| ! $response instanceof WP_REST_Response || ! is_array( $response->get_data() ) ) {
			return $response;
		}
		$response->set_data(
			array_values(
				array_filter(
					$response->get_data(),
					static function ( $item ) {
						return ! is_array( $item ) || 'e2e/editor-tools' !== ( $item['name'] ?? '' );
					}
				)
			)
		);
		return $response;
	},
	10,
	3
);
