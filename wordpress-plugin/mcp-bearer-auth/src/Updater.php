<?php
/**
 * Updates from the plugin's GitHub releases.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth;

/**
 * Offers new releases to WordPress' own update mechanism, so the Plugins
 * screen, "Update now" and auto-updates work as for a wordpress.org plugin
 * (decisions.md D14).
 *
 * The plugin header's `Update URI` names the GitHub repository; core then
 * asks the `update_plugins_github.com` filter instead of wordpress.org. A
 * release is a GitHub release tagged mcp-bearer-auth-vX.Y.Z (not draft, not
 * prerelease) carrying mcp-bearer-auth.zip and the version's readme.txt,
 * whose fields and sections WordPress shows (requirements, "Tested up to",
 * the details dialog). The server's vX.Y.Z releases in the same repository
 * are ignored.
 *
 * - MCP_BEARER_UPDATE_CHECK  false: never contact GitHub (updates by hand,
 *                            Composer, or a deployment pipeline).
 * - MCP_BEARER_AUTO_UPDATE   true/false: force auto-updates on/off; unset:
 *                            the "Enable auto-updates" link decides.
 */
final class Updater {

	const SLUG       = 'mcp-bearer-auth';
	const TAG_PREFIX = 'mcp-bearer-auth-v';
	const ASSET      = 'mcp-bearer-auth.zip';
	const README     = 'readme.txt';
	const CACHE_KEY  = 'mcp_bearer_auth_release';
	const CACHE_TTL  = 6 * HOUR_IN_SECONDS;

	/**
	 * After a failed lookup: GitHub allows 60 unauthenticated API calls per
	 * hour and IP, shared with every other site on the host.
	 */
	const ERROR_TTL = HOUR_IN_SECONDS;

	/**
	 * Main plugin file, absolute.
	 *
	 * @var string
	 */
	private $main_file;

	/**
	 * Constructor.
	 *
	 * @param string $main_file Main plugin file, absolute.
	 */
	public function __construct( $main_file ) {
		$this->main_file = $main_file;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register_hooks() {
		if ( ! defined( 'MCP_BEARER_UPDATE_CHECK' ) || MCP_BEARER_UPDATE_CHECK ) {
			add_filter( 'update_plugins_github.com', array( $this, 'update' ), 10, 3 );
			add_filter( 'plugins_api', array( $this, 'info' ), 20, 3 );
		}

		if ( defined( 'MCP_BEARER_AUTO_UPDATE' ) ) {
			add_filter( 'auto_update_plugin', array( $this, 'auto_update' ), 10, 2 );
		}
	}

	/**
	 * The `update_plugins_github.com` filter: this plugin's newest release.
	 * Core compares its version with the installed one.
	 *
	 * @param array|false $update      Update found by an earlier callback.
	 * @param array       $plugin_data Plugin headers.
	 * @param string      $plugin_file Plugin basename.
	 * @return array|false
	 */
	public function update( $update, $plugin_data, $plugin_file ) {
		if ( ! empty( $update ) || plugin_basename( $this->main_file ) !== $plugin_file ) {
			return $update;
		}

		$release = $this->release( (string) ( $plugin_data['UpdateURI'] ?? '' ) );

		if ( null === $release ) {
			return $update;
		}

		// The new version's requirements, from its readme.txt; the installed
		// version's headers if the release has none.
		return array(
			'slug'         => self::SLUG,
			'version'      => $release['version'],
			'url'          => $release['url'],
			'package'      => $release['package'],
			'requires'     => $release['readme']['requires'] ?? (string) ( $plugin_data['RequiresWP'] ?? '' ),
			'tested'       => $release['readme']['tested'] ?? '',
			'requires_php' => $release['readme']['requires_php'] ?? (string) ( $plugin_data['RequiresPHP'] ?? '' ),
		);
	}

	/**
	 * The `plugins_api` filter: the "View details" dialog, which would
	 * otherwise ask wordpress.org.
	 *
	 * @param false|object|array $result Result of earlier callbacks.
	 * @param string             $action API action.
	 * @param object             $args   Request arguments.
	 * @return false|object|array
	 */
	public function info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! is_object( $args ) || self::SLUG !== ( $args->slug ?? '' ) ) {
			return $result;
		}

		$headers = get_file_data(
			$this->main_file,
			array(
				'Name'        => 'Plugin Name',
				'PluginURI'   => 'Plugin URI',
				'Description' => 'Description',
				'Author'      => 'Author',
				'AuthorURI'   => 'Author URI',
				'UpdateURI'   => 'Update URI',
				'RequiresWP'  => 'Requires at least',
				'RequiresPHP' => 'Requires PHP',
			)
		);
		$release = $this->release( $headers['UpdateURI'] );

		if ( null === $release ) {
			return $result;
		}

		$readme   = $release['readme'] ?? array();
		$sections = $readme['sections'] ?? array( 'description' => '<p>' . esc_html( $headers['Description'] ) . '</p>' );

		// The GitHub release notes: what changed in exactly this version.
		$sections['changelog'] = ( '' !== trim( $release['notes'] ) ? '<pre>' . esc_html( $release['notes'] ) . '</pre>' : '' )
			. '<p><a href="' . esc_url( $release['url'] ) . '">' . esc_html__( 'Release on GitHub', 'mcp-bearer-auth' ) . '</a></p>';
		$author                = esc_html( $headers['Author'] );

		return (object) array(
			'name'              => $headers['Name'], // Not the download's.
			'slug'              => self::SLUG,
			'version'           => $release['version'],
			'author'            => '' !== $headers['AuthorURI'] ? '<a href="' . esc_url( $headers['AuthorURI'] ) . '">' . $author . '</a>' : $author,
			'homepage'          => '' !== $headers['PluginURI'] ? $headers['PluginURI'] : $release['url'],
			'short_description' => esc_html( $readme['short_description'] ?? $headers['Description'] ),
			'requires'          => $readme['requires'] ?? $headers['RequiresWP'],
			'tested'            => $readme['tested'] ?? '',
			'requires_php'      => $readme['requires_php'] ?? $headers['RequiresPHP'],
			'last_updated'      => $release['published'],
			'download_link'     => $release['package'],
			'sections'          => $sections,
		);
	}

	/**
	 * The `auto_update_plugin` filter, with MCP_BEARER_AUTO_UPDATE defined.
	 *
	 * @param bool|null $update Whether to auto-update.
	 * @param object    $item   Update offer.
	 * @return bool|null
	 */
	public function auto_update( $update, $item ) {
		if ( is_object( $item ) && plugin_basename( $this->main_file ) === ( $item->plugin ?? '' ) ) {
			return (bool) MCP_BEARER_AUTO_UPDATE;
		}

		return $update;
	}

	/**
	 * GitHub owner/repository from an Update URI.
	 *
	 * @param string $update_uri The `Update URI` header.
	 * @return string|null
	 */
	public static function repository( $update_uri ) {
		if ( ! preg_match( '#^https://github\.com/([A-Za-z0-9-]+/[A-Za-z0-9._-]+?)/?$#', $update_uri, $m ) ) {
			return null;
		}

		return $m[1];
	}

	/**
	 * The newest plugin release, cached.
	 *
	 * @param string $update_uri The `Update URI` header.
	 * @return array|null version, url, package, published, notes.
	 */
	private function release( $update_uri ) {
		$repository = self::repository( $update_uri );

		if ( null === $repository ) {
			return null;
		}

		$cached = get_site_transient( self::CACHE_KEY );

		if ( is_array( $cached ) && ( $cached['repository'] ?? '' ) === $repository ) {
			return $cached['release'];
		}

		$release = self::fetch( $repository );

		set_site_transient(
			self::CACHE_KEY,
			array(
				'repository' => $repository,
				'release'    => $release,
			),
			null === $release ? self::ERROR_TTL : self::CACHE_TTL
		);

		return $release;
	}

	/**
	 * Ask GitHub for the repository's releases and pick the newest plugin
	 * release.
	 *
	 * @param string $repository owner/repository.
	 * @return array|null
	 */
	private static function fetch( $repository ) {
		$response = wp_remote_get(
			'https://api.github.com/repos/' . $repository . '/releases?per_page=100',
			array(
				'timeout' => 10,
				'headers' => array( 'Accept' => 'application/vnd.github+json' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$releases = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $releases ) ) {
			return null;
		}

		$newest = null;

		foreach ( $releases as $release ) {
			$candidate = self::plugin_release( $repository, $release );

			if ( null !== $candidate && ( null === $newest || version_compare( $candidate['version'], $newest['version'], '>' ) ) ) {
				$newest = $candidate;
			}
		}

		if ( null !== $newest && null !== $newest['readme'] ) {
			$newest['readme'] = self::fetch_readme( $newest['readme'] );
		}

		return $newest;
	}

	/**
	 * A release's readme.txt, parsed.
	 *
	 * @param string $url Release download URL.
	 * @return array|null
	 */
	private static function fetch_readme( $url ) {
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		return Readme::parse( (string) wp_remote_retrieve_body( $response ) );
	}

	/**
	 * One GitHub release, if it is a plugin release.
	 *
	 * @param string $repository owner/repository.
	 * @param mixed  $release    Release from the API.
	 * @return array|null
	 */
	private static function plugin_release( $repository, $release ) {
		if ( ! is_array( $release ) || ! empty( $release['draft'] ) || ! empty( $release['prerelease'] ) ) {
			return null;
		}

		$tag = (string) ( $release['tag_name'] ?? '' );

		if ( ! preg_match( '/^' . preg_quote( self::TAG_PREFIX, '/' ) . '(\d+\.\d+\.\d+)$/', $tag, $m ) ) {
			return null;
		}

		// The package is installed as code: only this repository's own
		// release downloads, never a URL the API response merely names.
		$download = 'https://github.com/' . $repository . '/releases/download/' . $tag . '/';
		$assets   = array();

		foreach ( (array) ( $release['assets'] ?? array() ) as $asset ) {
			if ( is_array( $asset ) && in_array( $asset['name'] ?? '', array( self::ASSET, self::README ), true )
				&& ( $asset['browser_download_url'] ?? '' ) === $download . $asset['name'] ) {
				$assets[ $asset['name'] ] = $download . $asset['name'];
			}
		}

		if ( ! isset( $assets[ self::ASSET ] ) ) {
			return null;
		}

		return array(
			'version'   => $m[1],
			'url'       => 'https://github.com/' . $repository . '/releases/tag/' . $tag,
			'package'   => $assets[ self::ASSET ],
			'readme'    => $assets[ self::README ] ?? null,
			'published' => (string) ( $release['published_at'] ?? '' ),
			'notes'     => (string) ( $release['body'] ?? '' ),
		);
	}
}
