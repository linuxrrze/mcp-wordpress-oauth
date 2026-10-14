<?php
/**
 * Updates from GitHub releases: which release is offered, from where, how
 * often GitHub is asked.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use Brain\Monkey\Filters;
use Brain\Monkey\Functions;
use MCPBearerAuth\Updater;

class UpdaterTest extends TestCase {

	const MAIN_FILE  = '/var/www/html/wp-content/plugins/mcp-bearer-auth/mcp-bearer-auth.php';
	const BASENAME   = 'mcp-bearer-auth/mcp-bearer-auth.php';
	const UPDATE_URI = 'https://github.com/linuxrrze/mcp-wordpress-oauth';
	const DOWNLOAD   = 'https://github.com/linuxrrze/mcp-wordpress-oauth/releases/download/';

	/**
	 * Releases the fake GitHub API returns.
	 *
	 * @var array|null
	 */
	private $releases = array();

	/**
	 * readme.txt served for release downloads, or null for a 404.
	 *
	 * @var string|null
	 */
	private $readme = "=== MCP Bearer Auth ===\nRequires at least: 7.0\nTested up to: 7.1\nRequires PHP: 8.2\n\nShort.\n\n== Description ==\n\nLong <b>text</b>.\n";

	/**
	 * Site transients with their expiry.
	 *
	 * @var array
	 */
	private $site_transients = array();

	protected function setUp(): void {
		parent::setUp();
		$this->fetched = array();
		Functions\stubs(
			array(
				'plugin_basename'    => static function ( $file ) {
					return basename( dirname( $file ) ) . '/' . basename( $file );
				},
				'get_site_transient' => function ( $key ) {
					return $this->site_transients[ $key ]['value'] ?? false;
				},
				'set_site_transient' => function ( $key, $value, $ttl ) {
					$this->site_transients[ $key ] = array(
						'value' => $value,
						'ttl'   => $ttl,
					);
					return true;
				},
				'get_file_data'      => static function () {
					return array(
						'Name'        => 'MCP Bearer Auth',
						'Description' => 'Bearer <tokens>.',
						'Author'      => 'Marcel Ritter',
						'AuthorURI'   => '',
						'PluginURI'   => 'https://github.com/linuxrrze/mcp-wordpress-oauth/tree/main/wordpress-plugin/mcp-bearer-auth',
						'UpdateURI'   => self::UPDATE_URI,
						'RequiresWP'  => '6.9',
						'RequiresPHP' => '8.1',
					);
				},
				'esc_html'           => 'htmlspecialchars',
				'esc_url'            => 'htmlspecialchars',
				'esc_html__'         => static function ( $text ) {
					return $text;
				},
				'wp_remote_get'      => function ( $url ) {
					$this->fetched[] = $url;
					if ( null === $this->releases ) {
						return new \WP_Error( 'http_request_failed', 'down' );
					}
					if ( str_ends_with( $url, '/readme.txt' ) ) {
						return null === $this->readme ? array( 'code' => 404, 'body' => '' ) : array( 'code' => 200, 'body' => $this->readme );
					}
					return array(
						'code' => 200,
						'body' => json_encode( $this->releases ),
					);
				},
			)
		);
	}

	private static function release( $tag, array $extra = array(), $asset = null, $readme = null ) {
		return array_merge(
			array(
				'tag_name'     => $tag,
				'draft'        => false,
				'prerelease'   => false,
				'published_at' => '2026-10-14T12:00:00Z',
				'body'         => "Notes for $tag",
				'assets'       => array(
					array(
						'name'                 => 'mcp-bearer-auth.zip',
						'browser_download_url' => $asset ?? self::DOWNLOAD . $tag . '/mcp-bearer-auth.zip',
					),
					array(
						'name'                 => 'readme.txt',
						'browser_download_url' => $readme ?? self::DOWNLOAD . $tag . '/readme.txt',
					),
				),
			),
			$extra
		);
	}

	private function check( $plugin_file = self::BASENAME, $update_uri = self::UPDATE_URI, $earlier = false ) {
		$updater = new Updater( self::MAIN_FILE );
		return $updater->update(
			$earlier,
			array(
				'Version'     => '0.1.0',
				'UpdateURI'   => $update_uri,
				'RequiresWP'  => '6.9',
				'RequiresPHP' => '8.1',
			),
			$plugin_file
		);
	}

	public function test_offers_the_newest_plugin_release() {
		$this->releases = array(
			self::release( 'v3.0.0' ), // The server's releases share the repository.
			self::release( 'mcp-bearer-auth-v0.12.0', array( 'draft' => true ) ),
			self::release( 'mcp-bearer-auth-v0.11.0', array( 'prerelease' => true ) ),
			self::release( 'mcp-bearer-auth-v0.2.0' ),
			self::release( 'mcp-bearer-auth-v0.10.0' ),
			self::release( 'mcp-bearer-auth-v0.9.0' ),
		);

		$this->assertSame(
			array(
				'slug'         => 'mcp-bearer-auth',
				'version'      => '0.10.0',
				'url'          => 'https://github.com/linuxrrze/mcp-wordpress-oauth/releases/tag/mcp-bearer-auth-v0.10.0',
				'package'      => self::DOWNLOAD . 'mcp-bearer-auth-v0.10.0/mcp-bearer-auth.zip',
				'requires'     => '7.0', // The new version's, from its readme.txt.
				'tested'       => '7.1',
				'requires_php' => '8.2',
			),
			$this->check()
		);
		$this->assertSame(
			array(
				'https://api.github.com/repos/linuxrrze/mcp-wordpress-oauth/releases?per_page=100',
				self::DOWNLOAD . 'mcp-bearer-auth-v0.10.0/readme.txt',
			),
			$this->fetched
		);
	}

	public function test_without_a_readme_the_installed_requirements_apply() {
		$this->releases = array( self::release( 'mcp-bearer-auth-v0.2.0' ) );
		$this->readme   = null;

		$update = $this->check();

		$this->assertSame( array( '6.9', '', '8.1' ), array( $update['requires'], $update['tested'], $update['requires_php'] ) );
	}

	public function test_readme_must_be_this_repositorys_release_download() {
		$this->releases = array( self::release( 'mcp-bearer-auth-v0.2.0', array(), null, 'https://evil.example/readme.txt' ) );

		$this->assertSame( '6.9', $this->check()['requires'] );
		$this->assertNotContains( 'https://evil.example/readme.txt', $this->fetched );
	}

	public function test_package_must_be_this_repositorys_release_download() {
		$this->releases = array(
			self::release( 'mcp-bearer-auth-v0.3.0', array(), 'https://evil.example/mcp-bearer-auth.zip' ),
			self::release( 'mcp-bearer-auth-v0.2.0', array(), 'https://github.com/someone/else/releases/download/mcp-bearer-auth-v0.2.0/mcp-bearer-auth.zip' ),
			self::release( 'mcp-bearer-auth-v0.1.5', array( 'assets' => array() ) ),
		);

		$this->assertFalse( $this->check() );
	}

	public function test_other_plugins_and_earlier_answers_are_untouched() {
		$this->releases = array( self::release( 'mcp-bearer-auth-v0.2.0' ) );
		$earlier        = array( 'version' => '9.9.9' );

		$this->assertFalse( $this->check( 'other/other.php' ) );
		$this->assertSame( $earlier, $this->check( self::BASENAME, self::UPDATE_URI, $earlier ) );
		$this->assertSame( array(), $this->fetched );
	}

	public function test_update_uri_must_name_a_github_repository() {
		$this->releases = array( self::release( 'mcp-bearer-auth-v0.2.0' ) );

		$this->assertFalse( $this->check( self::BASENAME, 'https://github.example/linuxrrze/mcp-wordpress-oauth' ) );
		$this->assertFalse( $this->check( self::BASENAME, 'https://github.com/linuxrrze/mcp-wordpress-oauth/../../x' ) );
		$this->assertSame( array(), $this->fetched );
		$this->assertSame( 'a/b.c', Updater::repository( 'https://github.com/a/b.c/' ) );
	}

	public function test_github_is_asked_once_per_cache_period() {
		$this->releases = array( self::release( 'mcp-bearer-auth-v0.2.0' ) );

		$this->assertSame( '0.2.0', $this->check()['version'] );
		$this->assertSame( '0.2.0', $this->check()['version'] );
		$this->assertCount( 2, $this->fetched ); // The releases list and the readme, once.
		$this->assertSame( Updater::CACHE_TTL, $this->site_transients[ Updater::CACHE_KEY ]['ttl'] );
	}

	public function test_failures_are_cached_briefly() {
		$this->releases = null;

		$this->assertFalse( $this->check() );
		$this->assertFalse( $this->check() );
		$this->assertCount( 1, $this->fetched );
		$this->assertSame( Updater::ERROR_TTL, $this->site_transients[ Updater::CACHE_KEY ]['ttl'] );
	}

	public function test_details_dialog() {
		$this->releases = array( self::release( 'mcp-bearer-auth-v0.2.0', array( 'body' => '<script>x</script>' ) ) );
		$updater        = new Updater( self::MAIN_FILE );

		$info = $updater->info( false, 'plugin_information', (object) array( 'slug' => 'mcp-bearer-auth' ) );

		$this->assertSame( '0.2.0', $info->version );
		$this->assertSame( self::DOWNLOAD . 'mcp-bearer-auth-v0.2.0/mcp-bearer-auth.zip', $info->download_link );
		$this->assertSame( array( '7.0', '7.1', '8.2' ), array( $info->requires, $info->tested, $info->requires_php ) );
		$this->assertSame( 'Short.', $info->short_description );
		$this->assertSame( '<p>Long &lt;b&gt;text&lt;/b&gt;.</p>', $info->sections['description'] );
		$this->assertStringContainsString( '&lt;script&gt;', $info->sections['changelog'] );
		$this->assertStringNotContainsString( '<script>', $info->sections['changelog'] );
		$this->assertFalse( $updater->info( false, 'plugin_information', (object) array( 'slug' => 'akismet' ) ) );
		$this->assertFalse( $updater->info( false, 'query_plugins', (object) array( 'slug' => 'mcp-bearer-auth' ) ) );
	}

	public function test_hooks_by_default() {
		( new Updater( self::MAIN_FILE ) )->register_hooks();

		$this->assertNotFalse( Filters\has( 'update_plugins_github.com' ) );
		$this->assertNotFalse( Filters\has( 'plugins_api' ) );
		$this->assertFalse( Filters\has( 'auto_update_plugin' ) );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_constants() {
		define( 'MCP_BEARER_UPDATE_CHECK', false );
		define( 'MCP_BEARER_AUTO_UPDATE', true );
		$updater = new Updater( self::MAIN_FILE );
		$updater->register_hooks();

		$this->assertFalse( Filters\has( 'update_plugins_github.com' ) );
		$this->assertNotFalse( Filters\has( 'auto_update_plugin' ) );
		$this->assertTrue( $updater->auto_update( null, (object) array( 'plugin' => self::BASENAME ) ) );
		$this->assertNull( $updater->auto_update( null, (object) array( 'plugin' => 'other/other.php' ) ) );
	}
}
