<?php
/**
 * readme.txt: fields and sections for WordPress, everything escaped.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth\Tests\Unit;

use MCPBearerAuth\Readme;

class ReadmeTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		\Brain\Monkey\Functions\when( 'esc_html' )->alias( 'htmlspecialchars' );
	}

	public function test_the_plugins_own_readme() {
		$readme = Readme::parse( file_get_contents( dirname( __DIR__, 2 ) . '/readme.txt' ) );

		$this->assertSame( 'MCP Bearer Auth', $readme['name'] );
		$this->assertSame( array( '6.9', '6.9', '8.1' ), array( $readme['requires'], $readme['tested'], $readme['requires_php'] ) );
		$this->assertStringStartsWith( 'Lets an MCP server act as a WordPress user', $readme['short_description'] );
		$this->assertSame( array( 'description', 'installation', 'faq', 'changelog' ), array_keys( $readme['sections'] ) );
		$this->assertStringContainsString( '<a href="https://github.com/linuxrrze/mcp-wordpress-oauth">mcp-wordpress-oauth</a>', $readme['sections']['description'] );
		$this->assertStringContainsString( '<h4>Every bearer request is treated as anonymous</h4>', $readme['sections']['faq'] );
		$this->assertStringContainsString( '<ol><li>Upload <code>mcp-bearer-auth.zip</code>', $readme['sections']['installation'] );
	}

	public function test_markup() {
		$readme = Readme::parse( "=== X ===\nStable tag: 1.2.3\nTags: a\n\nShort\ntext.\n\n== Description ==\n\nOne\ntwo **bold**.\n* a\n* `b`\n\n1. c\n\n= Q =\nA.\n\n== Screenshots ==\n\nIgnored.\n" );

		$this->assertSame( '1.2.3', $readme['stable_tag'] );
		$this->assertSame( 'Short text.', $readme['short_description'] );
		$this->assertSame(
			'<p>One two <strong>bold</strong>.</p><ul><li>a</li><li><code>b</code></li></ul><ol><li>c</li></ol><h4>Q</h4><p>A.</p>',
			$readme['sections']['description']
		);
		$this->assertSame( array( 'description' ), array_keys( $readme['sections'] ) );
	}

	public function test_downloaded_text_cannot_inject_markup() {
		$readme = Readme::parse(
			"=== <img src=x onerror=alert(1)> ===\nTested up to: <b>7</b>\nRequires PHP: 8.2 <b>\n\n== Description ==\n\n"
			. "<script>alert(1)</script>\n[click](javascript:alert(1)) [x](https://a.example/\"onmouseover=\"alert(1))\n"
		);

		$html = $readme['sections']['description'];
		$this->assertStringNotContainsString( '<script', $html );
		$this->assertStringNotContainsString( 'href="javascript:', $html );
		$this->assertStringNotContainsString( '"onmouseover', $html );
		$this->assertArrayNotHasKey( 'tested', $readme );
		$this->assertArrayNotHasKey( 'requires_php', $readme );
		$this->assertSame( '<img src=x onerror=alert(1)>', $readme['name'] ); // Raw: the updater never shows it.
	}
}
