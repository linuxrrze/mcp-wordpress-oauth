<?php
/**
 * The readme.txt format WordPress plugins describe themselves in.
 *
 * @package MCPBearerAuth
 */

namespace MCPBearerAuth;

/**
 * Parses a readme.txt into the fields the plugin details dialog and the
 * update offer use. The text comes from a download, so every piece of it is
 * escaped; the only markup is the small subset written here (headings,
 * lists, paragraphs, `code`, **bold**, and http(s) links).
 */
final class Readme {

	/**
	 * Header fields → keys of the parsed array.
	 */
	const FIELDS = array(
		'requires at least' => 'requires',
		'tested up to'      => 'tested',
		'requires php'      => 'requires_php',
		'stable tag'        => 'stable_tag',
	);

	/**
	 * Sections shown in the details dialog, by readme heading.
	 */
	const SECTIONS = array(
		'description'                => 'description',
		'installation'               => 'installation',
		'frequently asked questions' => 'faq',
		'changelog'                  => 'changelog',
	);

	/**
	 * Parse a readme.txt.
	 *
	 * @param string $text File contents.
	 * @return array name, short_description, requires, tested, requires_php,
	 *               stable_tag, sections; only what the file has.
	 */
	public static function parse( $text ) {
		$lines  = explode( "\n", str_replace( array( "\r\n", "\r" ), "\n", $text ) );
		$result = array();

		if ( isset( $lines[0] ) && preg_match( '/^===\s*(.+?)\s*===\s*$/', $lines[0], $m ) ) {
			$result['name'] = $m[1];
			array_shift( $lines );
		}

		// Header fields up to the first blank line, then the short description
		// up to the first section.
		while ( $lines && '' !== trim( $lines[0] ) ) {
			$line = array_shift( $lines );

			// All of them are versions; WordPress compares and prints them.
			if ( preg_match( '/^([^:]+):\s*([0-9][0-9A-Za-z.+-]*)\s*$/', $line, $m ) && isset( self::FIELDS[ strtolower( trim( $m[1] ) ) ] ) ) {
				$result[ self::FIELDS[ strtolower( trim( $m[1] ) ) ] ] = $m[2];
			}
		}

		$short = array();

		while ( $lines && ! preg_match( '/^==[^=]/', $lines[0] ) ) {
			$short[] = trim( array_shift( $lines ) );
		}

		if ( '' !== trim( implode( ' ', $short ) ) ) {
			$result['short_description'] = trim( implode( ' ', $short ) );
		}

		$sections = array();
		$key      = null;

		foreach ( $lines as $line ) {
			if ( preg_match( '/^==\s*([^=].*?)\s*==\s*$/', $line, $m ) ) {
				$key = self::SECTIONS[ strtolower( $m[1] ) ] ?? null;

				if ( null !== $key ) {
					$sections[ $key ] = array();
				}
			} elseif ( null !== $key ) {
				$sections[ $key ][] = $line;
			}
		}

		foreach ( $sections as $key => $body ) {
			$html = self::html( $body );

			if ( '' !== $html ) {
				$result['sections'][ $key ] = $html;
			}
		}

		return $result;
	}

	/**
	 * Lines of one section as HTML.
	 *
	 * @param string[] $lines Lines.
	 * @return string
	 */
	private static function html( array $lines ) {
		$html  = '';
		$para  = array();
		$list  = array();
		$type  = '';
		$flush = static function () use ( &$html, &$para, &$list, &$type ) {
			if ( $para ) {
				$html .= '<p>' . self::inline( implode( ' ', $para ) ) . '</p>';
				$para  = array();
			}

			if ( $list ) {
				$html .= '<' . $type . '><li>' . implode( '</li><li>', array_map( array( self::class, 'inline' ), $list ) ) . '</li></' . $type . '>';
				$list  = array();
			}
		};

		foreach ( $lines as $line ) {
			$line = trim( $line );

			if ( '' === $line ) {
				$flush();
			} elseif ( preg_match( '/^=\s*(.+?)\s*=$/', $line, $m ) ) {
				$flush();
				$html .= '<h4>' . self::inline( $m[1] ) . '</h4>';
			} elseif ( preg_match( '/^(?:([*-])|\d+\.)\s+(.*)$/', $line, $m ) ) {
				$item_type = '' !== $m[1] ? 'ul' : 'ol';

				if ( $para || ( $list && $item_type !== $type ) ) {
					$flush();
				}

				$type   = $item_type;
				$list[] = $m[2];
			} else {
				if ( $list ) {
					$flush();
				}

				$para[] = $line;
			}
		}

		$flush();

		return $html;
	}

	/**
	 * Escape a line, then add `code`, **bold** and http(s) links.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private static function inline( $text ) {
		$text = esc_html( $text );
		$text = preg_replace( '/`([^`]+)`/', '<code>$1</code>', $text );
		$text = preg_replace( '/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $text );

		return preg_replace( '#\[([^\]]+)\]\((https?://[^\s)"<>]+)\)#', '<a href="$2">$1</a>', $text );
	}
}
