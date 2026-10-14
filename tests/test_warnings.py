"""Startup stays quiet: with httpx2 installed, Authlib no longer warns about
its httpx fallback."""

import subprocess
import sys


def test_no_authlib_httpx_warning_on_import():
    result = subprocess.run(
        [sys.executable, "-W", "default", "-c", "import mcp_wordpress.server, mcp_wordpress.wp_oauth"],
        capture_output=True, text=True, check=True,
    )
    assert "httpx module is deprecated" not in result.stderr
    assert "Warning" not in result.stderr, result.stderr
