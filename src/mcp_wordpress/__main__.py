"""Entry point: `python -m mcp_wordpress` or the `mcp-wordpress-oauth` console script."""

from __future__ import annotations

import logging
import os
import sys

from dotenv import load_dotenv

from . import __version__
from .config import ConfigError, load
from .server import MCP_PATH, client_settings, create_server, http_middleware


def main() -> None:
    load_dotenv()  # a local .env, if present; real env vars take precedence
    # FastMCP configures its own "fastmcp" logger and doesn't propagate to
    # root; this covers the package's own loggers.
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        settings = load()
        mcp = create_server(settings)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    log = logging.getLogger(__name__)
    log.info("Starting mcp-wordpress-oauth %s in AUTH_MODE=%s for WordPress %s",
             __version__, settings.auth_mode, settings.wordpress.url)
    for line in client_settings(settings):
        log.info("%s", line)
    # Stateless HTTP (D10). No banner (it makes FastMCP query pypi.org).
    # No access log (D8): in AUTH_MODE=wordpress, WordPress hands the new
    # Application Password to /wp/callback in the query string.
    mcp.run(
        transport="http", host=settings.host, port=settings.port, path=MCP_PATH,
        stateless_http=True, show_banner=False, middleware=http_middleware(settings),
        uvicorn_config={"access_log": False},
    )


if __name__ == "__main__":
    main()
