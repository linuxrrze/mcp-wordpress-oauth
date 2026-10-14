"""mcp-wordpress-oauth: WordPress Abilities as MCP tools, per signed-in user."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-wordpress-oauth")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0"
