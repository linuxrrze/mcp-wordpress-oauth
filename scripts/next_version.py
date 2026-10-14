#!/usr/bin/env python3
"""Compute the next release version from git tags and commit messages.

Git tags are the single source of truth for the version (docs/decisions.md,
D11). Two components are versioned independently, each from its own tags and
only from the commits that touch it:

- server: tags vX.Y.Z, commits outside wordpress-plugin/mcp-bearer-auth/
- plugin: tags mcp-bearer-auth-vX.Y.Z, commits inside it

Bump rules, applied to those commits since the component's last tag
(Conventional Commits style, matched leniently):

- "BREAKING CHANGE" in a message, or a "type!:" subject  -> major
- a "feat:" / "feat(scope):" subject                    -> minor
- anything else                                         -> patch

While the major version is 0, a breaking change bumps the minor version
instead (SemVer: 0.y.z makes no stability promise, so going to 1.0.0 should be
a deliberate choice: use `--bump major` via the workflow's manual trigger).

No tag yet -> INITIAL_VERSION. No commits since the last tag -> no release.

Usage: next_version.py [--component server|plugin] [--bump auto|patch|minor|major]
Prints key=value lines (version, tag, previous, release) and appends them to
$GITHUB_OUTPUT when running in GitHub Actions.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

INITIAL_VERSION = "0.1.0"
PLUGIN_PATH = "wordpress-plugin/mcp-bearer-auth/"
# component -> (tag prefix, pathspec of the commits that count)
COMPONENTS = {
    "server": ("v", (".", f":(exclude){PLUGIN_PATH}")),
    "plugin": ("mcp-bearer-auth-v", (PLUGIN_PATH,)),
}
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_BREAKING_SUBJECT = re.compile(r"^\w+(\([^)]*\))?!:", re.MULTILINE)
_FEAT_SUBJECT = re.compile(r"^feat(\([^)]*\))?:", re.IGNORECASE)


def parse(version: str) -> tuple[int, int, int]:
    match = _SEMVER.match(version.strip())
    if not match:
        raise ValueError(f"Not a X.Y.Z version: {version!r}")
    return int(match[1]), int(match[2]), int(match[3])


def detect_bump(messages: list[str]) -> str:
    bump = "patch"
    for message in messages:
        subject = message.strip().splitlines()[0] if message.strip() else ""
        if "BREAKING CHANGE" in message or _BREAKING_SUBJECT.match(subject):
            return "major"
        if _FEAT_SUBJECT.match(subject):
            bump = "minor"
    return bump


def next_version(previous: str | None, messages: list[str], bump: str = "auto") -> str | None:
    """Return the next X.Y.Z, or None when there is nothing to release."""
    if previous is None:
        return INITIAL_VERSION
    if not messages and bump == "auto":
        return None
    major, minor, patch = parse(previous)
    kind = detect_bump(messages) if bump == "auto" else bump
    if kind == "major" and major == 0 and bump == "auto":
        kind = "minor"
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def latest_tag(prefix: str) -> str | None:
    try:
        tag = _git("describe", "--tags", "--abbrev=0", "--match", f"{prefix}[0-9]*.[0-9]*.[0-9]*").strip()
    except subprocess.CalledProcessError:
        return None
    return tag or None


def messages_since(tag: str | None, paths: tuple[str, ...]) -> list[str]:
    rev = f"{tag}..HEAD" if tag else "HEAD"
    raw = _git("log", rev, "--format=%B%x00", "--", *paths)
    return [m for m in raw.split("\x00") if m.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--component", choices=sorted(COMPONENTS), default="server")
    parser.add_argument("--bump", choices=["auto", "patch", "minor", "major"], default="auto")
    args = parser.parse_args(argv)

    prefix, paths = COMPONENTS[args.component]
    tag = latest_tag(prefix)
    version = next_version(tag.removeprefix(prefix) if tag else None, messages_since(tag, paths), args.bump)
    outputs = {
        "previous": tag or "",
        "version": version or "",
        "tag": f"{prefix}{version}" if version else "",
        "release": "true" if version else "false",
    }
    lines = "".join(f"{k}={v}\n" for k, v in outputs.items())
    sys.stdout.write(lines)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
