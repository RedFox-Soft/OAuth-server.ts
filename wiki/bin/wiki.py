#!/usr/bin/env python3
"""Launcher for the llm-wiki plugin's bundled scripts.

The scripts ship inside the plugin cache, at a path that carries the plugin
version, so any command written against a fixed path breaks on plugin upgrade.
This resolves the newest installed copy at call time instead.

    python wiki/bin/wiki.py search "authorization code" --json
    python wiki/bin/wiki.py lint
    python wiki/bin/wiki.py stats
    python wiki/bin/wiki.py setup --cache
    python wiki/bin/wiki.py graph-extract
    python wiki/bin/wiki.py graph-query neighbors --node concept:pkce

Set LLM_WIKI_SCRIPTS to override script discovery.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

WIKI_DIR = Path(__file__).resolve().parents[1]
PLUGIN_GLOB = "plugins/cache/llm-wiki/llm-wiki/*/skills/llm-wiki/scripts"

# subcommand -> (script filename, how the script wants the wiki directory)
COMMANDS = {
    "search": ("wiki_search.py", "flag"),
    "setup": ("setup_wiki.py", "flag"),
    "lint": ("wiki_lint.py", "positional"),
    "stats": ("wiki_stats.py", "positional"),
    "graph-extract": ("wiki_graph_extract.py", "positional"),
    "graph-lint": ("wiki_graph_lint.py", "positional"),
    "graph-query": ("wiki_graph_query.py", "positional"),
}

# Scripts whose PEP 723 dependencies are mandatory, not optional. wiki_search
# degrades to lexical BM25 without them; the graph scripts and setup hard-fail.
NEEDS_UV = {"search", "setup", "graph-extract", "graph-lint"}


def version_key(scripts_dir: Path) -> tuple[int, ...]:
    """Sort key from the plugin version in .../llm-wiki/<version>/skills/..."""
    version = scripts_dir.parents[2].name
    parts = []
    for chunk in version.split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return tuple(parts)


def find_scripts() -> Path:
    override = os.environ.get("LLM_WIKI_SCRIPTS")
    if override:
        path = Path(override).expanduser()
        if not path.is_dir():
            sys.exit(f"LLM_WIKI_SCRIPTS is not a directory: {path}")
        return path

    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
    candidates = [p for p in claude_home.glob(PLUGIN_GLOB) if p.is_dir()]
    if not candidates:
        sys.exit(
            f"llm-wiki scripts not found under {claude_home / PLUGIN_GLOB}.\n"
            "Install the llm-wiki plugin, or point LLM_WIKI_SCRIPTS at its scripts directory."
        )
    return max(candidates, key=version_key)


def build_argv(command: str, script: Path, wiki_style: str, extra: list[str]) -> list[str]:
    # uv reads the script's inline dependency block; bare python silently skips it.
    if command in NEEDS_UV:
        if not shutil.which("uv"):
            sys.exit(
                f"`{command}` needs uv to resolve the script's pinned dependencies "
                "(FastEmbed, sqlite-vec, PyYAML). Install uv: https://docs.astral.sh/uv/"
            )
        argv = ["uv", "run", "--script", str(script)]
    else:
        argv = [sys.executable, str(script)]

    wiki = str(WIKI_DIR)
    if wiki_style == "flag":
        if "--wiki" not in extra:
            argv += ["--wiki", wiki]
        return argv + extra

    # Positional wiki arg goes first, but after any subcommand (graph-query).
    if any(not a.startswith("-") and Path(a).name == WIKI_DIR.name for a in extra):
        return argv + extra  # caller passed the wiki path themselves
    if command == "graph-query":
        if not extra:
            sys.exit("graph-query needs a subcommand: neighbors | edges | path | facts")
        return argv + [wiki] + extra
    return argv + [wiki] + extra


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        print("Commands: " + ", ".join(COMMANDS))
        return 0

    command, extra = args[0], args[1:]
    if command not in COMMANDS:
        sys.exit(f"Unknown command: {command}\nCommands: {', '.join(COMMANDS)}")

    script_name, wiki_style = COMMANDS[command]
    script = find_scripts() / script_name
    if not script.is_file():
        sys.exit(f"Script missing from the installed plugin: {script}")

    env = dict(os.environ)
    # The scripts print U+2192 and friends; a cp1252 console raises
    # UnicodeEncodeError mid-report without this.
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")

    argv = build_argv(command, script, wiki_style, extra)
    return subprocess.run(argv, cwd=WIKI_DIR.parent, env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
