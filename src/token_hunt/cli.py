"""token-hunt CLI entry point."""
from __future__ import annotations
import sys

import click

from token_hunt import __version__


@click.group()
@click.version_option(__version__, "--version")
def main() -> None:
    """token-hunt: catch secrets at chat time, not commit time."""


@main.command()
@click.argument("path", required=False, type=click.Path(exists=True))
@click.option("--stdin", is_flag=True, help="Read text from stdin instead of file.")
@click.option("--context", default="UserPromptSubmit",
              help="Detection point (UserPromptSubmit, PreToolUse:Bash, etc.)")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]))
def scan(path, stdin, context, fmt):
    """Scan a file or stdin for secret leaks."""
    # Implemented in Task 11
    click.echo("not yet implemented", err=True)
    sys.exit(1)


@main.command(name="list")
@click.option("--all", "show_all", is_flag=True, help="Show closed leaks too.")
def list_cmd(show_all):
    """List open leaks in rotations.log."""
    # Implemented in Task 12
    click.echo("not yet implemented", err=True)
    sys.exit(1)


@main.command()
@click.argument("leak_id", type=int)
@click.option("--note", default="", help="Optional rotation note.")
def close(leak_id, note):
    """Mark a leak as closed after rotation."""
    # Implemented in Task 13
    click.echo("not yet implemented", err=True)
    sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False))
@click.option("--context", default="PostToolUse:Read")
def watch(path, context):
    """Watch a directory for new transcript files and scan them."""
    # Implemented in Task 14
    click.echo("not yet implemented", err=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
