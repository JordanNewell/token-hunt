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
@click.option("--no-log", is_flag=True, help="Don't write to rotations.log.")
def scan(path, stdin, context, fmt, no_log):
    """Scan a file or stdin for secret leaks."""
    import json as _json
    import sys
    from pathlib import Path as _Path

    from token_hunt.engine import scan as scan_engine
    from token_hunt.store import LeakRecord, Store
    from token_hunt.types import ScanContext
    from dataclasses import asdict

    if stdin:
        text = sys.stdin.read()
        file_path = None
    elif path:
        text = _Path(path).read_text(encoding="utf-8", errors="replace")
        file_path = str(path)
    else:
        click.echo("error: provide a PATH or use --stdin", err=True)
        sys.exit(2)

    ctx = ScanContext(detection_point=context, file_path=file_path)
    result = scan_engine(text, ctx)

    if not no_log and result.matches:
        store = Store()
        for m in result.matches:
            store.append(LeakRecord(
                id=None,
                ts=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    .isoformat(timespec="seconds"),
                kind=m.kind,
                source=m.detection_point,
                fingerprint=m.fingerprint,
                rotate_url=m.rotate_url,
                status="open",
            ))

    if fmt == "json":
        click.echo(_json.dumps({
            "count": result.count,
            "matches": [asdict(m) for m in result.matches],
        }, indent=2))
    else:
        if not result.matches:
            click.echo("no leaks detected")
        else:
            click.echo(f"⚠️  {result.count} potential leak(s) detected:")
            for m in result.matches:
                fp_preview = m.fingerprint[:8] if m.fingerprint else "n/a"
                click.echo(f"  - {m.kind} (fp={fp_preview}) @ line {m.line}")
                if m.rotate_url:
                    click.echo(f"    rotate: {m.rotate_url}")


@main.command(name="list")
@click.option("--all", "show_all", is_flag=True, help="Show closed leaks too.")
def list_cmd(show_all):
    """List open leaks in rotations.log."""
    from token_hunt.store import Store

    store = Store()
    if show_all:
        records = []
        for line in store.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                import json as _j
                from token_hunt.store import LeakRecord
                records.append(LeakRecord(**_j.loads(line)))
    else:
        records = store.list_open()

    if not records:
        click.echo("no open leaks" if not show_all else "no leaks recorded")
        return

    click.echo(f"{'ID':<5} {'KIND':<22} {'SOURCE':<22} {'WHEN':<20} {'STATUS':<10} URL")
    for r in records:
        ts_short = r.ts[:19].replace("T", " ")
        status = r.status.upper()
        if r.is_overdue:
            status = "OVERDUE"
        click.echo(f"{r.id:<5} {r.kind:<22} {r.source:<22} {ts_short:<20} {status:<10} {r.rotate_url}")


@main.command()
@click.argument("leak_id", type=int)
@click.option("--note", default="", help="Optional rotation note.")
def close(leak_id, note):
    """Mark a leak as closed after rotation."""
    from token_hunt.store import Store
    store = Store()
    if store.close(leak_id, note=note):
        click.echo(f"leak {leak_id} marked closed")
    else:
        click.echo(f"error: leak {leak_id} not found", err=True)
        import sys; sys.exit(1)


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
