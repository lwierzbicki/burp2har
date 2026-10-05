"""click entry point for burp2har. Argument parsing only — logic is in core."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import click

from .core import __version__, convert


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(version=__version__, prog_name="burp2har")
@click.option(
    "-i",
    "--input",
    "input_xml",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="Burp XML file exported via 'Save items -> XML'.",
)
@click.option(
    "-o",
    "--output",
    "output_har",
    default="output.har",
    show_default=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output HAR path.",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Print warnings to stderr.")
def cli(input_xml: Path, output_har: Path, verbose: bool) -> None:
    """Convert a Burp Suite XML export (Save items -> XML) to a HAR 1.2 file."""
    try:
        convert(str(input_xml), str(output_har), verbose=verbose)
    except ET.ParseError as e:
        # malformed XML surfaces as a clean, actionable CLI error (exit 1)
        raise click.ClickException(f"Invalid XML: {e}") from e
    except OSError as e:
        # filesystem failures (unwritable path, full disk) surface cleanly
        raise click.ClickException(f"Failed to write output HAR: {e}") from e
    click.echo(f"[+] Wrote HAR: {output_har}")


if __name__ == "__main__":
    cli()
