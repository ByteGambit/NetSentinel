"""Command-line entry point for NetSentinel."""

from __future__ import annotations

import argparse
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser without starting application services."""

    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel network security monitoring application.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="start the PyQt6 desktop application",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Start the GUI when requested, otherwise retain the CLI help smoke path."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        from netsentinel.presentation.app import run_application

        return run_application(argv=[])
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
