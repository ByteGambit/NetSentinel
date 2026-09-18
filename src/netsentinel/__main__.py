"""Minimal command-line entry point for the NetSentinel package."""

from __future__ import annotations

import argparse
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser without starting application services."""

    return argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel network security monitoring application.",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and show the placeholder help output."""

    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
