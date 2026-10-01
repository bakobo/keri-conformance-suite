"""Command-line entry point for the conformance runner (`kcs`)."""

import argparse
import sys

from keri_conformance import __version__


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kcs",
        description="Run CESR, KERI, ACDC and IPEX conformance cases against an adapter.",
    )
    parser.add_argument("--version", action="store_true", help="print the runner version and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"kcs {__version__}")
        return 0
    parser.print_usage(sys.stderr)
    return 2
