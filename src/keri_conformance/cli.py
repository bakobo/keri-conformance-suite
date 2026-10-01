"""Command-line entry point for the conformance runner (`kcs`)."""

import argparse
import sys

from keri_conformance import __version__

USAGE_MISSING = "e.input.missing.f"
USAGE_INVALID = "e.input.format.f"


class _UsageError(Exception):
    """Raised instead of argparse's own exit, so every usage failure carries a code."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse calls this for every bad argument
        raise _UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="kcs",
        description="Run CESR, KERI, ACDC and IPEX conformance cases against an adapter.",
    )
    parser.add_argument("--version", action="store_true", help="print the runner version and exit")
    return parser


def _fail(parser: argparse.ArgumentParser, code: str, sentence: str) -> int:
    print(f"{code}: {sentence}", file=sys.stderr)
    parser.print_usage(sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        return _fail(parser, USAGE_INVALID,
                     f"The command line could not be understood ({exc}). Retrying the same "
                     "command will not help; correct the arguments.")
    if args.version:
        print(f"kcs {__version__}")
        return 0
    return _fail(parser, USAGE_MISSING,
                 "No command was given. Pass --version, or see the usage line below.")
