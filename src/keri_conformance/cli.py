"""Command-line entry point for the conformance runner (`kcs`)."""

import argparse
import json
import sys
from pathlib import Path

from keri_conformance import __version__
from keri_conformance.cases import load_cases
from keri_conformance.errors import E_REPORT_WRITE, HelloRefused, RunnerError
from keri_conformance.run import VERDICT_EXIT, human_summary, run_suite
from keri_conformance.session import AdapterSession, Limits, load_vocabulary

EXIT_CODES = """\
exit codes:
  0  conformant: every MUST assertion in every active case that was run passed
  1  at least one MUST assertion in an active case failed
  2  usage error
  3  the adapter's hello was refused; no case was run
  4  runner fault: the adapter could not be started, a case is malformed, the runner is
     running as root, the report could not be written, or an active MUST assertion uses a
     check this runner version cannot evaluate
"""


def _positive(kind):
    def parse(text):
        try:
            value = kind(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{text!r} is not a number") from exc
        if value <= 0:
            raise argparse.ArgumentTypeError(f"{text!r} must be greater than zero")
        return value

    return parse


def _adapter_options(parser):
    parser.add_argument("--suite", default=".", help="root of the suite checkout, which holds "
                        "profiles/ and cases/ (default: the current directory)")
    parser.add_argument("--timeout", type=_positive(float), default=Limits.timeout,
                        help=f"seconds allowed for each request (default: {Limits.timeout:g})")
    parser.add_argument("--max-response", type=_positive(int), default=Limits.max_response,
                        help=f"largest response line in bytes (default: {Limits.max_response})")
    parser.add_argument("--pass-env", action="extend", nargs="+", default=[], metavar="NAME",
                        help="pass this environment variable through to the adapter, which "
                             "otherwise sees only PATH, HOME, LANG, LC_ALL, TMPDIR and SYSTEMROOT")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kcs",
        description="Run CESR, KERI, ACDC and IPEX conformance cases against an adapter.",
    )
    parser.add_argument("--version", action="store_true", help="print the runner version and exit")
    commands = parser.add_subparsers(dest="command")
    run = commands.add_parser("run", help="run cases and write a conformance report",
                              epilog=EXIT_CODES,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    run.add_argument("--adapter", required=True, metavar="CMD",
                     help="the command that starts the adapter, split like a shell would split it "
                          "but never run through a shell")
    run.add_argument("--cases", help="directory of cases (default: SUITE/cases)")
    run.add_argument("--profile", help="run only the cases in this profile")
    run.add_argument("--report", default="kcs-report.json",
                     help="where to write the JSON report (default: kcs-report.json)")
    _adapter_options(run)
    run.set_defaults(handler=_run)
    return parser


def _session(args, command) -> AdapterSession:
    vocabulary = load_vocabulary(args.suite)
    limits = Limits(timeout=args.timeout, max_response=args.max_response)
    return AdapterSession(command, vocabulary, limits=limits, pass_env=args.pass_env)


def _run(args) -> int:
    cases_dir = args.cases or str(Path(args.suite) / "cases")
    cases = load_cases(cases_dir)
    with _session(args, args.adapter) as session:
        session.open()
        report = run_suite(session, cases, profile=args.profile, cases_dir=cases_dir)
    try:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RunnerError(E_REPORT_WRITE, f"The report could not be written to {args.report}: "
                                          f"{exc}.") from exc
    print(human_summary(report, args.report))
    return VERDICT_EXIT[report["verdict"]]


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"kcs {__version__}")
        return 0
    if args.command is None:
        parser.print_usage(sys.stderr)
        return 2
    try:
        return args.handler(args)
    except RunnerError as err:
        print(f"kcs: {err}", file=sys.stderr)
        if isinstance(err, HelloRefused):
            for problem in err.problems:
                print(f"  - {problem}", file=sys.stderr)
        return err.exit_code
