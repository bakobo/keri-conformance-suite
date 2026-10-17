"""Command-line entry point for the conformance runner (`kcs`)."""

import argparse
import json
import math
import sys
from pathlib import Path

from keri_conformance import __version__
from keri_conformance.agree import human_summary as agree_summary
from keri_conformance.agree import run_agreement
from keri_conformance.cases import load_cases
from keri_conformance.check import check_adapter, exit_code, render
from keri_conformance.errors import (
    E_REPORT_WRITE,
    E_REPORT_WRITE_TRANSIENT,
    E_USAGE_INVALID,
    E_USAGE_MISSING,
    EXIT_USAGE,
    HelloRefused,
    RunnerError,
)
from keri_conformance.jsonfile import TRANSIENT_ERRNOS
from keri_conformance.profiles import load_profile
from keri_conformance.run import VERDICT_EXIT, human_summary, run_suite
from keri_conformance.session import AdapterSession, Limits, load_vocabulary
from keri_conformance.suite import read_suite_version

EXIT_CODES = """\
A run whose cases carry only INTEROP assertions (a non-normative profile, such as
keripy-1x-interop) gets an interoperability verdict instead of a conformance one:
interoperable, not-interoperable, incomplete or no-evidence, from its active INTEROP
assertions, with the exit codes below. It is never a conformance claim. A layered profile
(such as sedi-1) runs its prerequisites' cases too, and its verdict is the claim: interoperable
only if every prerequisite is conformant and its own cases are interoperable.

exit codes:
  0  conformant: every MUST assertion in every active case that was run passed; or, for a
     non-normative profile, interoperable: every active INTEROP assertion evaluated passed
  1  not-conformant: at least one MUST assertion in an active case failed; or, for a
     non-normative profile, not-interoperable: an active INTEROP assertion failed
  2  usage error
  3  the adapter's hello was refused: at the start (no case was run), or aborted after a
     restart in which it refused hello or changed it (the report, if --report was given,
     holds the cases completed before that)
  4  runner fault: the adapter could not be started, a case is malformed, the runner is
     running as root or off POSIX, or the report could not be written; also the verdict
     incomplete: no MUST (or, for a non-normative profile, INTEROP) assertion failed, but an
     active one uses a check this runner version cannot evaluate; also a run aborted because
     the adapter's responses passed the 512 MiB budget for retained output (the partial
     report is written as for 3)
  5  no-evidence: no active MUST assertion (for a non-normative profile, no active INTEROP
     assertion) was evaluated, so nothing was shown
"""

AGREE_EXIT_CODES = """\
exit codes:
  0  every cell with an expectation agrees with it (this includes a matrix with none)
  1  at least one verifier's verdict disagrees with what its case implies
  2  usage error
  3  an adapter's hello was refused
  4  runner fault: an adapter could not be started, a case is malformed, or the report
     could not be written
"""

CHECK_EXIT_CODES = """\
exit codes:
  0  every available probe passed
  1  at least one probe failed
  2  usage error
  4  runner fault: the adapter could not be started, or the runner is running as root or
     off POSIX
"""


class _UsageError(Exception):
    """Raised instead of argparse's own exit, so every usage failure carries a code."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse calls this for every bad argument
        raise _UsageError(message)


def _fail(parser: argparse.ArgumentParser, code: str, sentence: str) -> int:
    print(f"{code}: {sentence}", file=sys.stderr)
    parser.print_usage(sys.stderr)
    return EXIT_USAGE


def _positive(kind):
    def parse(text):
        try:
            value = kind(text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{text!r} is not a number") from exc
        if not math.isfinite(value) or value <= 0:
            raise argparse.ArgumentTypeError(f"{text!r} must be a finite number greater than "
                                             "zero")
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
    parser = _Parser(
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
    run.add_argument("--profile", help="run only the cases in this profile, and for a layered "
                                       "profile such as sedi-1 its prerequisites' cases too")
    run.add_argument("--report", help="write the JSON conformance report here (default: no "
                                      "report is written)")
    _adapter_options(run)
    run.set_defaults(handler=_run)
    agree = commands.add_parser("agree", help="verify what each adapter issues and presents "
                                              "with every adapter's acdc.verify",
                                epilog=AGREE_EXIT_CODES,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    agree.add_argument("--adapter", required=True, action="append", type=_named,
                       metavar="NAME=CMD", help="an adapter, named for the matrix, and the "
                                                "command that starts it; give it once per adapter")
    agree.add_argument("--cases", help="directory of cases (default: SUITE/cases)")
    agree.add_argument("--profile", help="draw only on the cases of this profile")
    agree.add_argument("--report", help="write the JSON agreement matrix here (default: no "
                                        "report is written)")
    _adapter_options(agree)
    agree.set_defaults(handler=_agree)
    check = commands.add_parser("check-adapter", help="probe an adapter's protocol behaviour",
                                epilog=CHECK_EXIT_CODES,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    check.add_argument("adapter", metavar="CMD", help="the command that starts the adapter")
    _adapter_options(check)
    check.set_defaults(handler=_check)
    return parser


def _named(text: str) -> tuple[str, str]:
    name, sep, command = text.partition("=")
    if not sep or not name or not command.strip():
        raise argparse.ArgumentTypeError(f"{text!r} is not NAME=CMD")
    return name, command


def _write_report(path: str, report: dict) -> None:
    try:
        Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        code = E_REPORT_WRITE_TRANSIENT if exc.errno in TRANSIENT_ERRNOS else E_REPORT_WRITE
        raise RunnerError(code, f"The report could not be written to {path}: {exc}.") from exc


def _session(args, command) -> AdapterSession:
    vocabulary = load_vocabulary(args.suite)
    limits = Limits(timeout=args.timeout, max_response=args.max_response)
    return AdapterSession(command, vocabulary, limits=limits, pass_env=args.pass_env)


def _run(args) -> int:
    suite_version = read_suite_version(args.suite)
    cases_dir = args.cases or str(Path(args.suite) / "cases")
    profile = None if args.profile is None else load_profile(args.suite, args.profile)
    cases = load_cases(cases_dir)
    with _session(args, args.adapter) as session:
        session.open()
        report = run_suite(session, cases, profile=profile, cases_dir=cases_dir,
                           suite_version=suite_version)
    if args.report:
        _write_report(args.report, report)
    print(human_summary(report, args.report))
    aborted = report["aborted"]
    if aborted:
        print(f"kcs: {aborted['code']}: {aborted['reason']}", file=sys.stderr)
        for problem in aborted["problems"]:
            print(f"  - {problem}", file=sys.stderr)
        return aborted["exit_code"]
    return VERDICT_EXIT[report["verdict"]]


def _agree(args) -> int:
    adapters = dict(args.adapter)
    if len(adapters) != len(args.adapter):
        raise RunnerError(E_USAGE_INVALID, "Two adapters share a name, so the matrix could not "
                                           "tell their cells apart; give each --adapter its own "
                                           "NAME.", EXIT_USAGE)
    cases_dir = args.cases or str(Path(args.suite) / "cases")
    cases = load_cases(cases_dir)
    if args.profile is not None:
        members = load_profile(args.suite, args.profile).members
        cases = [c for c in cases if c["profile"] in members]
    report = run_agreement(lambda command: _session(args, command), adapters, cases,
                           read_suite_version(args.suite))
    if args.report:
        _write_report(args.report, report)
    print(agree_summary(report))
    return 1 if report["summary"]["disagree"] else 0


def _check(args) -> int:
    with _session(args, args.adapter) as session:
        results = check_adapter(session)
    print(render(results))
    return exit_code(results)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        return _fail(parser, E_USAGE_INVALID,
                     f"The command line could not be understood ({exc}). Retrying the same "
                     "command will not help; correct the arguments.")
    if args.version:
        print(f"kcs {__version__}")
        return 0
    if args.command is None:
        return _fail(parser, E_USAGE_MISSING,
                     "No command was given. Pass --version, or a command such as run or "
                     "check-adapter; see the usage line below.")
    try:
        return args.handler(args)
    except RunnerError as err:
        print(f"kcs: {err}", file=sys.stderr)
        if isinstance(err, HelloRefused):
            for problem in err.problems:
                print(f"  - {problem}", file=sys.stderr)
        return err.exit_code
