"""Errors the runner itself raises, and its exit codes.

Every code follows the Bakobo error-code grammar, ``<e|w>.<descriptor>[.<sub>].<r|f>``, where the
trailing ``f`` means retrying the same thing will not help. An adapter misbehaving on a case is not
one of these: that is a case failure, recorded in the conformance report. These are the conditions
under which the runner cannot produce a report at all.
"""

EXIT_CONFORMANT = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_REFUSED = 3
EXIT_FAULT = 4

E_USAGE_MISSING = "e.usage.command.missing.f"
E_USAGE_INVALID = "e.usage.args.invalid.f"
E_ADAPTER_START = "e.env.adapter.start.f"
E_ADAPTER_HELLO = "e.env.adapter.hello.f"
E_ADAPTER_HELLO_CHANGED = "e.env.adapter.hello.changed.f"
E_ROOT = "e.rule.root.f"
E_VOCABULARY = "e.self.config.vocabulary.f"
E_CASES_MISSING = "e.input.missing.cases.f"
E_CASE_FORMAT = "e.input.format.case.f"
E_REPORT_WRITE = "e.env.filesystem.report.r"
E_CHECK_NOT_IMPLEMENTED = "e.feature.unsupported.check.f"
E_EVALUATION_INCOMPLETE = "e.feature.unsupported.evaluation.f"


class RunnerError(Exception):
    """A condition that stops the runner, with a stable code and a full-sentence message."""

    def __init__(self, code: str, message: str, exit_code: int = EXIT_FAULT):
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class HelloRefused(RunnerError):
    """The adapter's hello was missing, malformed or outside the vocabulary; no case was run."""

    def __init__(self, code: str, message: str, problems: list[str]):
        super().__init__(code, message, EXIT_REFUSED)
        self.problems = problems
