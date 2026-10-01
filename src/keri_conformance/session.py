"""The adapter session: one adapter process, contained, and spoken to one request at a time.

The adapter is untrusted code that runs implementation code against hostile input
(docs/design.md, The runner). Everything here therefore bounds what the adapter can do to the
runner: it starts in its own process group with a scrubbed environment and POSIX resource limits,
every response is read with both a size cap and a deadline by a reader that never waits for a
newline that may not come, and any misbehaviour becomes a typed `Failure` after which the whole
process group is killed and a fresh adapter is started for the next request.

This module is POSIX-only: the reader multiplexes pipes with `selectors`, which Windows does not
support for pipes.
"""

import functools
import itertools
import json
import os
import re
import resource
import selectors
import shlex
import signal
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from keri_conformance.errors import (
    E_ADAPTER_HELLO,
    E_ADAPTER_HELLO_CHANGED,
    E_ADAPTER_START,
    E_ROOT,
    E_USAGE_INVALID,
    E_VOCABULARY,
    EXIT_USAGE,
    HelloRefused,
    RunnerError,
)
from keri_conformance.protocol import PROTOCOL_VERSION, SUPPORTED_PROTOCOLS

OPERATIONS = ("cesr.parse", "cesr.encode", "keri.process", "keri.emit")
ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
INITIAL_DISPOSITIONS = ("accepted", "pending", "rejected", "duplicitous")
FINAL_DISPOSITIONS = (*INITIAL_DISPOSITIONS, "superseded")
HELLO_FIELDS = ("protocol", "adapter", "implementation", "operations", "features", "composes")
HEX = re.compile(r"(?:[0-9a-f]{2})*")
CHUNK = 65536
CLIP = 2000


@dataclass(frozen=True)
class Limits:
    """Bounds on one adapter. The defaults are generous; tests set small ones."""

    timeout: float = 60.0
    max_response: int = 16 * 1024 * 1024
    address_space: int = 4 * 1024**3
    cpu_seconds: int = 600
    stderr_tail: int = 64 * 1024
    close_grace: float = 5.0


@dataclass(frozen=True)
class Reply:
    """A well-formed result from the adapter."""

    result: dict


@dataclass(frozen=True)
class Failure:
    """Anything but a well-formed result: timeout, oversize, exited, malformed, error-harness or
    error-unsupported. For a case, every one of these fails every assertion."""

    kind: str
    detail: str


def _clip(text: str) -> str:
    return text if len(text) <= CLIP else text[:CLIP] + "..."


def adapter_argv(command: str | list[str]) -> list[str]:
    """Turn an adapter command into an argv list. A string is split like a shell would split it,
    but no shell is ever run."""
    try:
        argv = shlex.split(command) if isinstance(command, str) else list(command)
    except ValueError as exc:
        raise RunnerError(E_USAGE_INVALID,
                          f"The adapter command could not be split into arguments: {exc}.",
                          EXIT_USAGE) from exc
    if not argv:
        raise RunnerError(E_USAGE_INVALID,
                          'The adapter command is empty; give the program that starts the adapter, '
                          'for example --adapter "python my_adapter.py".', EXIT_USAGE)
    return argv


def scrubbed_env(environ, pass_env) -> dict[str, str]:
    """The adapter's environment: a few harmless names plus those the caller passes through."""
    return {name: environ[name] for name in (*ENV_KEEP, *pass_env) if name in environ}


def apply_limits(res, address_space: int, cpu_seconds: int) -> None:
    """Cap the calling process's address space and CPU time. Runs in the child before exec, so
    it takes the `resource` module as an argument and never asks for more than the hard limit."""

    def capped(which, want):
        hard = res.getrlimit(which)[1]
        return want if hard == res.RLIM_INFINITY else min(want, hard)

    memory = capped(res.RLIMIT_AS, address_space)
    res.setrlimit(res.RLIMIT_AS, (memory, memory))
    cpu_hard = capped(res.RLIMIT_CPU, cpu_seconds + 1)
    res.setrlimit(res.RLIMIT_CPU, (min(cpu_seconds, cpu_hard), cpu_hard))


def load_vocabulary(suite) -> dict[str, bool]:
    """Read `profiles/features.json` under the suite root: feature name -> composable."""
    path = Path(suite) / "profiles" / "features.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RunnerError(E_VOCABULARY,
                          f"The feature vocabulary {path} does not exist; pass --suite with the "
                          "root of a suite checkout.") from exc
    except (OSError, ValueError) as exc:
        raise RunnerError(E_VOCABULARY, f"The feature vocabulary {path} could not be read as "
                                        f"JSON: {exc}.") from exc
    features = doc.get("features") if isinstance(doc, dict) else None
    if not isinstance(features, dict) or not all(
            isinstance(entry, dict) and isinstance(entry.get("composable"), bool)
            for entry in features.values()):
        raise RunnerError(E_VOCABULARY,
                          f"The feature vocabulary {path} must have a \"features\" object whose "
                          "entries each carry a boolean \"composable\".")
    return {name: entry["composable"] for name, entry in features.items()}


def _check_names(result, field, known, what, problems) -> list[str]:
    value = result[field]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        problems.append(f'"{field}" must be a list of strings.')
        return []
    for name in value:
        if name not in known:
            problems.append(f'"{field}" lists "{name}", which is not {what}.')
    return value


def validate_hello(result, vocabulary: dict[str, bool]) -> list[str]:
    """Every problem with a hello result, each naming the field and what was expected."""
    if not isinstance(result, dict):
        return ["The hello result is not a JSON object."]
    problems = []
    for field in HELLO_FIELDS[:-1]:
        if field not in result:
            problems.append(f'"{field}" is missing.')
    for field in result:
        if field not in HELLO_FIELDS:
            problems.append(f'"{field}" is not a field of the hello result.')
    supported = ", ".join(map(str, sorted(SUPPORTED_PROTOCOLS)))
    if "protocol" in result and (type(result["protocol"]) is not int
                                 or result["protocol"] not in SUPPORTED_PROTOCOLS):
        problems.append(f'"protocol" is {json.dumps(result["protocol"])}; this runner supports '
                        f"protocol version {supported}.")
    for field, keys in (("adapter", ("name", "version")),
                        ("implementation", ("name", "version", "commit"))):
        if field in result:
            value = result[field]
            if not isinstance(value, dict):
                problems.append(f'"{field}" must be an object with {", ".join(keys)}.')
                continue
            for key in keys:
                if not isinstance(value.get(key), str):
                    problems.append(f'"{field}.{key}" is missing or not a string.')
    if "operations" in result:
        ops = _check_names(result, "operations", OPERATIONS,
                           f"an operation of protocol version {PROTOCOL_VERSION}", problems)
        if not ops and isinstance(result["operations"], list):
            problems.append('"operations" must list at least one operation.')
    features = []
    if "features" in result:
        features = _check_names(result, "features", vocabulary,
                                "in the feature vocabulary (profiles/features.json)", problems)
    if "composes" in result:
        for name in _check_names(result, "composes", vocabulary,
                                 "in the feature vocabulary (profiles/features.json)", problems):
            if vocabulary.get(name) is False:
                problems.append(f'"composes" lists "{name}", but "{name}" is not composable; only '
                                "features marked composable in profiles/features.json may be "
                                "composed.")
            if name not in features:
                problems.append(f'"composes" lists "{name}", which is not also listed in '
                                '"features"; a composed behaviour is still a declared feature.')
    return problems


def _is_int(value) -> bool:
    return type(value) is int


def _shape_parse(result):
    if set(result) == {"items"}:
        items = result["items"]
        if not isinstance(items, list):
            return '"items" is not a list.'
        for n, item in enumerate(items):
            if not (isinstance(item, dict) and isinstance(item.get("kind"), str)
                    and _is_int(item.get("start")) and _is_int(item.get("end"))):
                return (f'Item {n} is not an object with a string "kind" and integer "start" '
                        'and "end".')
            if item["kind"] == "counter" and not _is_int(item.get("group_end")):
                return f'Item {n} is a counter without an integer "group_end".'
        return None
    if set(result) == {"reject"}:
        reject = result["reject"]
        if isinstance(reject, dict) and isinstance(reject.get("class"), str):
            return None
        return 'The rejection is not an object with a string "class".'
    return 'A cesr.parse result must have exactly one of "items" or "reject".'


def _hex_field(result, field, op):
    value = result.get(field)
    if set(result) == {field} and isinstance(value, str) and HEX.fullmatch(value):
        return None
    return f'A {op} result must be exactly {{"{field}": <lowercase hex string>}}.'


def _shape_process(result):
    if set(result) != {"dispositions", "key_states"}:
        return 'A keri.process result must have exactly "dispositions" and "key_states".'
    dispositions = result["dispositions"]
    if not isinstance(dispositions, list):
        return '"dispositions" is not a list.'
    for n, entry in enumerate(dispositions):
        if not (isinstance(entry, dict) and entry.get("initial") in INITIAL_DISPOSITIONS
                and entry.get("final") in FINAL_DISPOSITIONS):
            return f'Disposition {n} is not an object with a valid "initial" and "final".'
    key_states = result["key_states"]
    if isinstance(key_states, dict) and all(isinstance(v, dict) for v in key_states.values()):
        return None
    return '"key_states" is not an object whose values are key-state objects.'


_SHAPES = {
    "cesr.parse": _shape_parse,
    "cesr.encode": functools.partial(_hex_field, field="encoded", op="cesr.encode"),
    "keri.process": _shape_process,
    "keri.emit": functools.partial(_hex_field, field="stream", op="keri.emit"),
}


def check_result_shape(op: str, result) -> str | None:
    """None if `result` is plausible for `op`, else a sentence saying what is wrong."""
    if not isinstance(result, dict):
        return "The result is not a JSON object."
    check = _SHAPES.get(op)
    return check(result) if check else None


def parse_response(line: bytes, request_id: int, op: str) -> Reply | Failure:
    """Validate one response line against the request it answers."""
    try:
        message = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        return Failure("malformed", _clip(f"The adapter's response is not UTF-8 JSON: {exc}."))
    if not isinstance(message, dict):
        return Failure("malformed", "The adapter's response is not a JSON object.")
    rid = message.get("id")
    if not _is_int(rid) or rid != request_id:
        return Failure("malformed", _clip(f"The adapter's response has id {json.dumps(rid)}, but "
                                          f"the request's id was {request_id}."))
    keys = set(message) - {"id"}
    if keys == {"result"}:
        problem = check_result_shape(op, message["result"])
        if problem:
            return Failure("malformed", f"The adapter's {op} result is malformed. {problem}")
        return Reply(message["result"])
    if keys == {"error"}:
        error = message["error"]
        if not (isinstance(error, dict) and error.get("kind") in ("harness", "unsupported")
                and isinstance(error.get("message"), str)):
            return Failure("malformed", 'The adapter\'s error is not an object with "kind" '
                                        '"harness" or "unsupported" and a string "message".')
        return Failure(f"error-{error['kind']}",
                       _clip(f"The adapter answered with a {error['kind']} error: "
                             f"{error['message']}"))
    return Failure("malformed", 'The adapter\'s response must have "id" and exactly one of '
                                '"result" or "error", and nothing else.')


class AdapterSession:
    """One adapter, restarted with a fresh hello after any failure."""

    def __init__(self, command, vocabulary: dict[str, bool], *, limits: Limits | None = None,
                 pass_env=(), geteuid=None, environ=None, start_attempts: int = 2):
        self.argv = adapter_argv(command)
        self.vocabulary = vocabulary
        self.limits = limits or Limits()
        self.pass_env = tuple(pass_env)
        self._geteuid = geteuid or os.geteuid
        self._environ = os.environ if environ is None else environ
        self._attempts = start_attempts
        self._ids = itertools.count(1)
        self._proc = None
        self._selector = None
        self._buffer = bytearray()
        self._stderr = bytearray()
        self.hello = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @property
    def pid(self):
        return self._proc.pid if self._proc else None

    def next_id(self) -> int:
        return next(self._ids)

    def open(self) -> dict:
        """Start the adapter and validate its hello. Raises RunnerError or HelloRefused."""
        if self._geteuid() == 0:
            raise RunnerError(E_ROOT, "The runner refuses to run as root, because the adapter runs "
                                      "untrusted implementation code with the runner's "
                                      "privileges. Run kcs as an unprivileged user.")
        self.hello = self._start()
        return self.hello

    def ensure_running(self) -> None:
        """Restart the adapter if the last request killed it, and require the same hello."""
        if self._proc is None:
            hello = self._start()
            if hello != self.hello:
                self.kill()
                raise HelloRefused(E_ADAPTER_HELLO_CHANGED,
                                   "The adapter's hello after a restart differs from its first "
                                   "hello, so results before and after the restart would "
                                   "describe different adapters.", ["The hello changed."])

    def request(self, op: str, fields: dict) -> Reply | Failure:
        """Send one request and read its response; restart first if the last one failed."""
        self.ensure_running()
        rid = self.next_id()
        outcome = self._roundtrip({**fields, "id": rid, "op": op}, op, rid)
        if isinstance(outcome, Failure):
            self.kill()
        return outcome

    def take_stderr(self) -> str:
        """The adapter's stderr captured since the last call (its bounded tail)."""
        if self._proc is not None:
            self._drain_stderr()
        text = self._stderr.decode("utf-8", errors="replace")
        self._stderr.clear()
        return text

    def close(self) -> None:
        """Close stdin, give the adapter a moment to exit, then kill its process group."""
        if self._proc is None:
            return
        self._proc.stdin.close()
        with suppress(subprocess.TimeoutExpired):
            self._proc.wait(timeout=self.limits.close_grace)
        self.kill()

    def kill(self) -> None:
        """Kill the adapter's whole process group and release its pipes."""
        proc = self._proc
        if proc is None:
            return
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        self._drain_stderr()
        self._proc = None
        self._selector.close()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
        self._buffer.clear()

    def exchange(self, data: bytes) -> bytes | Failure:
        """Write `data` (possibly empty) and read one response line, within the limits."""
        proc = self._proc
        limits = self.limits
        deadline = time.monotonic() + limits.timeout
        pending = memoryview(data)
        if pending:
            self._selector.register(proc.stdin, selectors.EVENT_WRITE, "in")
        try:
            while True:
                newline = self._buffer.find(b"\n")
                if newline >= 0:
                    line = bytes(self._buffer[:newline])
                    del self._buffer[:newline + 1]
                    if len(line) > limits.max_response:
                        return Failure("oversize", f"The adapter's response line is {len(line)} "
                                                   f"bytes, over the {limits.max_response}-byte "
                                                   "limit.")
                    if pending:
                        return Failure("malformed", "The adapter answered before the runner had "
                                                    "finished writing the request.")
                    return line
                if len(self._buffer) > limits.max_response:
                    return Failure("oversize", f"The adapter wrote more than "
                                               f"{limits.max_response} bytes without ending its "
                                               "response line.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return Failure("timeout", f"The adapter did not answer within "
                                              f"{limits.timeout:g} seconds (timeout).")
                for key, _ in self._selector.select(remaining):
                    if key.data == "in":
                        try:
                            written = os.write(proc.stdin.fileno(), pending[:CHUNK])
                        except BrokenPipeError:
                            return Failure("exited", "The adapter stopped reading its standard "
                                                     "input before the request was written "
                                                     "(exited).")
                        pending = pending[written:]
                        if not pending:
                            self._selector.unregister(proc.stdin)
                    elif key.data == "out":
                        chunk = os.read(proc.stdout.fileno(), CHUNK)
                        if not chunk:
                            return Failure("exited", "The adapter exited or closed its standard "
                                                     "output before answering (exited).")
                        self._buffer += chunk
                    else:
                        chunk = os.read(proc.stderr.fileno(), CHUNK)
                        if chunk:
                            self._keep_stderr(chunk)
                        else:
                            self._selector.unregister(proc.stderr)
        finally:
            if pending:
                self._selector.unregister(proc.stdin)

    # --- internals ------------------------------------------------------------------------------

    def _spawn(self) -> None:
        error = None
        for _ in range(self._attempts):
            try:
                proc = subprocess.Popen(
                    self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=0, start_new_session=True,
                    env=scrubbed_env(self._environ, self.pass_env),
                    # The runner starts no threads, so a preexec_fn is safe here; it is the only
                    # stdlib way to set rlimits in the child before exec.
                    preexec_fn=functools.partial(  # noqa: PLW1509
                        apply_limits, resource, self.limits.address_space,
                        self.limits.cpu_seconds))
            except (OSError, subprocess.SubprocessError) as exc:
                error = exc
                continue
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
            self._selector = selectors.DefaultSelector()
            self._selector.register(proc.stdout, selectors.EVENT_READ, "out")
            self._selector.register(proc.stderr, selectors.EVENT_READ, "err")
            self._proc = proc
            return
        raise RunnerError(E_ADAPTER_START,
                          f"The adapter command {shlex.join(self.argv)} could not be started "
                          f"after {self._attempts} attempts: {error}.")

    def _start(self) -> dict:
        self._spawn()
        outcome = self._roundtrip({"id": 0, "op": "hello", "protocol": PROTOCOL_VERSION},
                                  "hello", 0)
        if isinstance(outcome, Failure):
            self.kill()
            raise HelloRefused(E_ADAPTER_HELLO,
                               f"The adapter did not answer hello with a result ({outcome.kind}). "
                               f"{outcome.detail}", [outcome.detail])
        problems = validate_hello(outcome.result, self.vocabulary)
        if problems:
            self.kill()
            raise HelloRefused(E_ADAPTER_HELLO,
                               "The adapter's hello was refused. " + " ".join(problems), problems)
        return outcome.result

    def _roundtrip(self, message: dict, op: str, rid: int) -> Reply | Failure:
        line = self.exchange(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        if isinstance(line, Failure):
            return line
        return parse_response(line, rid, op)

    def _keep_stderr(self, chunk: bytes) -> None:
        self._stderr += chunk
        excess = len(self._stderr) - self.limits.stderr_tail
        if excess > 0:
            del self._stderr[:excess]

    def _drain_stderr(self) -> None:
        fd = self._proc.stderr.fileno()
        while True:
            try:
                chunk = os.read(fd, CHUNK)
            except BlockingIOError:
                return
            if not chunk:
                return
            self._keep_stderr(chunk)
