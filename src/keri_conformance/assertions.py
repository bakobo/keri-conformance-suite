"""Assertion evaluation: pure functions from (assertion, adapter result) to an outcome.

The adapter's result has already been checked for plausible shape by the session; the checks here
still never assume a field is present or well-typed, because a wrong answer must be a failure and
never an exception. Equality is type-strict throughout, so `1`, `1.0` and `true` are all different.
"""

import base64
import json
import re
from dataclasses import dataclass
from fractions import Fraction

from keri_conformance import issued
from keri_conformance.errors import E_CHECK_NOT_IMPLEMENTED

# The schemas' threshold patterns, matched with re.search as Python's jsonschema matches them.
NUMERIC = re.compile(r"^(0x)?[0-9a-fA-F]{1,64}$")
FRACTION = re.compile(r"^[0-9]{1,64}(/(?=[0-9]{1,64}$)[0-9]*[1-9][0-9]*)?$")
KEY_STATE_FIELDS = ("sn", "said", "keys", "kt", "ndigs", "nt", "wits", "bt", "delegator")
CRYPTO_CHECKS = ("emitted_body", "signatures_verify", "attachments_equivalent")


@dataclass(frozen=True)
class Evaluation:
    """`outcome` is pass, fail, not-applicable (a conditional assertion whose condition does not
    hold) or not-implemented; `actual` is what the adapter reported."""

    outcome: str
    actual: object
    detail: str | None = None


def strict_equal(a, b) -> bool:
    """Equality that also requires equal JSON types at every level."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b, strict=True))
    return a == b


def _numeric(value):
    if isinstance(value, str) and NUMERIC.fullmatch(value):
        return ("numeric", int(value.removeprefix("0x"), 16))
    return None


def _fraction(value):
    if not (isinstance(value, str) and FRACTION.fullmatch(value)):
        return None
    try:
        return str(Fraction(value))
    except (ValueError, ZeroDivisionError, OverflowError):
        return None  # FRACTION admits neither, but a conversion failure must never escape


def normalize_threshold(value):
    """A canonical, comparable form of a threshold, or None if it is malformed.

    A numeric threshold is a hex integer string with an optional 0x prefix. A weighted threshold
    is a list of fraction strings (one clause) or a list of such lists (several clauses); each
    fraction becomes `n/d` in lowest terms, or `n` when the denominator is 1. The two kinds never
    compare equal.
    """
    if isinstance(value, str):
        return _numeric(value)
    if not isinstance(value, list) or not value:
        return None
    if all(isinstance(v, str) for v in value):
        clauses = [value]
    elif all(isinstance(v, list) for v in value):
        clauses = value
    else:
        return None
    normalized = []
    for clause in clauses:
        fractions = tuple(_fraction(v) for v in clause)
        if not clause or None in fractions:
            return None
        normalized.append(fractions)
    return ("weighted", tuple(normalized))


def _fail(actual, detail):
    return Evaluation("fail", actual, detail)


def _decoded(assertion, result):
    if "items" not in result:
        return _fail(result, "The adapter did not report decoded items.")
    items = result["items"]
    if strict_equal(items, assertion["expected"]):
        return Evaluation("pass", items)
    return _fail(items, "The decoded items differ from the expected items.")


def _rejected(assertion, result):
    if "reject" in result:
        return Evaluation("pass", result)
    if "accepted" in result:
        return _fail(result, f"The implementation accepted the stream, consuming "
                             f"{result['accepted'].get('consumed')} bytes of it, where it must "
                             "have rejected it.")
    return _fail(result, "The adapter did not reject the stream.")


def _encoded(assertion, result):
    encoded = result.get("encoded")
    if strict_equal(encoded, assertion["expected"]):
        return Evaluation("pass", encoded)
    return _fail(encoded, "The encoding differs from the expected encoding.")


def _reading(result, message):
    """The adapter's entry for one message, or None if it reported none."""
    dispositions = result.get("dispositions")
    if not isinstance(dispositions, list) or message >= len(dispositions):
        return None
    return dispositions[message]


def _disposition(assertion, result):
    message, phase, expected = assertion["message"], assertion["phase"], assertion["expected"]
    entry = _reading(result, message)
    if entry is None:
        return _fail(None, f"The adapter reported no disposition for message {message}.")
    actual = entry.get(phase)
    if phase == "final" and expected != "seen" and entry.get("initial") == "seen":
        # "Once an event has been first seen, it is always seen and can't be unseen" (KERI spec
        # line 1788), so a message seen on arrival was accepted, whatever is reported later.
        return _fail(actual, f"Message {message} was seen on arrival, and a seen message is always "
                             f"seen, so its final reading cannot be {expected}.")
    holds = actual != "seen" if expected == "not-seen" else actual == expected
    if holds:
        return Evaluation("pass", actual)
    return _fail(actual, f"Message {message}'s {phase} reading is {actual}, not {expected}.")


def _trunk(assertion, result):
    message, expected = assertion["message"], assertion["expected"]
    entry = _reading(result, message)
    if entry is None:
        return _fail(None, f"The adapter reported no disposition for message {message}.")
    actual = entry.get("trunk")
    if strict_equal(actual, expected):
        return Evaluation("pass", actual)
    def where(on):
        return "on the trunk" if on is True else "off the trunk"

    return _fail(actual, f"Message {message} is {where(actual)} at the end, where it should be "
                         f"{where(expected)}.")


def _key_state(assertion, result):
    aid, expected, condition = assertion["aid"], assertion["expected"], assertion["if_seen"]
    entry = _reading(result, condition)
    if entry is None:
        return _fail(None, f"The adapter reported no disposition for message {condition}, on "
                           "whose acceptance this key-state assertion is conditioned.")
    # A message seen on arrival stays seen (line 1788), so reporting it unseen later does not
    # take the key state out of the assertion's reach.
    if entry.get("final") != "seen" and entry.get("initial") != "seen":
        return Evaluation("not-applicable", entry.get("final"),
                          f"The assertion applies only if message {condition} was seen, and its "
                          f"readings are {entry.get('initial')} and {entry.get('final')}.")
    states = result.get("key_states")
    if not isinstance(states, dict) or aid not in states:
        return _fail(None, f"The adapter reported no key state for {aid}.")
    actual = states[aid]
    wrong = []
    for field in KEY_STATE_FIELDS:
        if field not in actual:
            wrong.append(field)
        elif field in ("kt", "nt"):
            ours = normalize_threshold(expected[field])
            if ours is None or ours != normalize_threshold(actual[field]):
                wrong.append(field)
        elif field == "bt":
            ours = _numeric(expected[field])
            if ours is None or ours != _numeric(actual[field]):
                wrong.append(field)
        elif not strict_equal(actual[field], expected[field]):
            wrong.append(field)
    if wrong:
        return _fail(actual, f"The key state of {aid} differs in {', '.join(wrong)}.")
    return Evaluation("pass", actual)


REGISTRY_FIELDS = ("rd", "n", "d", "td", "ts")


def _verdict(assertion, result):
    actual, expected = result.get("verdict"), assertion["expected"]
    # not-valid takes either refinement; an exact refinement, which only an INTEROP assertion of
    # a layered profile grades (this.i 8fh68wt6), takes only itself.
    holds = actual in ("invalid", "incomplete") if expected == "not-valid" else actual == expected
    if holds:
        return Evaluation("pass", actual)
    return _fail(actual, f"The adapter's verdict is {actual}, which is not "
                         f"{assertion['expected']}.")


def _registry(result):
    registry = result.get("registry")
    return registry if isinstance(registry, dict) else None


def _registry_reported(assertion, result):
    actual = _registry(result) is not None
    if actual is assertion["expected"]:
        return Evaluation("pass", actual)
    return _fail(actual, "The adapter reported the registry's head, where it should have "
                         "reported none." if actual else
                         "The adapter reported no registry, where it should have reported "
                         "the registry's head.")


def _registry_state(assertion, result):
    registry = _registry(result)
    if registry is None:
        if result.get("verdict") == "valid":
            # A valid verdict commits the adapter to the registry it relied on, so it cannot hide
            # a wrongly advanced head by not reporting it (docs/design.md, Registry state).
            return _fail(None, "The adapter answered valid but reported no registry; a valid "
                               "verdict for an ACDC that names a registry must report its head.")
        return Evaluation("not-applicable", None,
                          "The assertion applies only when the adapter reports a registry, and "
                          f"it reported none with the verdict {result.get('verdict')}.")
    expected = assertion["expected"]
    wrong = [f for f in REGISTRY_FIELDS
             if f not in registry or not strict_equal(registry[f], expected[f])]
    if wrong:
        return _fail(registry, f"The registry's head differs in {', '.join(wrong)}.")
    return Evaluation("pass", registry)


def _edge(assertion, result):
    """The adapter's report of the assertion's edge, or None if it reported none."""
    edges = result.get("edges")
    for edge in edges if isinstance(edges, list) else ():
        if (isinstance(edge, dict) and edge.get("near") == assertion["near"]
                and edge.get("path") == assertion["path"]):
            return edge
    return None


def _edge_name(assertion):
    return f"the edge {assertion['path']} of {assertion['near']}"


def _edge_reported(assertion, result):
    edge = _edge(assertion, result)
    if edge is not None:
        return Evaluation("pass", edge)
    return _fail(None, f"The adapter did not report {_edge_name(assertion)}.")


def _edge_valid(assertion, result):
    edge = _edge(assertion, result)
    expected = assertion["expected"]
    if edge is None:
        verdict = result.get("verdict")
        if expected is False and assertion["level"] == "MUST":
            # A valid verdict commits the adapter to the failing edge: it must show it found the
            # edge not valid (docs/design.md, Edges).
            if verdict == "valid":
                return _fail(None, f"The adapter answered valid without reporting "
                                   f"{_edge_name(assertion)}, which is not valid.")
            return Evaluation("pass", None, f"The adapter did not report "
                                            f"{_edge_name(assertion)}, and its verdict is "
                                            f"{verdict}, not valid.")
        return Evaluation("not-applicable", None, f"The assertion applies only when the adapter "
                                                  f"reports {_edge_name(assertion)}.")
    actual = edge.get("valid")
    if strict_equal(actual, expected):
        return Evaluation("pass", actual)
    return _fail(actual, f"The adapter found {_edge_name(assertion)} "
                         f"{'valid' if actual is True else 'not valid'}, where it is "
                         f"{'valid' if expected else 'not valid'}.")


def _exn_verdict(assertion, result):
    message, expected = assertion["message"], assertion["expected"]
    verdicts = result.get("verdicts")
    if not isinstance(verdicts, list) or message >= len(verdicts):
        return _fail(None, f"The adapter reported no verdict for message {message}.")
    entry = verdicts[message]
    on_delivery, final = entry.get("on_delivery"), entry.get("verdict")
    if expected == "rejected":
        # A message that must be dropped is read twice, so accepting it on arrival and retracting
        # it later still fails (docs/design.md, IPEX).
        holds = on_delivery == "rejected" and final == "rejected"
    else:
        holds = final == "accepted"
    if holds:
        return Evaluation("pass", entry)
    return _fail(entry, f"Message {message} was {on_delivery} on delivery and {final} at the "
                        f"end, where it should have been {expected}"
                        f"{' both times' if expected == 'rejected' else ' at the end'}.")


def _issued(assertion, result, case_input):
    """What was issued verifies and is what the case asked for (this.i 2u2ps8mt)."""
    if "refused" in result:
        return _fail(result, "The issuer refused to issue what it must issue.")
    try:
        problems = issued.grade(case_input, result)
    except (issued.Unread, TypeError, ValueError, AttributeError, KeyError,
            RecursionError) as exc:
        # The verifier refuses what it cannot read check by check; this is the backstop for an
        # adapter's answer it did not foresee, which fails the check rather than the run.
        return _fail(None, f"What was issued cannot be graded: {type(exc).__name__}: {exc}.")
    if problems:
        return _fail({"problems": problems}, "What was issued does not verify as asked: "
                     + "; ".join(problems) + ".")
    return Evaluation("pass", {"credentials": sorted(result["credentials"])})


def _issue_refused(assertion, result):
    if "refused" in result:
        return Evaluation("pass", result)
    return _fail(result, "The issuer issued what it must refuse.")


# The CESR text domain.
TEXT_DOMAIN = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
# What a presentation may attach: seal source couples pointing to its issuer's commitment, each
# a sequence number (0A) and a Blake3-256 digest (E), at -S (seal-couple-code).
COUPLES = re.compile(r"(0A[A-Za-z0-9_-]{22}E[A-Za-z0-9_-]{43})+")
COUPLE_SIZE = 68
# JSON's two-character escapes, by the byte after the backslash.
SIMPLE_ESCAPES = {ord('"'): b'"', ord("\\"): b"\\", ord("/"): b"/", ord("b"): b"\b",
                  ord("f"): b"\f", ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t"}
HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


def _presented_stream(result) -> bytes:
    """The presentation's bytes, or Unread if there is none, it is longer than a stream may be,
    or it is not genus-pinned hex."""
    text = result["presented"]["stream"]
    if len(text) > 2 * issued.MAX_STREAM:
        raise issued.Unread(f"the presentation is longer than {issued.MAX_STREAM} bytes")
    stream = bytes.fromhex(text)
    if not stream.startswith(issued.GENUS):
        raise issued.Unread("the presentation does not begin with the genus/version code")
    return stream


def _presented(assertion, result):
    """The body is the one the disclosure asks for, byte for byte, and what follows it is
    nothing or an attachments group of seal source couples (this.i 37ehqmh4)."""
    if "presented" not in result:
        return _fail(result, "The holder refused to present what it must present.")
    try:
        _, raw, rest = issued.frame(_presented_stream(result), b"ACDC")
        if rest and not rest.startswith((b"-C", b"--C")):
            raise issued.Unread("what follows the body is not an attachments group")
        if not set(rest) <= TEXT_DOMAIN:
            raise issued.Unread("the attachments are not in the CESR text domain")
        for code, contents in issued.groups(rest):
            if code != "-S" or not COUPLES.fullmatch(contents):
                raise issued.Unread(f"an attachment group {code} is not seal source couples")
            for i in range(0, len(contents), COUPLE_SIZE):
                # raw_of refuses a primitive that is not canonically encoded.
                issued.raw_of(contents[i:i + 24], "0A", 16)
                issued.raw_of(contents[i + 24:i + COUPLE_SIZE], "E", 32)
    except (issued.Unread, TypeError, ValueError, KeyError, AttributeError,
            RecursionError) as exc:
        return _fail(None, f"The presentation cannot be read: {type(exc).__name__}: {exc}.")
    if raw != bytes.fromhex(assertion["expected"]["body"]):
        return _fail({"body": raw.hex()}, "The presented body is not the one the disclosure "
                                          "asks for.")
    return Evaluation("pass", {"body": raw.hex()})


def _encodings(secret: str) -> list[bytes]:
    """The forms in which a secret may leak: raw, hex, JSON-escaped, and the part of its Base64
    and Base64url encodings that does not depend on where it starts in a stream."""
    data = secret.encode("utf-8")
    forms = [data, data.hex().encode(), json.dumps(secret)[1:-1].encode()]
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        for lead in range(3):
            text = encode(b"\0" * lead + data)
            core = text[-(-4 * lead // 3):(8 * (lead + len(data))) // 6]
            if len(core) >= 4:
                forms.append(core)
    return forms


def _json_unescape(text: bytes) -> bytes:
    """``text`` with every JSON string escape decoded, in one pass: a run of \\uXXXX escapes as
    the characters it stands for (a surrogate pair joined, an unpaired surrogate kept), and the
    two-character escapes. Anything else stands as it is."""
    out, units, i, n = bytearray(), [], 0, len(text)

    def flush():
        if units:
            chars = "".join(chr(u) for u in units)
            out.extend(chars.encode("utf-16-le", "surrogatepass")
                       .decode("utf-16-le", "surrogatepass").encode("utf-8", "surrogatepass"))
            units.clear()

    while i < n:
        if text[i] == 0x5C and i + 1 < n:
            after = text[i + 1]
            if after == ord("u") and i + 6 <= n and all(c in HEX_DIGITS for c in text[i + 2:i + 6]):
                units.append(int(text[i + 2:i + 6], 16))
                i += 6
                continue
            if after in SIMPLE_ESCAPES:
                flush()
                out.extend(SIMPLE_ESCAPES[after])
                i += 2
                continue
        flush()
        out.append(text[i])
        i += 1
    flush()
    return bytes(out)


def _strings(value) -> list[bytes]:
    """Every string in a parsed response, keys included, as UTF-8 (an unpaired surrogate kept)."""
    out, stack = [], [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item.encode("utf-8", "surrogatepass"))
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return out


def _secrets_absent(assertion, result):
    """None of the secrets the disclosure hides is in the response, in any form _encodings
    enumerates."""
    texts = _strings(result)
    if "presented" in result:
        try:
            texts.append(bytes.fromhex(result["presented"]["stream"]))
        except (TypeError, ValueError, KeyError, AttributeError):
            pass
    # Each text as it stands and with its JSON escapes decoded, each also in lower case so that
    # hex in any case matches the lowercase hex form.
    haystacks = []
    for text in texts:
        unescaped = _json_unescape(text)
        haystacks += [text, unescaped, text.lower(), unescaped.lower()]
    leaked = [n for n, secret in enumerate(assertion["expected"])
              if any(form in hay for form in _encodings(secret) for hay in haystacks)]
    if leaked:
        return _fail({"leaked": leaked}, f"The response carries secret(s) {leaked} that the "
                                         f"disclosure hides.")
    return Evaluation("pass", None)


def _present_refused(assertion, result):
    if "refused" in result:
        return Evaluation("pass", result)
    return _fail(result, "The holder presented what it must refuse.")


# Checks that read the case's own input as well as the result: what was asked for comes only from
# the case.
CHECKS_WITH_INPUT = {"issued": _issued}

CHECKS = {
    "issue_refused": _issue_refused,
    "presented": _presented,
    "secrets_absent": _secrets_absent,
    "present_refused": _present_refused,
    "decoded": _decoded,
    "rejected": _rejected,
    "encoded": _encoded,
    "disposition": _disposition,
    "trunk": _trunk,
    "key_state": _key_state,
    "verdict": _verdict,
    "registry_reported": _registry_reported,
    "registry_state": _registry_state,
    "edge_reported": _edge_reported,
    "edge_valid": _edge_valid,
    "exn_verdict": _exn_verdict,
}


def evaluate(assertion: dict, result: dict, case_input: dict | None = None) -> Evaluation:
    """Evaluate one assertion against the adapter's result for its case, whose input a check
    that needs the case's own keys reads."""
    if assertion["check"] in CHECKS_WITH_INPUT:
        return CHECKS_WITH_INPUT[assertion["check"]](assertion, result, case_input)
    check = CHECKS.get(assertion["check"])
    if check is None:
        return Evaluation("not-implemented", None,
                          f"{E_CHECK_NOT_IMPLEMENTED}: This runner version cannot evaluate a "
                          f"{assertion['check']} assertion, so it is neither passed nor failed.")
    return check(assertion, result)
