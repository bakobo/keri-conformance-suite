"""Profiles as the runner reads them, and the claim a layered profile makes (docs/design.md, Targets
and profiles; this.i 47yreej2).

A profile is `profiles/<name>.json` under the suite root. Most profiles are a flat list of cases.
A layered profile, such as sedi-1, also names prerequisite profiles, a version, the operations and
features an adapter must declare to claim it, and the choices it makes where the specifications
are silent. Its claim is computed over its own cases and every prerequisite's, run in one session,
so a prerequisite passed in some other run never counts.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from keri_conformance.errors import (
    E_PROFILE_FORMAT,
    E_PROFILE_READ_TRANSIENT,
    E_PROFILE_UNKNOWN,
    EXIT_USAGE,
    RunnerError,
)
from keri_conformance.jsonfile import JsonFileError, read_json
from keri_conformance.shapes import array, obj, string

MAX_PROFILE_BYTES = 1024 * 1024
PROFILE_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")  # always applied with fullmatch
NAME = string(f"^{PROFILE_NAME.pattern}$")
TOKEN = string(min_length=1)


def _unread(value, path):
    """A field the generator checks and the runner only carries."""


# The fields the runner reads from a layered profile. The generated file carries more (its basis,
# pins, choices and maxima), which the generator checks and the runner does not judge.
LAYERED = obj(
    {"name": NAME, "version": TOKEN, "prerequisites": array(NAME, min_items=1),
     "requires": obj({"operations": array(TOKEN), "features": array(TOKEN)}),
     "cases": array(TOKEN)},
    {key: _unread for key in ("about", "normative", "status", "basis", "pins", "choices",
                              "maxima")},
)


@dataclass(frozen=True)
class Profile:
    name: str
    version: str | None = None
    prerequisites: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()
    features: tuple[str, ...] = ()
    # For a layered profile: each member's case ids, from its profile file. A layered run must
    # send exactly these, so a claim cannot rest on cases other than the ones the profile names.
    manifests: dict[str, tuple[str, ...]] = field(default_factory=dict, compare=False)

    @property
    def layered(self) -> bool:
        return bool(self.prerequisites)

    @property
    def members(self) -> tuple[str, ...]:
        """Every profile whose cases a run of this one sends: its own, then its prerequisites'."""
        return (self.name, *self.prerequisites)


def _read(suite, name: str) -> dict:
    path = Path(suite) / "profiles" / f"{name}.json"
    try:
        doc = read_json(path, MAX_PROFILE_BYTES)
    except JsonFileError as exc:
        if exc.kind == "missing":
            raise RunnerError(E_PROFILE_UNKNOWN,
                              f"There is no profile named {name}: {path} does not exist. A run "
                              "of a profile the suite does not define would show nothing, so it "
                              "is refused rather than reported as no-evidence.",
                              EXIT_USAGE) from exc
        raise RunnerError(E_PROFILE_READ_TRANSIENT if exc.transient else E_PROFILE_FORMAT,
                          f"The profile file {path} {exc.sentence}.") from exc
    if not isinstance(doc, dict) or doc.get("name") != name:
        raise RunnerError(E_PROFILE_FORMAT,
                          f"The profile file {path} must be an object whose \"name\" is {name}.")
    return doc


def load_profile(suite, name: str) -> Profile:
    """The profile `name` under the suite root, or a coded refusal. A prerequisite must itself be
    a flat profile: layers do not nest."""
    if not isinstance(name, str) or not PROFILE_NAME.fullmatch(name):
        raise RunnerError(E_PROFILE_UNKNOWN,
                          f"{json.dumps(name)} is not a profile name; names are lowercase "
                          "letters, digits, dots and hyphens, such as keri-1.0.", EXIT_USAGE)
    doc = _read(suite, name)
    if "prerequisites" not in doc:
        return Profile(name)
    problem = LAYERED(doc, "")
    if problem:
        raise RunnerError(E_PROFILE_FORMAT, f"The layered profile {name} is malformed: {problem}.")
    manifests = {name: tuple(doc["cases"])}
    for prerequisite in doc["prerequisites"]:
        flat = _read(suite, prerequisite) if prerequisite != name else doc
        if "prerequisites" in flat:
            raise RunnerError(E_PROFILE_FORMAT,
                              f"The layered profile {name} names {prerequisite} as a "
                              "prerequisite, which is itself layered; layers do not nest.")
        problem = array(TOKEN)(flat.get("cases"), f"{prerequisite}.cases")
        if problem:
            raise RunnerError(E_PROFILE_FORMAT, f"The prerequisite profile {prerequisite} of "
                                                f"{name} is malformed: {problem}.")
        manifests[prerequisite] = tuple(flat["cases"])
    return Profile(name, doc["version"], tuple(doc["prerequisites"]),
                   tuple(doc["requires"]["operations"]), tuple(doc["requires"]["features"]),
                   manifests)


def manifest_problem(profile: Profile, case_ids: dict[str, set[str]]) -> str | None:
    """None if, for every member of a layered profile, the cases that claim it are exactly the
    ones its profile file lists; otherwise what differs. ``case_ids`` maps a profile name to the
    ids of the cases that name it."""
    for member, listed in profile.manifests.items():
        have, want = case_ids.get(member, set()), set(listed)
        if have != want:
            parts = [f"missing {', '.join(sorted(want - have))}" if want - have else "",
                     f"not listed {', '.join(sorted(have - want))}" if have - want else ""]
            return (f"the cases for {member} are not the ones its profile file lists ("
                    + "; ".join(p for p in parts if p) + ")")
    return None


def claim_verdict(own: str, prerequisites: dict[str, str], missing: bool) -> str:
    """A layered profile's claim, taking definite failures first (this.i 47yreej2, 3g4le6js):
    not-interoperable if a prerequisite is not conformant, a requirement is not declared, or the
    profile's own INTEROP verdict is not-interoperable; otherwise incomplete unless every
    prerequisite is conformant and the profile's own verdict is interoperable."""
    if missing or own == "not-interoperable" or "not-conformant" in prerequisites.values():
        return "not-interoperable"
    if own != "interoperable" or any(v != "conformant" for v in prerequisites.values()):
        return "incomplete"
    return "interoperable"
