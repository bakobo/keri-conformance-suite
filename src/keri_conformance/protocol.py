"""The adapter protocol's version, in one place.

docs/adapter-protocol.md is the specification. The runner accepts the current protocol version and
the one before it, so that adapters maintained outside this repository have a full major cycle to
catch up (docs/design.md, Versioning).
"""

PROTOCOL_VERSION = 1

SUPPORTED_PROTOCOLS = frozenset(v for v in (PROTOCOL_VERSION, PROTOCOL_VERSION - 1) if v >= 1)
