"""The three ways an operation can fail, and the one door through which keripy is called.

- Rejection: keripy refused the stream. Reported as a cesr.parse rejection result whose class is
  keripy's exception class. Never an error response.
- Unsupported: keripy (or this adapter) cannot perform the operation for this input. Reported as
  an `unsupported` error response.
- AdapterBug, or any exception raised outside `keri()`: the adapter itself is wrong. Reported as a
  `harness` error response.
"""


class Rejection(Exception):
    def __init__(self, klass, message):
        super().__init__(message)
        self.klass = klass


class Unsupported(Exception):
    pass


class AdapterBug(Exception):
    pass


def keri(fn, *args, **kwargs):
    """Call into keripy. Any exception keripy raises becomes a Rejection carrying its class name;
    an AdapterBug raised by adapter code running inside the call passes through unchanged."""
    try:
        return fn(*args, **kwargs)
    except (AdapterBug, Rejection, Unsupported):
        raise
    except Exception as exc:
        raise Rejection(type(exc).__name__, str(exc)) from exc
