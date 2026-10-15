"""Console entry point: kcs-adapter-heti."""

import sys

from kcs_adapter_heti import protocol


def main():
    out = sys.stdout.buffer
    # Anything else that prints (heti, keripy, their dependencies) goes to stderr, never into the
    # response stream.
    sys.stdout = sys.stderr
    protocol.serve(sys.stdin.buffer, out)
    return 0
