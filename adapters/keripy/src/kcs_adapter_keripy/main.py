"""Console entry point: kcs-adapter-keripy."""

import sys

from kcs_adapter_keripy import protocol


def main():
    out = sys.stdout.buffer
    # Anything else that prints (keripy, its dependencies) goes to stderr, never into the
    # response stream.
    sys.stdout = sys.stderr
    protocol.serve(sys.stdin.buffer, out)
    return 0
