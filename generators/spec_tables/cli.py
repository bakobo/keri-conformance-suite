"""Regenerate every case under cases/ and the profiles that list them, from scenarios/.

    scripts/regenerate            write the generated files into the repository
    scripts/regenerate --out DIR  write them under DIR instead
    scripts/regenerate --check    generate into a temporary directory and compare, byte for byte,
                                  with what is committed; exit 1 and list every difference

scripts/regenerate is a one-line entry point to main() here, so the coverage gate measures this
logic. Uses only the Python standard library, so CI can run it with any Python 3.12 or later. The
pinned CESR specification text is read from its cache (see spec_source.py) and fetched there first
if the cache is empty.

Exit status: 0 success; 1 --check found differences; 2 the specification text is unavailable;
3 a generator error (a malformed scenario, a bad case id, unreadable code tables). Errors 2 and 3
print a coded message on standard error.
"""

import argparse
import pathlib
import sys
import tempfile

from . import regenerate, spec_source
from .errors import GeneratorError

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="compare instead of writing")
    group.add_argument("--out", type=pathlib.Path, help="write under this directory")
    args = parser.parse_args(argv)

    try:
        files = regenerate.generate(ROOT)
    except spec_source.SpecUnavailable as e:
        print(str(e), file=sys.stderr)
        return 2
    except GeneratorError as e:
        print(str(e), file=sys.stderr)
        return 3
    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            regenerate.write(pathlib.Path(tmp), files)
            diffs = regenerate.differences(
                regenerate.committed(pathlib.Path(tmp)), regenerate.committed(ROOT)
            )
        if diffs:
            print("Generated cases differ from the committed ones:")
            for line in diffs:
                print(f"  {line}")
            print("Run scripts/regenerate and commit the result; never edit a case by hand.")
            return 1
        print(f"{len(files)} generated files match the committed ones.")
        return 0
    regenerate.write(args.out or ROOT, files)
    print(f"Wrote {len(files)} files under {args.out or ROOT}.")
    return 0

