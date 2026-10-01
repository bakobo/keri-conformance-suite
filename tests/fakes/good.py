"""A correct fake adapter, driven by a table.

Usage: good.py [--table FILE] [--hello FILE] [--late-stderr] [--env-dump FILE]

The table is a JSON list of {"match": {...}, "result": {...}} or {"match": {...}, "error": {...}}
entries. A request matches an entry when every key in "match" equals the request's value for that
key. The first matching entry answers; a request no entry matches gets a harness error. Without
--table the built-in table below is used. --hello replaces the hello result; --late-stderr writes
to stderr 0.1 s after each response; --env-dump writes the adapter's environment to a file so
tests can see what the runner passed through.
"""

import json
import os
import sys
import time

HELLO = {
    "protocol": 1,
    "adapter": {"name": "fake-adapter", "version": "0.0.1"},
    "implementation": {"name": "fake-impl", "version": "1.0.0", "commit": "0123abc"},
    "operations": ["cesr.parse", "cesr.encode", "keri.process", "keri.emit"],
    "features": ["cesr.genus-2.00", "kel.basic", "crypto.ed25519", "keri.escrow"],
    "composes": ["keri.escrow"],
}

TABLE = [
    {"match": {"op": "cesr.parse", "stream": "2d4b"}, "result": {"reject": {"class": "truncated"}}},
    {"match": {"op": "cesr.parse"}, "result": {"items": [
        {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 0, "group_end": 4},
    ]}},
    {"match": {"op": "cesr.encode"}, "result": {"encoded": "10"}},
    {"match": {"op": "keri.process"}, "result": {
        "dispositions": [{"initial": "accepted", "final": "accepted"}],
        "key_states": {"EAbc": {
            "sn": 0, "said": "EAbc", "keys": ["DAbc"], "kt": "1", "ndigs": ["EGhi"], "nt": "1",
            "wits": [], "bt": "0", "delegator": None,
        }},
    }},
    {"match": {"op": "keri.emit"}, "result": {"stream": "7b7d"}},
]


def option(name):
    if name in sys.argv:
        return sys.argv[sys.argv.index(name) + 1]
    return None


def load(name, default):
    path = option(name)
    if path is None:
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def answer(request, table):
    if request.get("op") == "hello":
        return {"id": request["id"], "result": HELLO_RESULT}
    for entry in table:
        if all(request.get(k) == v for k, v in entry["match"].items()):
            body = {k: v for k, v in entry.items() if k != "match"}
            return {"id": request["id"], **body}
    return {"id": request["id"], "error": {"kind": "harness", "message": "unknown op"}}


HELLO_RESULT = load("--hello", HELLO)


def main():
    table = load("--table", TABLE)
    dump = option("--env-dump")
    if dump:
        with open(dump, "w", encoding="utf-8") as f:
            json.dump(dict(os.environ), f)
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except ValueError:
            print(json.dumps({"id": None, "error": {"kind": "harness", "message": "bad json"}}),
                  flush=True)
            continue
        print("handling", request.get("op"), file=sys.stderr, flush=True)
        print(json.dumps(answer(request, table)), flush=True)
        if "--late-stderr" in sys.argv:
            time.sleep(0.1)
            print("answered", request.get("op"), file=sys.stderr, flush=True)


main()
