"""A fake adapter that answers hello correctly, then a malformed (non-JSON) line with scripted
output lines, then every JSON request with a well-formed cesr.parse result.

Usage: scripted.py LINES.json, where LINES.json is a list of strings written verbatim, one per
line, in answer to the first non-JSON line; the entry EXIT exits instead.
"""

import json
import sys

HELLO = {
    "protocol": 1,
    "adapter": {"name": "scripted", "version": "0"},
    "implementation": {"name": "scripted", "version": "0", "commit": "0"},
    "operations": ["cesr.parse"],
    "features": [],
}

with open(sys.argv[1], encoding="utf-8") as f:
    SCRIPT = json.load(f)


def send(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        request = json.loads(line)
    except ValueError:
        for scripted in SCRIPT:
            if scripted == "EXIT":
                sys.exit(0)
            send(scripted)
        continue
    if request["op"] == "hello":
        send(json.dumps({"id": request["id"], "result": HELLO}))
    elif request["op"] == "cesr.parse":
        send(json.dumps({"id": request["id"], "result": {"items": []}}))
    else:
        send(json.dumps({"id": request["id"], "error": {"kind": "harness", "message": "op"}}))
