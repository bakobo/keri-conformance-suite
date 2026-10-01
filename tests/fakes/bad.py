"""A misbehaving fake adapter. Usage: bad.py MODE [ARG]

Every mode answers hello correctly unless its name starts with "hello-", then misbehaves on the
first request after hello in the way its name says. The modes are the branches of behave()
and main().
"""

import json
import os
import subprocess
import sys
import time

HELLO = {
    "protocol": 1,
    "adapter": {"name": "bad-adapter", "version": "0.0.1"},
    "implementation": {"name": "bad-impl", "version": "1.0.0", "commit": "0123abc"},
    "operations": ["cesr.parse", "cesr.encode", "keri.process", "keri.emit"],
    "features": ["cesr.genus-2.00", "kel.basic", "crypto.ed25519"],
}

MODE = sys.argv[1]
ARG = sys.argv[2] if len(sys.argv) > 2 else None
out = sys.stdout.buffer


def write(data):
    out.write(data)
    out.flush()


def send(obj):
    write(json.dumps(obj).encode() + b"\n")


def hang():
    while True:
        time.sleep(60)


def read_request():
    line = sys.stdin.buffer.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)


def hello():
    request = read_request()
    send({"id": request["id"], "result": HELLO})


def behave(request):
    rid = request["id"]
    if MODE == "crash":
        print("boom: the parser panicked", file=sys.stderr, flush=True)
        sys.exit(3)
    if MODE == "hang":
        hang()
    if MODE == "oversize":
        write(b'{"id": %d, "result": {"encoded": "' % rid + b"a" * int(ARG) + b'"}}\n')
        hang()
    if MODE == "no-newline":
        write(b'{"id": ')
        hang()
    if MODE == "flood":
        while True:
            write(b"a" * 65536)
    if MODE == "wrong-id":
        return send({"id": rid + 1, "result": {"encoded": "10"}})
    if MODE == "bool-id":
        return write(b'{"id": true, "result": {"encoded": "10"}}\n')
    if MODE == "junk":
        return write(b"this is not json\n")
    if MODE == "not-utf8":
        return write(b"\xff\xfe\n")
    if MODE == "not-object":
        return write(b"[1, 2]\n")
    if MODE == "both":
        return send({"id": rid, "result": {}, "error": {"kind": "harness", "message": "x"}})
    if MODE == "neither":
        return send({"id": rid})
    if MODE == "extra-key":
        return send({"id": rid, "result": {"encoded": "10"}, "extra": 1})
    if MODE == "error-harness":
        return send({"id": rid, "error": {"kind": "harness", "message": "glue raised"}})
    if MODE == "error-unsupported":
        return send({"id": rid, "error": {"kind": "unsupported", "message": "cannot"}})
    if MODE == "error-bad-kind":
        return send({"id": rid, "error": {"kind": "oops", "message": "x"}})
    if MODE == "error-not-object":
        return send({"id": rid, "error": "x"})
    if MODE == "memory":
        block = bytearray(int(ARG))
        return send({"id": rid, "result": {"encoded": f"{len(block[:1]):02x}"}})
    if MODE == "cpu":
        while True:
            pass
    if MODE == "grandchild":
        child = subprocess.Popen(["sleep", "60"])
        with open(ARG, "w", encoding="utf-8") as f:
            f.write(str(child.pid))
        hang()
    if MODE == "stderr-flood":
        sys.stderr.write("x" * 200_000 + "END")
        sys.stderr.flush()
        return send({"id": rid, "result": {"encoded": "10"}})
    if MODE == "answer-all":
        return send({"id": rid, "result": {"encoded": "10"}})
    raise SystemExit(f"unknown mode {MODE}")


def main():
    if MODE == "hello-crash":
        sys.exit(1)
    if MODE == "hello-hang":
        hang()
    if MODE == "hello-error":
        request = read_request()
        return send({"id": request["id"], "error": {"kind": "harness", "message": "no"}})
    if MODE == "close-stdin":
        hello()
        os.close(0)
        hang()
    if MODE == "close-stderr":
        os.close(2)
        hello()
        while True:
            request = read_request()
            send({"id": request["id"], "result": {"encoded": "10"}})
    if MODE == "no-read":
        hello()
        hang()
    if MODE == "early-answer":
        hello()
        sys.stdin.buffer.read(1)
        write(b'{"id": 1, "result": {"items": []}}\n')
        hang()
    if MODE == "crash-on-junk":
        hello()
        read_request()
    if MODE == "silent-on-junk":
        hello()
        for line in sys.stdin.buffer:
            try:
                request = json.loads(line)
            except ValueError:
                continue
            if request.get("op") not in HELLO["operations"]:
                send({"id": request["id"], "error": {"kind": "harness", "message": "op"}})
            else:
                send({"id": request["id"], "result": {"items": []}})
        return None
    if MODE == "leak":
        hello()
        for seen, line in enumerate(sys.stdin.buffer):
            request = json.loads(line)
            state = "accepted" if seen == 0 else "duplicitous"
            send({"id": request["id"], "result": {
                "dispositions": [{"initial": state, "final": state}], "key_states": {}}})
        return None
    hello()
    while True:
        behave(read_request())


if __name__ == "__main__":
    main()
