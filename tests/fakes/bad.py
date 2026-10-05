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


def encoded(rid, **extra):
    return json.dumps({"id": rid, "result": {"encoded": "10"}, **extra}).encode() + b"\n"


def error(rid, kind, message):
    return json.dumps({"id": rid, "error": {"kind": kind, "message": message}}).encode() + b"\n"


# Modes that answer each request with one fixed line, as a function of the request id.
LINES = {
    "wrong-id": lambda rid: encoded(rid + 1),
    "bool-id": lambda rid: b'{"id": true, "result": {"encoded": "10"}}\n',
    "junk": lambda rid: b"this is not json\n",
    "not-utf8": lambda rid: b"\xff\xfe\n",
    "not-object": lambda rid: b"[1, 2]\n",
    "both": lambda rid: json.dumps({"id": rid, "result": {},
                                    "error": {"kind": "harness", "message": "x"}}).encode() + b"\n",
    "neither": lambda rid: json.dumps({"id": rid}).encode() + b"\n",
    "extra-key": lambda rid: encoded(rid, extra=1),
    "error-harness": lambda rid: error(rid, "harness", "glue raised"),
    "error-unsupported": lambda rid: error(rid, "unsupported", "cannot"),
    "error-bad-kind": lambda rid: error(rid, "oops", "x"),
    "error-not-object": lambda rid: json.dumps({"id": rid, "error": "x"}).encode() + b"\n",
    "answer-all": encoded,
    "few-dispositions": lambda rid: json.dumps({"id": rid, "result": {
        "dispositions": [{"initial": "seen", "final": "seen", "trunk": True}],
        "key_states": {}}}).encode() + b"\n",
}


def behave(request):
    rid = request["id"]
    if MODE in LINES:
        write(LINES[MODE](rid))
    elif MODE == "crash":
        print("boom: the parser panicked", file=sys.stderr, flush=True)
        sys.exit(3)
    elif MODE == "hang":
        hang()
    elif MODE == "oversize":
        write(b'{"id": %d, "result": {"encoded": "' % rid + b"a" * int(ARG) + b'"}}\n')
        hang()
    elif MODE == "no-newline":
        write(b'{"id": ')
        hang()
    elif MODE == "flood":
        while True:
            write(b"a" * 65536)
    elif MODE == "memory":
        block = bytearray(int(ARG))  # fails under a small enough address-space limit
        del block
        write(encoded(rid))
    elif MODE == "cpu":
        while True:
            pass
    elif MODE == "grandchild":
        child = subprocess.Popen(["sleep", "60"])
        with open(ARG, "w", encoding="utf-8") as f:
            f.write(str(child.pid))
        hang()
    elif MODE == "stderr-flood":
        sys.stderr.write("x" * 200_000 + "END")
        sys.stderr.flush()
        write(encoded(rid))
    else:
        raise SystemExit(f"unknown mode {MODE}")


def main():
    if MODE == "hello-crash":
        sys.exit(1)
    if MODE == "hello-hang":
        hang()
    if MODE == "hello-error":
        request = read_request()
        send({"id": request["id"],
              "error": {"kind": "harness", "message": "the hello handler is broken"}})
        return
    if MODE == "hello-version":
        request = read_request()
        send({"id": request["id"], "result": {**HELLO, "protocol": max(request["supported"]) + 1}})
        hang()
    if MODE == "close-stdin":
        request = read_request()
        os.close(0)  # before answering hello, so the runner's next write always finds it closed
        send({"id": request["id"], "result": HELLO})
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
        sys.exit(5)
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
        return
    if MODE == "leak":
        hello()
        for seen, line in enumerate(sys.stdin.buffer):
            request = json.loads(line)
            state = "seen" if seen == 0 else "duplicitous"
            send({"id": request["id"], "result": {
                "dispositions": [{"initial": state, "final": state, "trunk": seen == 0}],
                "key_states": {}}})
        return
    hello()
    while True:
        behave(read_request())


if __name__ == "__main__":
    main()
