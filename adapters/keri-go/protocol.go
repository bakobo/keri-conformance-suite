// Command kcs-adapter-keri-go connects grapeid/keri-go to the conformance runner over adapter
// protocol version 1 (docs/adapter-protocol.md): one JSON request per line on standard input, one
// JSON response per line on standard output. README.md says what it declares and why.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"runtime/debug"
)

const (
	protocolVersion = 1
	adapterName     = "kcs-adapter-keri-go"
	adapterVersion  = "0.1.0"

	// implVersion is the keri-go module version go.mod requires; implCommit is the commit its tag
	// v0.1.5 names in github.com/grapeid/keri-go. TestHelloNamesThePinnedModule ties the first to
	// go.mod.
	implVersion = "0.1.5"
	implCommit  = "f06d1dac5a36dea4b619eb6934e43e6fdc68b835"

	// maxRequestLine is the longest request line read, in bytes, not counting its newline.
	maxRequestLine = 64 * 1024 * 1024
)

var (
	operations = []string{"cesr.parse", "cesr.encode", "keri.process"}
	// Drawn from profiles/features.json; README.md says why each is or is not declared.
	features = []string{
		"cesr.genus-1.00",
		"cesr.serialization.json",
		"crypto.ed25519",
		"kel.basic",
		"kel.multisig.numeric",
		"kel.multisig.weighted",
		"keri.routing",
		"keri.version-1.x",
	}
	// keri-go validates a whole log; routing each delivery to its identifier's log is the
	// adapter's (kel.go).
	composes = []string{"keri.routing"}
)

// Error codes, per bakobo/dev standards/error-codes.md. Each is the prefix of its message.
const (
	eOversize     = "e.input.range.request-size.f"
	eMalformed    = "e.input.format.request.f"
	eUnknownOp    = "e.input.range.unknown-op.f"
	eUndeclaredOp = "e.feature.unsupported.undeclared-op.f"
	eVersion      = "e.feature.unsupported.protocol-version.f"
	eBinaryDomain = "e.feature.unsupported.binary-domain.f"
	eACDCBody     = "e.feature.unsupported.acdc-body.f"
	ePanic        = "e.self.unknown.panic.f"
	eStdio        = "e.env.io.stdio.f"
)

// opError is an operation's failure: kind is "harness" or "unsupported".
type opError struct {
	kind    string
	message string
}

func harness(code, format string, args ...any) *opError {
	return &opError{"harness", code + ": " + fmt.Sprintf(format, args...)}
}

func unsupported(code, format string, args ...any) *opError {
	return &opError{"unsupported", code + ": " + fmt.Sprintf(format, args...)}
}

type operation func(request map[string]json.RawMessage) (any, *opError)

var ops = map[string]operation{
	"hello":        hello,
	"cesr.parse":   parseOp,
	"cesr.encode":  encodeOp,
	"keri.process": processOp,
}

func hello(request map[string]json.RawMessage) (any, *opError) {
	offered := request["supported"]
	if offered == nil {
		offered = json.RawMessage("[" + string(request["protocol"]) + "]")
	}
	var list []json.RawMessage
	_ = json.Unmarshal(offered, &list)
	for _, v := range list {
		if string(v) == "1" {
			return map[string]any{
				"protocol": protocolVersion,
				"adapter":  map[string]string{"name": adapterName, "version": adapterVersion},
				"implementation": map[string]string{
					"name": "keri-go", "version": implVersion, "commit": implCommit,
				},
				"operations": operations,
				"features":   features,
				"composes":   composes,
			}, nil
		}
	}
	return nil, unsupported(eVersion, "This adapter implements adapter protocol version 1 only, "+
		"and the runner offered %s.", offered)
}

// requestID reads a request's id: a non-negative integer no larger than 2^64-1, echoed exactly.
func requestID(request map[string]json.RawMessage) (json.RawMessage, bool) {
	raw, ok := request["id"]
	if !ok {
		return nil, false
	}
	n, ok := new(big.Int).SetString(string(raw), 10)
	if !ok || raw[0] == '-' || n.BitLen() > 64 {
		return nil, false
	}
	return raw, true
}

func respond(id json.RawMessage, result any, e *opError) []byte {
	if id == nil {
		id = json.RawMessage("null")
	}
	var body map[string]any
	if e != nil {
		body = map[string]any{"id": id, "error": map[string]string{"kind": e.kind, "message": e.message}}
	} else {
		body = map[string]any{"id": id, "result": result}
	}
	out, _ := json.Marshal(body)
	return out
}

// handleLine answers one request line. It never panics: a panic in an operation, including one
// inside keri-go, is logged and answered as a harness error.
func handleLine(line []byte, log io.Writer) (out []byte) {
	var request map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(line))
	var extra json.RawMessage
	if err := dec.Decode(&request); err != nil || request == nil || dec.Decode(&extra) != io.EOF {
		return respond(nil, nil, harness(eMalformed, "The request line is not a JSON object."))
	}
	id, ok := requestID(request)
	if !ok {
		return respond(nil, nil, harness(eMalformed, "The request has no id that is a non-negative integer."))
	}
	var opField *string
	if err := json.Unmarshal(request["op"], &opField); err != nil || opField == nil {
		return respond(id, nil, harness(eMalformed, "The request has no string op."))
	}
	op := *opField
	handler, known := ops[op]
	if !known {
		switch op {
		case "keri.emit", "acdc.verify", "exn.verify":
			return respond(id, nil, unsupported(eUndeclaredOp, "This adapter does not offer %s; "+
				"its hello lists the operations it does.", op))
		}
		return respond(id, nil, harness(eUnknownOp, "%q is not an operation of adapter protocol 1.", op))
	}
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintf(log, "%s: panic in %s: %v\n%s", ePanic, op, p, debug.Stack())
			out = respond(id, nil, harness(ePanic, "The operation panicked (%v), so it gave no "+
				"answer; standard error has the stack.", p))
		}
	}()
	result, err := handler(request)
	if err != nil {
		fmt.Fprintln(log, err.message)
	}
	return respond(id, result, err)
}

// serve answers request lines until end of input. It returns the process exit status.
func serve(in io.Reader, out io.Writer, log io.Writer, limit int) int {
	reader := bufio.NewReader(in)
	for {
		line, oversize, err := readLine(reader, limit)
		if err != nil && err != io.EOF {
			fmt.Fprintf(log, "%s: The adapter could not read standard input: %v\n", eStdio, err)
			return 1
		}
		if line == nil && !oversize {
			return 0
		}
		var response []byte
		if oversize {
			response = respond(nil, nil, harness(eOversize, "The request line is longer than %d "+
				"bytes, so it was not read.", limit))
		} else {
			response = handleLine(line, log)
		}
		if _, werr := out.Write(append(response, '\n')); werr != nil {
			fmt.Fprintf(log, "%s: The adapter could not write standard output: %v\n", eStdio, werr)
			return 1
		}
		if err == io.EOF {
			return 0
		}
	}
}

// readLine reads one line without its newline, holding at most limit bytes of it. A longer line
// is consumed to its end and reported as oversize. At end of input, err is io.EOF and line is the
// unterminated remainder, or nil if there is none.
func readLine(r *bufio.Reader, limit int) (line []byte, oversize bool, err error) {
	var buf []byte
	for {
		chunk, rerr := r.ReadSlice('\n')
		if !oversize {
			buf = append(buf, chunk...)
			n := len(buf)
			if rerr == nil {
				n-- // the newline
			}
			if n > limit {
				oversize, buf = true, nil
			}
		}
		switch rerr {
		case nil:
			if oversize {
				return nil, true, nil
			}
			return bytes.TrimSuffix(buf, []byte("\n")), false, nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if oversize {
				return nil, true, io.EOF
			}
			if len(buf) == 0 {
				return nil, false, io.EOF
			}
			return buf, false, io.EOF
		default:
			return nil, false, rerr
		}
	}
}
