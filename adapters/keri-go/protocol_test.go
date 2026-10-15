package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// answer runs one request line through handleLine and decodes the response.
func answer(t *testing.T, line string) map[string]any {
	t.Helper()
	out := handleLine([]byte(line), &bytes.Buffer{})
	var r map[string]any
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("response is not JSON: %s", out)
	}
	assertWellFormed(t, r)
	return r
}

// assertWellFormed checks that a response is {id, result} or {id, error:{kind, message}}.
func assertWellFormed(t *testing.T, r map[string]any) {
	t.Helper()
	if _, ok := r["id"]; !ok || len(r) != 2 {
		t.Fatalf("not {id, result|error}: %v", r)
	}
	if e, ok := r["error"].(map[string]any); ok {
		if len(e) != 2 || (e["kind"] != "harness" && e["kind"] != "unsupported") {
			t.Fatalf("malformed error: %v", r)
		}
		if _, ok := e["message"].(string); !ok {
			t.Fatalf("error without message: %v", r)
		}
		return
	}
	if _, ok := r["result"].(map[string]any); !ok {
		t.Fatalf("neither result nor error: %v", r)
	}
}

func errorOf(t *testing.T, r map[string]any) (string, string) {
	t.Helper()
	e, ok := r["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected an error response, got %v", r)
	}
	return e["kind"].(string), e["message"].(string)
}

func TestHelloDeclaresWhatTheAdapterImplements(t *testing.T) {
	r := answer(t, `{"id":0,"op":"hello","protocol":1,"supported":[1]}`)
	if r["id"].(float64) != 0 {
		t.Fatalf("id not echoed: %v", r)
	}
	res := r["result"].(map[string]any)
	if res["protocol"].(float64) != 1 {
		t.Fatalf("protocol: %v", res)
	}
	impl := res["implementation"].(map[string]any)
	if impl["name"] != "keri-go" || impl["version"] != implVersion || impl["commit"] != implCommit {
		t.Fatalf("implementation: %v", impl)
	}
	adapter := res["adapter"].(map[string]any)
	if adapter["name"] != adapterName || adapter["version"] != adapterVersion {
		t.Fatalf("adapter: %v", adapter)
	}
	got, _ := json.Marshal([]any{res["operations"], res["features"], res["composes"]})
	want, _ := json.Marshal([]any{operations, features, composes})
	if !bytes.Equal(got, want) {
		t.Fatalf("hello declares %s, want %s", got, want)
	}
}

func TestHelloNegotiatesFromSupportedOrProtocol(t *testing.T) {
	r := answer(t, `{"id":1,"op":"hello","protocol":2,"supported":[2,1]}`)
	if r["result"].(map[string]any)["protocol"].(float64) != 1 {
		t.Fatalf("did not choose 1 from supported: %v", r)
	}
	r = answer(t, `{"id":1,"op":"hello","protocol":1}`)
	if r["result"].(map[string]any)["protocol"].(float64) != 1 {
		t.Fatalf("did not fall back to protocol: %v", r)
	}
	for _, line := range []string{
		`{"id":1,"op":"hello","protocol":2,"supported":[2]}`,
		`{"id":1,"op":"hello","protocol":1,"supported":["1"]}`,
		`{"id":1,"op":"hello","protocol":1.5}`,
		`{"id":1,"op":"hello"}`,
	} {
		kind, msg := errorOf(t, answer(t, line))
		if kind != "unsupported" || !strings.HasPrefix(msg, eVersion+": ") {
			t.Fatalf("%s: got %s %q", line, kind, msg)
		}
	}
}

func TestUnreadableLinesGetANullID(t *testing.T) {
	for _, line := range []string{
		``, `   `, `not json`, `[1,2]`, `"x"`, `{"op":"hello"}`, `{"id":-1,"op":"hello"}`,
		`{"id":1.5,"op":"hello"}`, `{"id":"7","op":"hello"}`, `{"id":null,"op":"hello"}`,
		`{"id":18446744073709551616,"op":"hello"}`, `{"id":1} trailing`,
	} {
		r := answer(t, line)
		if r["id"] != nil {
			t.Fatalf("%q: id should be null: %v", line, r)
		}
		kind, msg := errorOf(t, r)
		if kind != "harness" || !strings.HasPrefix(msg, eMalformed+": ") {
			t.Fatalf("%q: got %s %q", line, kind, msg)
		}
	}
}

func TestLargestIDIsEchoedExactly(t *testing.T) {
	out := handleLine([]byte(`{"id":18446744073709551615,"op":"hello","supported":[1]}`), &bytes.Buffer{})
	if !bytes.HasPrefix(out, []byte(`{"id":18446744073709551615,`)) {
		t.Fatalf("id not echoed exactly: %s", out)
	}
}

func TestRequestsWithoutAUsableOpCarryTheirID(t *testing.T) {
	cases := map[string]string{
		`{"id":3}`:                                   eMalformed,
		`{"id":3,"op":7}`:                            eMalformed,
		`{"id":3,"op":"keri.dance"}`:                 eUnknownOp,
		`{"id":3,"op":"cesr.parse"}`:                 eMalformed,
		`{"id":3,"op":"cesr.parse","stream":"ABCD"}`: eMalformed,
		`{"id":3,"op":"cesr.parse","stream":"abc"}`:  eMalformed,
		`{"id":3,"op":"cesr.parse","stream":7}`:      eMalformed,
	}
	for line, code := range cases {
		r := answer(t, line)
		if r["id"].(float64) != 3 {
			t.Fatalf("%s: id not carried: %v", line, r)
		}
		kind, msg := errorOf(t, r)
		if kind != "harness" || !strings.HasPrefix(msg, code+": ") {
			t.Fatalf("%s: got %s %q, want %s", line, kind, msg, code)
		}
	}
}

func TestUndeclaredOperationsAreUnsupported(t *testing.T) {
	for _, op := range []string{"keri.emit", "acdc.verify", "exn.verify"} {
		kind, msg := errorOf(t, answer(t, `{"id":4,"op":"`+op+`"}`))
		if kind != "unsupported" || !strings.HasPrefix(msg, eUndeclaredOp+": ") {
			t.Fatalf("%s: got %s %q", op, kind, msg)
		}
	}
}

func TestAPanicBecomesAHarnessErrorAndIsLogged(t *testing.T) {
	ops["test.panic"] = func(map[string]json.RawMessage) (any, *opError) { panic("boom") }
	defer delete(ops, "test.panic")
	var log bytes.Buffer
	out := handleLine([]byte(`{"id":5,"op":"test.panic"}`), &log)
	var r map[string]any
	_ = json.Unmarshal(out, &r)
	kind, msg := errorOf(t, r)
	if kind != "harness" || !strings.HasPrefix(msg, ePanic+": ") || !strings.Contains(log.String(), "boom") {
		t.Fatalf("got %s %q, log %q", kind, msg, log.String())
	}
}

func TestServeAnswersEachLineAndExitsZeroAtEOF(t *testing.T) {
	in := strings.NewReader("{\"id\":0,\"op\":\"hello\",\"supported\":[1]}\nnope\n{\"id\":2,\"op\":\"x\"}")
	var out, log bytes.Buffer
	if code := serve(in, &out, &log, 1024); code != 0 {
		t.Fatalf("exit %d, log %s", code, log.String())
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 responses, got %q", out.String())
	}
	for _, l := range lines {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("%q", l)
		}
		assertWellFormed(t, r)
	}
}

func TestServeAnswersAnOversizeLineAndSkipsIt(t *testing.T) {
	long := `{"id":9,"op":"cesr.parse","stream":"` + strings.Repeat("ab", 100) + "\"}\n"
	in := strings.NewReader(long + "{\"id\":10,\"op\":\"hello\",\"supported\":[1]}\n")
	var out, log bytes.Buffer
	if code := serve(in, &out, &log, 64); code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 responses, got %q", out.String())
	}
	var first, second map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &first)
	_ = json.Unmarshal([]byte(lines[1]), &second)
	if first["id"] != nil {
		t.Fatalf("oversize line should get a null id: %v", first)
	}
	if _, msg := errorOf(t, first); !strings.HasPrefix(msg, eOversize+": ") {
		t.Fatalf("oversize: %q", msg)
	}
	if second["id"].(float64) != 10 {
		t.Fatalf("next request not answered: %v", second)
	}
}

func TestServeAcceptsALineOfExactlyTheLimit(t *testing.T) {
	line := `{"id":1,"op":"hello","supported":[1]}`
	var out, log bytes.Buffer
	serve(strings.NewReader(line+"\n"), &out, &log, len(line))
	if !strings.Contains(out.String(), `"result"`) {
		t.Fatalf("a line of exactly the limit was refused: %s", out.String())
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestServeExitsOneOnStdioFailure(t *testing.T) {
	var log bytes.Buffer
	if code := serve(failingReader{}, &bytes.Buffer{}, &log, 64); code != 1 || !strings.Contains(log.String(), eStdio) {
		t.Fatalf("read failure: exit %d, log %q", code, log.String())
	}
	log.Reset()
	in := strings.NewReader("{\"id\":0,\"op\":\"hello\",\"supported\":[1]}\n")
	if code := serve(in, failingWriter{}, &log, 64); code != 1 || !strings.Contains(log.String(), eStdio) {
		t.Fatalf("write failure: exit %d, log %q", code, log.String())
	}
}

func TestReadFailureWhileSkippingAnOversizeLine(t *testing.T) {
	var log bytes.Buffer
	in := io.MultiReader(strings.NewReader(strings.Repeat("x", 100)), failingReader{})
	if code := serve(in, &bytes.Buffer{}, &log, 10); code != 1 {
		t.Fatalf("exit %d, log %q", code, log.String())
	}
}

func TestALineLongerThanTheReadBufferButWithinTheLimitIsRead(t *testing.T) {
	line := `{"id":1,"op":"hello","supported":[1],"pad":"` + strings.Repeat("x", 10000) + `"}`
	var out bytes.Buffer
	serve(strings.NewReader(line+"\n"), &out, &bytes.Buffer{}, maxRequestLine)
	if !strings.Contains(out.String(), `"result"`) {
		t.Fatalf("%s", out.String())
	}
}

func TestAnOversizeLastLineWithoutANewlineIsAnswered(t *testing.T) {
	var out bytes.Buffer
	if code := serve(strings.NewReader(strings.Repeat("x", 100)), &out, &bytes.Buffer{}, 10); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), eOversize) {
		t.Fatalf("%s", out.String())
	}
}

// main serves standard input to standard output and exits with serve's status.
func TestMainServesStdio(t *testing.T) {
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	savedIn, savedOut, savedExit := os.Stdin, os.Stdout, exit
	defer func() { os.Stdin, os.Stdout, exit = savedIn, savedOut, savedExit }()
	os.Stdin, os.Stdout = inR, outW
	status := -1
	exit = func(code int) { status = code }
	_, _ = inW.WriteString("{\"id\":0,\"op\":\"hello\",\"supported\":[1]}\n")
	inW.Close()
	main()
	outW.Close()
	got, _ := io.ReadAll(outR)
	if status != 0 || !strings.Contains(string(got), `"keri-go"`) {
		t.Fatalf("exit %d, output %s", status, got)
	}
}
