package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// caseStream reads the stream of one of the suite's cases. Reading a case's input is fine; reading
// its expectations would not be, and these tests check keri-go's verdicts against what the README
// records, not against the case.
func caseStream(t *testing.T, layer, id string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cases", layer, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Input struct {
			Stream   string
			Messages []struct{ Stream string }
		}
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Input.Stream != "" {
		return c.Input.Stream
	}
	return c.Input.Messages[0].Stream
}

func parseResult(t *testing.T, streamHex string) map[string]any {
	t.Helper()
	r := answer(t, `{"id":1,"op":"cesr.parse","stream":"`+streamHex+`"}`)
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("parse answered an error: %v", r)
	}
	return res
}

func TestInteropMustRejectStreamsAreRejected(t *testing.T) {
	for _, id := range []string{"CESR-0049", "CESR-0050", "CESR-0052", "CESR-0054", "CESR-0057"} {
		res := parseResult(t, caseStream(t, "cesr", id))
		reject, ok := res["reject"].(map[string]any)
		if !ok || reject["class"] != classParse {
			t.Fatalf("%s: %v", id, res)
		}
	}
}

func TestAnAcceptedStreamIsAnsweredWithASummary(t *testing.T) {
	s := caseStream(t, "cesr", "CESR-0045")
	res := parseResult(t, s)
	acc, ok := res["accepted"].(map[string]any)
	if !ok || int(acc["consumed"].(float64)) != len(s)/2 {
		t.Fatalf("%v", res)
	}
}

func TestConcatenatedMessagesAndLeadingWhitespaceAreConsumedWhole(t *testing.T) {
	s := caseStream(t, "cesr", "CESR-0045")
	both := hex.EncodeToString([]byte("\n ")) + s + s
	res := parseResult(t, both)
	if int(res["accepted"].(map[string]any)["consumed"].(float64)) != len(both)/2 {
		t.Fatalf("%v", res)
	}
}

// keri-go skips whitespace before a message but not after its attachments, where it expects a
// count code or the next body.
func TestWhitespaceAfterAttachmentsIsRejected(t *testing.T) {
	s := caseStream(t, "cesr", "CESR-0045")
	res := parseResult(t, s+hex.EncodeToString([]byte("\n"))+s)
	if res["reject"].(map[string]any)["class"] != classParse {
		t.Fatalf("%v", res)
	}
}

func TestAGenus2StreamIsRejectedByVersionDetection(t *testing.T) {
	// keri-go frames a leading -_AAACAA as part of the body, so the version string is not at the
	// offset DetectVersion requires.
	res := parseResult(t, hex.EncodeToString([]byte("-_AAACAA"))+caseStream(t, "cesr", "CESR-0045"))
	if res["reject"].(map[string]any)["class"] != classVersion {
		t.Fatalf("%v", res)
	}
}

func TestAStreamKeriGoCannotFrameIsRejected(t *testing.T) {
	// KERI-0001's 2.00 controller-signature group (-K) reads as an unknown 1.00 group.
	res := parseResult(t, caseStream(t, "keri", "KERI-0001"))
	if res["reject"].(map[string]any)["class"] != classParse {
		t.Fatalf("%v", res)
	}
}

func TestAnEmptyStreamIsRejected(t *testing.T) {
	if parseResult(t, "")["reject"] == nil {
		t.Fatal("empty stream accepted")
	}
}

func TestEncodeUsesKeriGosNamedCodesOnly(t *testing.T) {
	raw := strings.Repeat("00", 32)
	r := answer(t, `{"id":2,"op":"cesr.encode","code":"E","raw":"`+raw+`","domain":"text"}`)
	enc, _ := hex.DecodeString(r["result"].(map[string]any)["encoded"].(string))
	if string(enc) != "E"+strings.Repeat("A", 43) {
		t.Fatalf("%s", enc)
	}
	sig := strings.Repeat("11", 64)
	r = answer(t, `{"id":2,"op":"cesr.encode","code":"0B","raw":"`+sig+`","domain":"text"}`)
	enc, _ = hex.DecodeString(r["result"].(map[string]any)["encoded"].(string))
	if !strings.HasPrefix(string(enc), "0B") || len(enc) != 88 {
		t.Fatalf("%s", enc)
	}
}

func TestEncodeRefusals(t *testing.T) {
	cases := map[string][2]string{
		`{"id":2,"op":"cesr.encode","code":"M","raw":"0000","domain":"text"}`: {"unsupported", eUnknownCode},
		`{"id":2,"op":"cesr.encode","code":"E","raw":"00","domain":"binary"}`: {"unsupported", eBinaryDomain},
		`{"id":2,"op":"cesr.encode","code":"E","raw":"00","domain":"qb3"}`:    {"harness", eMalformed},
		`{"id":2,"op":"cesr.encode","code":"","raw":"00","domain":"text"}`:    {"harness", eMalformed},
		`{"id":2,"op":"cesr.encode","code":"E","raw":"0","domain":"text"}`:    {"harness", eMalformed},
		`{"id":2,"op":"cesr.encode","raw":"00","domain":"text"}`:              {"harness", eMalformed},
	}
	for line, want := range cases {
		kind, msg := errorOf(t, answer(t, line))
		if kind != want[0] || !strings.HasPrefix(msg, want[1]+": ") {
			t.Fatalf("%s: got %s %q", line, kind, msg)
		}
	}
}

func TestEncodeRefusedByKeriGo(t *testing.T) {
	saved := matterQB64
	defer func() { matterQB64 = saved }()
	matterQB64 = func(string, []byte) (string, error) { return "", errTest }
	kind, msg := errorOf(t, answer(t, `{"id":2,"op":"cesr.encode","code":"E","raw":"00","domain":"text"}`))
	if kind != "unsupported" || !strings.HasPrefix(msg, eEncodeRefused+": ") {
		t.Fatalf("got %s %q", kind, msg)
	}
}
