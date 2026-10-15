package main

import (
	"encoding/base64"
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

func TestEncodeHandsEveryCodeToKeriGo(t *testing.T) {
	raw := strings.Repeat("00", 32)
	r := answer(t, `{"id":2,"op":"cesr.encode","code":"E","raw":"`+raw+`","domain":"text"}`)
	enc, _ := hex.DecodeString(r["result"].(map[string]any)["encoded"].(string))
	if string(enc) != "E"+strings.Repeat("A", 43) {
		t.Fatalf("%s", enc)
	}
	// keri-go names no code M, and encodes it anyway by the same arithmetic; that is its answer.
	r = answer(t, `{"id":2,"op":"cesr.encode","code":"M","raw":"0001","domain":"text"}`)
	enc, _ = hex.DecodeString(r["result"].(map[string]any)["encoded"].(string))
	if string(enc) != "MAAB" {
		t.Fatalf("%s", enc)
	}
}

func TestEncodeRefusals(t *testing.T) {
	cases := map[string][2]string{
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

// When keri-go refuses to encode, the answer is a rejection, as for cesr.parse.
func TestARefusalByKeriGoIsARejection(t *testing.T) {
	// A three-character code cannot be written over any raw value: keri-go's own check refuses it.
	r := answer(t, `{"id":2,"op":"cesr.encode","code":"1AA","raw":"","domain":"text"}`)
	if r["result"].(map[string]any)["reject"].(map[string]any)["class"] != classEncode {
		t.Fatalf("%v", r)
	}
}

// keri-go's stream reader frames bodies by braces and does not read them; its ParseEvent does.
func TestABodyKeriGoCannotReadIsRejected(t *testing.T) {
	raw, _ := hex.DecodeString(caseStream(t, "cesr", "CESR-0045"))
	broken := strings.Replace(string(raw), `_",`, `_"!`, 1)
	res := parseResult(t, hex.EncodeToString([]byte(broken)))
	if res["reject"].(map[string]any)["class"] != classEvent {
		t.Fatalf("%v", res)
	}
}

// keri-go has no parse-level ACDC reader: ParseEvent reads key events (and would refuse an ACDC's
// s, a schema SAID, as a sequence number), and VerifyCredential also checks SAIDs. So an ACDC body
// is answered unsupported, whether it is keri-go's own issued-into-registry vector or not JSON.
func TestAnACDCBodyIsUnsupported(t *testing.T) {
	good, _ := base64.StdEncoding.DecodeString("eyJ2IjoiQUNEQzEwSlNPTjAwMDE5NF8iLCJkIjoiRUNnSVVVc1dhWjhIU2o1aWV6ODc2OFBFcEcxeE4wYmNaRjdOOHdWWWw1UzMiLCJpIjoiREdMRHpoZzdWTzFVRUZPczRBdi1nVVU3aGNSYmR2eU9fNW53N0liS0JyUXQiLCJyaSI6IkVOclNGcnhPTXI1R1VfQldVRWFKdEx0ZDdsLTVlZWJHTy0tUVgzX283bG9vIiwicyI6IkVDSzB4Wmxram1Qb092ME5HR0Z5Mi1fal9lOXpjMHl4YXlISDBwTmVveDh3IiwiYSI6eyJkIjoiRUVGRjlqczdrT09zSXlBY2tTMHpZVldiSGJpMmVHbXQtMFdfdWdxVkFxM2ciLCJpIjoiREdwbzJiczdncTh3TjNYenBYUkR1RzlSYVkzbXhlUTlVa0ttZnI3YUwwZy0iLCJkdCI6IjIwMjQtMDEtMDFUMDA6MDA6MDAuMDAwMDAwKzAwOjAwIiwibmFtZSI6IkFsaWNlIiwic2NvcmUiOjQyfX0=")
	bad := []byte(`{"v":"ACDC10JSON000000_","x":xx}`)
	for _, body := range [][]byte{good, bad} {
		kind, msg := errorOf(t, answer(t, `{"id":1,"op":"cesr.parse","stream":"`+hex.EncodeToString(body)+`"}`))
		if kind != "unsupported" || !strings.HasPrefix(msg, eACDCBody+": ") {
			t.Fatalf("%s: got %s %q", body, kind, msg)
		}
	}
}
