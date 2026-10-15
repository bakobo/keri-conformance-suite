package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ecmaRegexp runs the schema's patterns as ECMAScript regular expressions, which JSON Schema
// specifies; Go's own engine has no lookahead, and the threshold pattern uses one.
type ecmaRegexp struct{ re *regexp2.Regexp }

func (r ecmaRegexp) MatchString(s string) bool {
	ok, err := r.re.MatchString(s)
	return ok && err == nil
}

func (r ecmaRegexp) String() string { return r.re.String() }

var responseSchema *jsonschema.Schema

func init() {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "adapter-protocol.schema.json"))
	if err != nil {
		panic(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	c := jsonschema.NewCompiler()
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		re, err := regexp2.Compile(s, regexp2.ECMAScript)
		return ecmaRegexp{re}, err
	})
	if err := c.AddResource("protocol.json", doc); err != nil {
		panic(err)
	}
	responseSchema = c.MustCompile("protocol.json#/$defs/response")
}

func assertResponseMatchesSchema(t *testing.T, r map[string]any) {
	t.Helper()
	b, _ := json.Marshal(r)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := responseSchema.Validate(inst); err != nil {
		t.Fatalf("response %s does not match the protocol schema: %v", b, err)
	}
}

// Every kind of response the adapter gives matches schema/adapter-protocol.schema.json.
func TestEveryResponseKindMatchesTheProtocolSchema(t *testing.T) {
	accepted := caseStream(t, "cesr", "CESR-0045")
	for _, line := range []string{
		`{"id":0,"op":"hello","protocol":1,"supported":[1]}`,
		`{"id":0,"op":"hello","supported":[2]}`,
		`{"id":1,"op":"cesr.parse","stream":"` + accepted + `"}`,
		`{"id":1,"op":"cesr.parse","stream":"` + caseStream(t, "cesr", "CESR-0049") + `"}`,
		`{"id":2,"op":"cesr.encode","code":"E","raw":"` + strings.Repeat("00", 32) + `","domain":"text"}`,
		`{"id":2,"op":"cesr.encode","code":"M","raw":"0000","domain":"text"}`,
		`{"id":3,"op":"keri.process","messages":[]}`,
		`{"id":4,"op":"keri.emit"}`,
		`{"id":5,"op":"nope"}`,
		`not json`,
	} {
		assertResponseMatchesSchema(t, answer(t, line))
	}
}

// hello names exactly the keri-go version go.mod requires, so a moved pin cannot keep reporting
// the old identity. The commit is the one the v0.1.5 tag points at, checked when the pin was set
// (README, "What it tests, pinned").
func TestHelloNamesThePinnedModule(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*github\.com/grapeid/keri-go v(\S+)$|require github\.com/grapeid/keri-go v(\S+)`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go.mod does not require keri-go")
	}
	v := string(m[1]) + string(m[2])
	if v != implVersion {
		t.Fatalf("go.mod requires keri-go %s and hello reports %s", v, implVersion)
	}
	if len(implCommit) != 40 {
		t.Fatalf("commit %q is not a full SHA", implCommit)
	}
}
