package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

var errTest = errors.New("test failure")

// identity is a KEL under construction, built and signed by keri-go itself.
type identity struct {
	t       *testing.T
	chain   *keri.Keychain
	prefix  string
	said    string
	sn      int
	wits    []string
	witSigs map[string]keri.Signer
}

// must panics on error; it wraps keri-go calls that build test fixtures.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func witnesses(t *testing.T, n int) ([]string, map[string]keri.Signer) {
	var ids []string
	sigs := map[string]keri.Signer{}
	for i := 0; i < n; i++ {
		s := must(keri.GenerateSigner(false))
		id := must(s.PublicKey())
		ids = append(ids, id)
		sigs[id] = s
	}
	return ids, sigs
}

// incept builds and signs an inception with n keys, the given thresholds (nil for keri-go's
// defaults) and witnesses.
func incept(t *testing.T, label string, n int, isith json.RawMessage, wits []string, witSigs map[string]keri.Signer, toad *int) (*identity, []byte) {
	t.Helper()
	chain := must(keri.NewKeychain(keri.NewMemoryKeyStore(), label, n))
	icp := must(keri.BuildInception(keri.InceptionInput{
		Keys:        must(chain.CurrentKeys()),
		NextDigests: must(chain.NextDigests()),
		Isith:       isith,
		Nsith:       isith,
		Witnesses:   wits,
		Toad:        toad,
		Derivation:  "self-addressing",
	}))
	ev := must(keri.ParseEvent(icp))
	id := &identity{t: t, chain: chain, prefix: ev.Identifier, said: ev.SAID, wits: wits, witSigs: witSigs}
	return id, id.sign(icp, chain.Signers())
}

func (id *identity) sign(event []byte, signers []keri.Signer) []byte {
	return must(keri.SignEvent(event, signers...)).Message
}

// forge signs an event's body with a key the event does not declare, as index 0. keri-go's
// SignEvent refuses to, so the signature is framed directly: code A is an Ed25519 indexed
// signature and its second character the index.
func forge(t *testing.T, message []byte, by keri.Signer) []byte {
	body := message[:strings.Index(string(message), "}-")+1]
	sig := must(keri.MatterQB64("AA", must(by.Sign(body))))
	return append(append([]byte(nil), body...), must(keri.AttachControllerSigs([]string{sig}))...)
}

// receipted attaches a receipt couple from each named witness to a signed message.
func (id *identity) receipted(message []byte, by ...string) []byte {
	body := message[:strings.Index(string(message), "}-")+1]
	var couples []keri.ReceiptCouple
	for _, w := range by {
		sig := must(id.witSigs[w].Sign(body))
		couples = append(couples, keri.ReceiptCouple{Witness: w, CigarQB64: must(keri.MatterQB64(keri.CodeEd25519Sig, sig))})
	}
	group := must(keri.AttachReceiptCouples(couples))
	return append(append([]byte(nil), message...), group...)
}

func (id *identity) interact(data ...json.RawMessage) []byte {
	id.sn++
	ixn := must(keri.BuildInteraction(keri.InteractionInput{Prefix: id.prefix, PriorSAID: id.said, SN: id.sn, Data: data}))
	id.said = must(keri.ParseEvent(ixn)).SAID
	return id.sign(ixn, id.chain.Signers())
}

func (id *identity) rotate(cuts, adds []string, toad *int) []byte {
	keys, next, err := id.chain.Rotate()
	if err != nil {
		id.t.Fatal(err)
	}
	id.sn++
	rot := must(keri.BuildRotation(keri.RotationInput{
		Prefix: id.prefix, Keys: keys, PriorSAID: id.said, SN: id.sn, NextDigests: next,
		PriorWitnesses: id.wits, Cuts: cuts, Adds: adds, Toad: toad,
	}))
	id.said = must(keri.ParseEvent(rot)).SAID
	return id.sign(rot, id.chain.Signers())
}

func process(t *testing.T, messages ...[]byte) map[string]any {
	t.Helper()
	type msg struct {
		Stream string `json:"stream"`
		Source string `json:"source"`
	}
	ms := []msg{}
	for _, m := range messages {
		ms = append(ms, msg{hex.EncodeToString(m), "controller"})
	}
	req, _ := json.Marshal(map[string]any{"id": 3, "op": "keri.process", "perspective": map[string]string{"role": "validator"}, "messages": ms})
	r := answer(t, string(req))
	res, ok := r["result"].(map[string]any)
	if !ok {
		t.Fatalf("keri.process answered an error: %v", r)
	}
	assertResponseMatchesSchema(t, r)
	return res
}

func readings(res map[string]any) []string {
	var out []string
	for _, d := range res["dispositions"].([]any) {
		m := d.(map[string]any)
		out = append(out, m["initial"].(string)+"/"+m["final"].(string)+"/"+map[bool]string{true: "trunk", false: "off"}[m["trunk"].(bool)])
	}
	return out
}

func assertReadings(t *testing.T, res map[string]any, want ...string) {
	t.Helper()
	got := readings(res)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("readings %v, want %v (%v)", got, want, res["dispositions"])
	}
}

func keyState(t *testing.T, res map[string]any, prefix string) map[string]any {
	t.Helper()
	ks, ok := res["key_states"].(map[string]any)[prefix].(map[string]any)
	if !ok {
		t.Fatalf("no key state for %s: %v", prefix, res["key_states"])
	}
	return ks
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestALogOfEveryBasicKindIsSeenAndItsKeyStateReported(t *testing.T) {
	id, icp := incept(t, "a", 1, nil, nil, nil, nil)
	ixn1 := id.interact()
	rot := id.rotate(nil, nil, nil)
	ixn3 := id.interact()
	res := process(t, icp, ixn1, rot, ixn3)
	assertReadings(t, res, "seen/seen/trunk", "seen/seen/trunk", "seen/seen/trunk", "seen/seen/trunk")
	ks := keyState(t, res, id.prefix)
	keys := must(id.chain.CurrentKeys())
	next := must(id.chain.NextDigests())
	want := map[string]any{"sn": 3, "said": id.said, "keys": keys, "kt": "1", "ndigs": next, "nt": "1", "wits": []string{}, "bt": "0", "delegator": nil}
	if asJSON(ks) != asJSON(want) {
		t.Fatalf("key state %s, want %s", asJSON(ks), asJSON(want))
	}
}

func TestAnEventSignedByTheWrongKeyIsRejected(t *testing.T) {
	_, icp := incept(t, "a", 1, nil, nil, nil, nil)
	other, _ := incept(t, "b", 1, nil, nil, nil, nil)
	res := process(t, forge(t, icp, other.chain.Signers()[0]))
	assertReadings(t, res, "rejected/rejected/off")
	if len(res["key_states"].(map[string]any)) != 0 {
		t.Fatalf("key state for a rejected inception: %v", res["key_states"])
	}
	if !strings.Contains(res["dispositions"].([]any)[0].(map[string]any)["reason"].(string), "ValidateSignedKEL") {
		t.Fatalf("reason should name keri-go's refusal: %v", res["dispositions"])
	}
}

func TestAnEventBeforeItsPriorIsRejectedAndNotEscrowed(t *testing.T) {
	id, icp := incept(t, "a", 1, nil, nil, nil, nil)
	ixn1 := id.interact()
	ixn2 := id.interact()
	res := process(t, icp, ixn2, ixn1)
	assertReadings(t, res, "seen/seen/trunk", "rejected/rejected/off", "seen/seen/trunk")
	if keyState(t, res, id.prefix)["sn"].(float64) != 1 {
		t.Fatalf("%v", res["key_states"])
	}
}

func TestARepeatedEventIsSeenAgainAndAConflictingOneRejected(t *testing.T) {
	id, icp := incept(t, "a", 1, nil, nil, nil, nil)
	fork := *id
	ixnA := id.interact(json.RawMessage(`{"d":"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	ixnB := fork.interact()
	res := process(t, icp, ixnA, icp, ixnA, ixnB)
	assertReadings(t, res, "seen/seen/trunk", "seen/seen/trunk", "seen/seen/trunk", "seen/seen/trunk", "rejected/rejected/off")
	if keyState(t, res, id.prefix)["said"] != id.said {
		t.Fatalf("%v", res["key_states"])
	}
}

func TestARepeatWithBadSignaturesIsRejected(t *testing.T) {
	_, icp := incept(t, "a", 1, nil, nil, nil, nil)
	other, _ := incept(t, "b", 1, nil, nil, nil, nil)
	res := process(t, icp, forge(t, icp, other.chain.Signers()[0]))
	assertReadings(t, res, "seen/seen/trunk", "rejected/rejected/off")
}

func TestTwoIdentifiersAreRoutedToTheirOwnLogs(t *testing.T) {
	a, icpA := incept(t, "a", 1, nil, nil, nil, nil)
	b, icpB := incept(t, "b", 1, nil, nil, nil, nil)
	res := process(t, icpA, icpB, b.interact(), a.interact())
	assertReadings(t, res, "seen/seen/trunk", "seen/seen/trunk", "seen/seen/trunk", "seen/seen/trunk")
	if len(res["key_states"].(map[string]any)) != 2 {
		t.Fatalf("%v", res["key_states"])
	}
}

func TestWeightedAndNumericMultisig(t *testing.T) {
	id, icp := incept(t, "w", 3, json.RawMessage(`["1/2","1/2","1/2"]`), nil, nil, nil)
	signers := id.chain.Signers()
	ixn := id.interact()
	one := forge(t, ixn, signers[0])
	res := process(t, icp, one, ixn)
	assertReadings(t, res, "seen/seen/trunk", "rejected/rejected/off", "seen/seen/trunk")
	if asJSON(keyState(t, res, id.prefix)["kt"]) != `["1/2","1/2","1/2"]` {
		t.Fatalf("%v", keyState(t, res, id.prefix))
	}

	n, icpN := incept(t, "n", 3, json.RawMessage(`"2"`), nil, nil, nil)
	res = process(t, icpN)
	if keyState(t, res, n.prefix)["kt"] != "2" {
		t.Fatalf("%v", res["key_states"])
	}
}

func TestAWitnessedEventNeedsItsThresholdOfReceipts(t *testing.T) {
	wits, sigs := witnesses(t, 3)
	two := 2
	id, icp := incept(t, "a", 1, nil, wits, sigs, &two)
	short := id.receipted(icp, wits[0])
	enough := id.receipted(icp, wits[0], wits[2])
	res := process(t, icp, short, enough)
	assertReadings(t, res, "rejected/rejected/off", "rejected/rejected/off", "seen/seen/trunk")
	ks := keyState(t, res, id.prefix)
	if asJSON(ks["wits"]) != asJSON(wits) || ks["bt"] != "2" {
		t.Fatalf("%v", ks)
	}

	ixn := id.interact()
	res = process(t, enough, ixn, id.receipted(ixn, wits[1]), id.receipted(ixn, wits[1], wits[2]))
	assertReadings(t, res, "seen/seen/trunk", "rejected/rejected/off", "rejected/rejected/off", "seen/seen/trunk")
}

func TestARotationCutsAndAddsWitnesses(t *testing.T) {
	wits, sigs := witnesses(t, 3)
	one := 1
	id, icp := incept(t, "a", 1, nil, wits[:2], sigs, &one)
	rot := id.rotate([]string{wits[0]}, []string{wits[2]}, &one)
	id.wits = []string{wits[1], wits[2]}
	res := process(t, id.receipted(icp, wits[0]), id.receipted(rot, wits[2]))
	assertReadings(t, res, "seen/seen/trunk", "seen/seen/trunk")
	if asJSON(keyState(t, res, id.prefix)["wits"]) != asJSON([]string{wits[1], wits[2]}) {
		t.Fatalf("%v", keyState(t, res, id.prefix))
	}
	// A receipt from the witness the rotation cut does not count.
	res = process(t, id.receipted(icp, wits[0]), id.receipted(rot, wits[0]))
	assertReadings(t, res, "seen/seen/trunk", "rejected/rejected/off")
}

func TestMessagesTheAdapterDoesNotRouteAreRejected(t *testing.T) {
	id, icp := incept(t, "a", 1, nil, nil, nil, nil)
	rct := must(keri.BuildReceipt(keri.ReceiptInput{Prefix: id.prefix, SN: 0, EventSAID: id.said}))
	dip := []byte(`{"v":"KERI10JSON00003d_","t":"dip","i":"EAbc","s":"0"}-AAA`)
	unknown := []byte(`{"v":"KERI10JSON00003d_","t":"zzz","i":"EAbc","s":"0"}-AAA`)
	notHex := []byte("{}")
	twoMessages := append(append([]byte(nil), icp...), icp...)
	prefixed := append([]byte("-_AAACAA"), icp...)
	noType := []byte(`{"v":"KERI10JSON00003d_","i":"EAbc","s":"0"}-AAA`)
	truncated := icp[:len(icp)-2]
	res := process(t, icp, rct, dip, unknown, notHex, twoMessages, prefixed, noType, truncated)
	assertReadings(t, res, "seen/seen/trunk", "rejected/rejected/off", "rejected/rejected/off", "rejected/rejected/off", "rejected/rejected/off",
		"rejected/rejected/off", "rejected/rejected/off", "rejected/rejected/off", "rejected/rejected/off")
	for i, d := range res["dispositions"].([]any)[1:] {
		if d.(map[string]any)["reason"] == "" {
			t.Fatalf("message %d has no reason", i+1)
		}
	}
}

func TestMalformedProcessRequests(t *testing.T) {
	for _, line := range []string{
		`{"id":3,"op":"keri.process"}`,
		`{"id":3,"op":"keri.process","messages":{}}`,
		`{"id":3,"op":"keri.process","messages":[{"source":"x"}]}`,
		`{"id":3,"op":"keri.process","messages":[{"stream":"zz"}]}`,
		`{"id":3,"op":"keri.process","messages":[7]}`,
	} {
		kind, msg := errorOf(t, answer(t, line))
		if kind != "harness" || !strings.HasPrefix(msg, eMalformed+": ") {
			t.Fatalf("%s: got %s %q", line, kind, msg)
		}
	}
}

func TestAnEmptyDeliveryListHasNoDispositions(t *testing.T) {
	res := process(t)
	if len(res["dispositions"].([]any)) != 0 || len(res["key_states"].(map[string]any)) != 0 {
		t.Fatalf("%v", res)
	}
}
