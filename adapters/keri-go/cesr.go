package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	keri "github.com/grapeid/keri-go"
)

// Rejection classes: the keri-go function that refused the stream.
const (
	classParse   = "ParseKELStream"
	classVersion = "DetectVersion"
)

// matterQB64 is keri-go's encoder, a variable so a test can make it fail.
var matterQB64 = keri.MatterQB64

// encodable are the codes keri-go names (cesr.go): it encodes any code by the same arithmetic,
// but only these are codes it knows, so only these are offered.
var encodable = map[string]bool{
	keri.CodeBlake3_256:  true,
	keri.CodeEd25519:     true,
	keri.CodeEd25519N:    true,
	keri.CodeEd25519Sig:  true,
	keri.CodeEd25519Seed: true,
}

func hexField(request map[string]json.RawMessage, field string) ([]byte, *opError) {
	// A pointer, because JSON null decodes into a string as "" without error.
	var value *string
	if err := json.Unmarshal(request[field], &value); err != nil || value == nil {
		return nil, harness(eMalformed, "%q must be a lowercase hex string.", field)
	}
	text := *value
	for _, c := range text {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return nil, harness(eMalformed, "%q must be a lowercase hex string.", field)
		}
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return nil, harness(eMalformed, "%q must be a lowercase hex string.", field)
	}
	return raw, nil
}

// parseOp gives keri-go's verdict on a stream. keri-go's stream reader, ParseKELStream, splits a
// stream into messages and measures their attachment groups, and DetectVersion reads each
// message's version string. Either refusing is a rejection; otherwise the stream is accepted, and
// because keri-go reports no item offsets the answer is the protocol's summary.
func parseOp(request map[string]json.RawMessage) (any, *opError) {
	stream, bad := hexField(request, "stream")
	if bad != nil {
		return nil, bad
	}
	messages, err := keri.ParseKELStream(stream)
	if err != nil {
		return reject(classParse, err), nil
	}
	for _, m := range messages {
		if _, _, err := keri.DetectVersion(m); err != nil {
			return reject(classVersion, err), nil
		}
	}
	// ParseKELStream reads to the end of the stream or refuses it, so it consumed all of it.
	return map[string]any{"accepted": map[string]int{"consumed": len(stream)}}, nil
}

func reject(class string, why error) any {
	fmt.Fprintf(os.Stderr, "rejected by %s: %v\n", class, why)
	return map[string]any{"reject": map[string]string{"class": class}}
}

func encodeOp(request map[string]json.RawMessage) (any, *opError) {
	var code, domain string
	if json.Unmarshal(request["code"], &code) != nil || code == "" {
		return nil, harness(eMalformed, "\"code\" must be a non-empty string.")
	}
	if json.Unmarshal(request["domain"], &domain) != nil || (domain != "text" && domain != "binary") {
		return nil, harness(eMalformed, "\"domain\" must be \"text\" or \"binary\".")
	}
	raw, bad := hexField(request, "raw")
	if bad != nil {
		return nil, bad
	}
	if domain == "binary" {
		return nil, unsupported(eBinaryDomain, "keri-go encodes in the text domain only.")
	}
	if !encodable[code] {
		return nil, unsupported(eUnknownCode, "keri-go names no code %q.", code)
	}
	qb64, err := matterQB64(code, raw)
	if err != nil {
		return nil, unsupported(eEncodeRefused, "keri-go refused to encode: %v", err)
	}
	return map[string]string{"encoded": hex.EncodeToString([]byte(qb64))}, nil
}
