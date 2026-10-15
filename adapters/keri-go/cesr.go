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
	classEncode  = "MatterQB64"
	classEvent   = "ParseEvent"
)

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
// stream into messages and measures their attachment groups, DetectVersion reads each message's
// version string, and ParseEvent reads a KERI body's fields. Any of them refusing is a rejection; otherwise the stream is accepted, and
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
		proto, _, err := keri.DetectVersion(m)
		if err != nil {
			return reject(classVersion, err), nil
		}
		// ParseEvent reads key events; an ACDC body has no reader in keri-go that takes a stream.
		if proto == keri.ProtocolKERI {
			if _, err := keri.ParseEvent(m); err != nil {
				return reject(classEvent, err), nil
			}
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
	// Every code goes to keri-go: MatterQB64 checks no code table and no raw size, and whatever it
	// answers, an encoding or a refusal, is keri-go's answer.
	qb64, err := keri.MatterQB64(code, raw)
	if err != nil {
		return reject(classEncode, err), nil
	}
	return map[string]string{"encoded": hex.EncodeToString([]byte(qb64))}, nil
}
