package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	keri "github.com/grapeid/keri-go"
)

// keri.process, composed. keri-go has no per-message processor: ValidateSignedKEL judges a whole
// log. The adapter supplies the routing (declared in composes as keri.routing): it keeps, per
// identifier, the messages seen so far, and a delivered key event is seen exactly when keri-go
// accepts that log with the event in its place, and, when the identifier is witnessed, when
// keri-go counts enough receipts attached to the event. Nothing is escrowed and nothing is
// superseded, so a reading never changes after delivery, and everything the adapter does not
// route is rejected rather than judged by adapter code.

// routing prefixes the reason of every rejection the adapter makes itself, rather than keri-go.
const routing = "refused by the adapter's routing, not by keri-go: "

// kelLog is one identifier's seen messages, in sequence-number order.
type kelLog struct {
	messages [][]byte
	events   []*keri.Event
}

type validator struct {
	logs  map[string]*kelLog
	order []string
}

type disposition struct {
	Initial string `json:"initial"`
	Final   string `json:"final"`
	Trunk   bool   `json:"trunk"`
	Reason  string `json:"reason,omitempty"`
}

func processOp(request map[string]json.RawMessage) (any, *opError) {
	var messages []struct {
		Stream json.RawMessage `json:"stream"`
	}
	if err := json.Unmarshal(request["messages"], &messages); err != nil || messages == nil {
		return nil, harness(eMalformed, "\"messages\" must be a list of {stream, source} objects.")
	}
	streams := make([][]byte, len(messages))
	for i, m := range messages {
		raw, bad := hexField(map[string]json.RawMessage{"stream": m.Stream}, "stream")
		if bad != nil {
			return nil, bad
		}
		streams[i] = raw
	}
	v := &validator{logs: map[string]*kelLog{}}
	dispositions := make([]disposition, len(streams))
	for i, s := range streams {
		if reason := v.deliver(s); reason != "" {
			dispositions[i] = disposition{"rejected", "rejected", false, reason}
		} else {
			dispositions[i] = disposition{"seen", "seen", true, ""}
		}
	}
	return map[string]any{"dispositions": dispositions, "key_states": v.keyStates()}, nil
}

// deliver routes one message and returns why it was not seen, or "" if it was.
func (v *validator) deliver(raw []byte) string {
	split, err := keri.ParseKELStream(raw)
	if err != nil {
		return "keri-go's ParseKELStream refused the message: " + err.Error()
	}
	if len(split) != 1 {
		return fmt.Sprintf("the delivery holds %d messages, and a delivery is one message", len(split))
	}
	if _, _, err := keri.DetectVersion(raw); err != nil {
		return "keri-go's DetectVersion refused the message: " + err.Error()
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return "keri-go's ParseEvent refused the message: " + err.Error()
	}
	switch ev.Ilk {
	case "icp", "rot", "ixn":
	case "dip", "drt":
		return routing + "delegated events are not routed (kel.delegation is not declared)"
	default:
		return fmt.Sprintf("%sa %q is not a key event this adapter routes", routing, ev.Ilk)
	}

	log := v.logs[ev.Identifier]
	if log == nil {
		log = &kelLog{}
	}
	prior := log.messages
	occupied := ev.SN < uint64(len(log.events))
	if occupied {
		prior = log.messages[:ev.SN]
	}
	candidate := append(append([][]byte(nil), prior...), raw)
	if _, err := keri.ValidateSignedKEL(candidate); err != nil {
		return "keri-go's ValidateSignedKEL refused the log with this event: " + err.Error()
	}
	if reason := witnessed(raw, ev, log.events[:len(prior)]); reason != "" {
		return reason
	}
	// keri-go accepts this event in its place. If a different seen event already holds that
	// place, keri-go has no rule for choosing between the two, and the adapter supersedes nothing.
	if occupied && log.events[ev.SN].SAID != ev.SAID {
		return fmt.Sprintf("%skeri-go accepts this event at sequence number %d, which already "+
			"holds the seen event %s, and the adapter supersedes nothing", routing, ev.SN,
			log.events[ev.SN].SAID)
	}
	if len(prior) == len(log.events) {
		if len(log.events) == 0 {
			v.logs[ev.Identifier] = log
			v.order = append(v.order, ev.Identifier)
		}
		log.messages = append(log.messages, raw)
		log.events = append(log.events, ev)
	}
	return ""
}

// witnessed checks an event against the witness threshold in force once it is applied, with
// keri-go's ReceiptsMeetThreshold counting the receipt couples attached to it.
func witnessed(raw []byte, ev *keri.Event, before []*keri.Event) string {
	wits, toad := witnessState(append(append([]*keri.Event(nil), before...), ev))
	if toad == 0 {
		return ""
	}
	// ReceiptsMeetThreshold verifies receipts over the event's own bytes, which it takes without
	// attachments. ValidateSignedKEL has already checked that the version string's size is the
	// length of the body keri-go framed, so that size marks where the body ends.
	// Neither call below can fail on an event ValidateSignedKEL accepted; if one did, the count
	// would be zero and the event rejected.
	var vs string
	_ = json.Unmarshal(fields(ev)["v"], &vs)
	_, _, size, _ := keri.ParseVersionString(vs)
	count, _, _ := keri.ReceiptsMeetThreshold(raw, raw[:size], wits)
	if uint64(count) < toad {
		return fmt.Sprintf("%d of the %d witness receipts the threshold requires are attached and "+
			"verify, and this adapter escrows nothing", count, toad)
	}
	return ""
}

// witnessState replays the witness list and threshold through a log's establishment events.
func witnessState(events []*keri.Event) ([]string, uint64) {
	wits := []string{}
	var toad uint64
	for _, e := range events {
		switch e.Ilk {
		case "icp":
			wits = append([]string{}, e.Witnesses...)
		case "rot":
			cut := map[string]bool{}
			for _, w := range e.WitnessCut {
				cut[w] = true
			}
			kept := []string{}
			for _, w := range wits {
				if !cut[w] {
					kept = append(kept, w)
				}
			}
			wits = append(kept, e.WitnessAdd...)
		}
		if e.HasTOAD {
			toad = e.TOAD
		}
	}
	return wits, toad
}

func (v *validator) keyStates() map[string]any {
	out := map[string]any{}
	for _, id := range v.order {
		events := v.logs[id].events
		last := events[len(events)-1]
		var est *keri.Event
		for _, e := range events {
			if e.Establishment() {
				est = e
			}
		}
		wits, toad := witnessState(events)
		f := fields(est)
		out[id] = map[string]any{
			"sn": last.SN, "said": last.SAID,
			"keys": est.Keys, "kt": threshold(f["kt"]),
			"ndigs": append([]string{}, est.NextDigest...), "nt": threshold(f["nt"]),
			"wits": wits, "bt": strconv.FormatUint(toad, 16),
			"delegator": nil,
		}
	}
	return out
}

// fields are an event's top-level fields as keri-go's ParseEvent read them, by name.
func fields(e *keri.Event) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, f := range e.Fields {
		out[f.Name] = f.Value
	}
	return out
}

// threshold is a kt or nt value as keri-go read it: a hex string or nested lists of fractions.
func threshold(raw json.RawMessage) any {
	var v any
	_ = json.Unmarshal(raw, &v)
	return v
}
