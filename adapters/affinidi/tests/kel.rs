//! keri.process (docs/adapter-protocol.md): each message delivered in order to fresh state, every
//! verdict from Affinidi's Kever, and the readings and key states the adapter reports from it.

mod common;

use common::*;
use kcs_adapter_affinidi::kel::E_PERSPECTIVE;
use kcs_adapter_affinidi::protocol::{E_MALFORMED, handle_line};
use serde_json::{Value, json};

fn process(streams: &[String]) -> Value {
    let messages: Vec<Value> = streams
        .iter()
        .map(|s| json!({"stream": s, "source": "controller"}))
        .collect();
    let request = json!({"id": 7, "op": "keri.process", "perspective": {"role": "validator"},
                         "messages": messages});
    let response = handle_line(&serde_json::to_vec(&request).unwrap());
    assert_eq!(response["id"], 7, "{response}");
    response["result"].clone()
}

/// (initial, final, trunk) for each message.
fn readings(result: &Value) -> Vec<(String, String, bool)> {
    result["dispositions"]
        .as_array()
        .unwrap_or_else(|| panic!("no dispositions in {result}"))
        .iter()
        .map(|d| {
            (
                d["initial"].as_str().unwrap().to_string(),
                d["final"].as_str().unwrap().to_string(),
                d["trunk"].as_bool().unwrap(),
            )
        })
        .collect()
}

fn seen() -> (String, String, bool) {
    ("seen".into(), "seen".into(), true)
}

fn rejected() -> (String, String, bool) {
    ("rejected".into(), "rejected".into(), false)
}

fn reason(result: &Value, i: usize) -> String {
    result["dispositions"][i]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn an_inception_is_seen_and_its_key_state_reported() {
    let (k0, k1) = (signer(1), signer(2));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let pre = said(&icp);
    let result = process(&[stream(&icp, &[sigs(&icp, &[(&k0, 0)])])]);
    assert_eq!(readings(&result), vec![seen()]);
    assert!(
        result["dispositions"][0].get("reason").is_none(),
        "{result}"
    );
    assert_eq!(
        result["key_states"],
        json!({pre.clone(): {
            "sn": 0, "said": pre, "keys": [key(&k0)], "kt": "1",
            "ndigs": [commit(&k1)], "nt": "1", "wits": [], "bt": "0", "delegator": null
        }})
    );
}

#[test]
fn a_kel_in_affinidis_rotation_form_is_seen_to_its_end() {
    let (k0, k1, k2) = (signer(1), signer(2), signer(3));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let pre = said(&icp);
    let ixn1 = ixn(&pre, 1, &pre, json!([]));
    let rot2 = rot(&pre, 2, &said(&ixn1), &[&k1], &[&k2], true);
    let ixn3 = ixn(&pre, 3, &said(&rot2), json!([]));
    let result = process(&[
        stream(&icp, &[sigs(&icp, &[(&k0, 0)])]),
        stream(&ixn1, &[sigs(&ixn1, &[(&k0, 0)])]),
        stream(&rot2, &[sigs(&rot2, &[(&k1, 0)])]),
        stream(&ixn3, &[sigs(&ixn3, &[(&k1, 0)])]),
    ]);
    assert_eq!(readings(&result), vec![seen(); 4]);
    let state = &result["key_states"][&pre];
    assert_eq!(state["sn"], 3);
    assert_eq!(state["said"], json!(said(&ixn3)));
    assert_eq!(state["keys"], json!([key(&k1)]));
    assert_eq!(state["ndigs"], json!([commit(&k2)]));
}

#[test]
fn a_rotation_without_c_is_rejected_as_affinidi_rejects_it() {
    // keripy 1.x's rot has no c field; Affinidi's RotationEvent requires one.
    let (k0, k1, k2) = (signer(1), signer(2), signer(3));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let pre = said(&icp);
    let rot1 = rot(&pre, 1, &pre, &[&k1], &[&k2], false);
    let result = process(&[
        stream(&icp, &[sigs(&icp, &[(&k0, 0)])]),
        stream(&rot1, &[sigs(&rot1, &[(&k1, 0)])]),
    ]);
    assert_eq!(readings(&result), vec![seen(), rejected()]);
    assert!(reason(&result, 1).contains("`c`"), "{result}");
    assert!(!reason(&result, 1).starts_with("routing: "), "{result}");
    assert_eq!(result["key_states"][&pre]["sn"], 0);
}

#[test]
fn a_bad_signature_is_rejected_and_state_does_not_move() {
    let (k0, k1, other) = (signer(1), signer(2), signer(9));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let pre = said(&icp);
    let ixn1 = ixn(&pre, 1, &pre, json!([]));
    let result = process(&[
        stream(&icp, &[sigs(&icp, &[(&k0, 0)])]),
        stream(&ixn1, &[sigs(&ixn1, &[(&other, 0)])]),
    ]);
    assert_eq!(readings(&result), vec![seen(), rejected()]);
    assert_eq!(result["key_states"][&pre]["sn"], 0);
    assert_eq!(result["key_states"][&pre]["said"], json!(pre));
}

#[test]
fn an_unsigned_or_tampered_inception_is_rejected_and_reports_no_key_state() {
    let (k0, k1) = (signer(1), signer(2));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let mut tampered = icp.raw().to_vec();
    let at = tampered.len() - 3;
    tampered[at] = b'x';
    let mut bytes = tampered.clone();
    bytes.extend_from_slice(sigs(&icp, &[(&k0, 0)]).as_bytes());
    let result = process(&[stream(&icp, &[]), hex(&bytes)]);
    assert_eq!(readings(&result), vec![rejected(), rejected()]);
    assert_eq!(result["key_states"], json!({}));
}

#[test]
fn an_event_before_its_prior_is_rejected_for_good_without_escrow() {
    let (k0, k1) = (signer(1), signer(2));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let pre = said(&icp);
    let ixn1 = ixn(&pre, 1, &pre, json!([]));
    let result = process(&[
        stream(&ixn1, &[sigs(&ixn1, &[(&k0, 0)])]),
        stream(&icp, &[sigs(&icp, &[(&k0, 0)])]),
    ]);
    assert_eq!(readings(&result), vec![rejected(), seen()]);
    assert_eq!(result["key_states"][&pre]["sn"], 0);
}

#[test]
fn a_replayed_event_reads_seen_and_a_conflicting_one_is_rejected() {
    let (k0, k1) = (signer(1), signer(2));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let pre = said(&icp);
    let first = ixn(&pre, 1, &pre, json!([]));
    let second = ixn(&pre, 1, &pre, json!([{"d": pre.clone()}]));
    let icp_stream = stream(&icp, &[sigs(&icp, &[(&k0, 0)])]);
    let result = process(&[
        icp_stream.clone(),
        stream(&first, &[sigs(&first, &[(&k0, 0)])]),
        stream(&second, &[sigs(&second, &[(&k0, 0)])]),
        icp_stream,
    ]);
    assert_eq!(readings(&result), vec![seen(), seen(), rejected(), seen()]);
    assert_eq!(result["key_states"][&pre]["said"], json!(said(&first)));
}

#[test]
fn a_second_inception_of_a_held_prefix_is_rejected() {
    // A self-addressing prefix is the inception's own SAID, so the only second inception of a
    // held prefix is a basic one, whose prefix is its first key.
    let (k0, k1, k2) = (signer(1), signer(2), signer(3));
    let basic = |next: &Signer| {
        finish(
            json!({"v": "", "t": "icp", "d": "", "i": key(&k0), "s": "0", "kt": "1",
                   "k": [key(&k0)], "nt": "1", "n": [commit(next)], "bt": "0", "b": [],
                   "c": [], "a": []}),
            false,
        )
    };
    let (first, second) = (basic(&k1), basic(&k2));
    let result = process(&[
        stream(&first, &[sigs(&first, &[(&k0, 0)])]),
        stream(&second, &[sigs(&second, &[(&k0, 0)])]),
    ]);
    assert_eq!(readings(&result), vec![seen(), rejected()]);
    assert_eq!(
        result["key_states"][key(&k0)]["ndigs"],
        json!([commit(&k1)])
    );
}

#[test]
fn numeric_multisig_needs_its_threshold() {
    let (a, b, c) = (signer(1), signer(2), signer(3));
    let (na, nb, nc) = (signer(4), signer(5), signer(6));
    let icp = Icp {
        keys: &[&a, &b, &c],
        kt: json!("2"),
        next: &[&na, &nb, &nc],
        nt: json!("2"),
        wits: &[],
        bt: "0",
    }
    .icp();
    let one = process(&[stream(&icp, &[sigs(&icp, &[(&a, 0)])])]);
    assert_eq!(readings(&one), vec![rejected()]);
    let two = process(&[stream(&icp, &[sigs(&icp, &[(&a, 0), (&c, 2)])])]);
    assert_eq!(readings(&two), vec![seen()]);
    assert_eq!(two["key_states"][said(&icp)]["kt"], "2");
}

#[test]
fn a_numeric_threshold_is_reported_in_hex() {
    let keys: Vec<_> = (1..=10).map(signer).collect();
    let refs: Vec<&_> = keys.iter().collect();
    let icp = Icp {
        keys: &refs,
        kt: json!("10"),
        next: &refs[..1],
        nt: json!("1"),
        wits: &[],
        bt: "0",
    }
    .icp();
    let signed: Vec<_> = refs.iter().enumerate().map(|(i, s)| (*s, i)).collect();
    let result = process(&[stream(&icp, &[sigs(&icp, &signed)])]);
    assert_eq!(readings(&result), vec![seen()]);
    // Affinidi read "10" as ten, which KERI writes as hex "a".
    assert_eq!(result["key_states"][said(&icp)]["kt"], "a");
}

#[test]
fn weighted_thresholds_in_affinidis_nested_form_are_held_and_reported() {
    let (a, b, c) = (signer(1), signer(2), signer(3));
    let icp = Icp {
        keys: &[&a, &b, &c],
        kt: json!([["1/2", "1/2", "1/2"]]),
        next: &[&a],
        nt: json!([["1"]]),
        wits: &[],
        bt: "0",
    }
    .icp();
    let under = process(&[stream(&icp, &[sigs(&icp, &[(&a, 0)])])]);
    assert_eq!(readings(&under), vec![rejected()]);
    let met = process(&[stream(&icp, &[sigs(&icp, &[(&a, 0), (&b, 1)])])]);
    assert_eq!(readings(&met), vec![seen()]);
    assert_eq!(
        met["key_states"][said(&icp)]["kt"],
        json!([["1/2", "1/2", "1/2"]])
    );
    assert_eq!(met["key_states"][said(&icp)]["nt"], json!([["1"]]));
}

#[test]
fn a_flat_weighted_threshold_is_rejected_as_affinidi_rejects_it() {
    let (a, b) = (signer(1), signer(2));
    let icp = Icp {
        keys: &[&a, &b],
        kt: json!(["1/2", "1/2"]),
        next: &[&a],
        nt: json!("1"),
        wits: &[],
        bt: "0",
    }
    .icp();
    let result = process(&[stream(&icp, &[sigs(&icp, &[(&a, 0), (&b, 1)])])]);
    assert_eq!(readings(&result), vec![rejected()]);
    assert!(reason(&result, 0).contains("clause"), "{result}");
}

#[test]
fn witness_receipt_couples_attached_to_the_event_meet_its_threshold() {
    let (k0, k1) = (signer(1), signer(2));
    let (w1, w2) = (witness(11), witness(12));
    let icp = Icp {
        keys: &[&k0],
        kt: json!("1"),
        next: &[&k1],
        nt: json!("1"),
        wits: &[&w1, &w2],
        bt: "2",
    }
    .icp();
    let pre = said(&icp);
    let sig = sigs(&icp, &[(&k0, 0)]);
    let short = process(&[stream(&icp, &[sig.clone(), couples(&icp, &[&w1])])]);
    assert_eq!(readings(&short), vec![rejected()]);
    let indexed = process(&[stream(
        &icp,
        &[sig.clone(), wigs(&icp, &[(&w1, 0), (&w2, 1)])],
    )]);
    assert_eq!(
        readings(&indexed),
        vec![rejected()],
        "Affinidi does not count -B"
    );
    let met = process(&[stream(&icp, &[sig.clone(), couples(&icp, &[&w1, &w2])])]);
    assert_eq!(readings(&met), vec![seen()]);
    assert_eq!(met["key_states"][&pre]["wits"], json!([key(&w1), key(&w2)]));
    assert_eq!(met["key_states"][&pre]["bt"], "2");

    // An ixn short of receipts is not accepted on arrival, and its receipted copy is.
    let ixn1 = ixn(&pre, 1, &pre, json!([]));
    let later = process(&[
        stream(&icp, &[sig, couples(&icp, &[&w1, &w2])]),
        stream(&ixn1, &[sigs(&ixn1, &[(&k0, 0)])]),
        stream(
            &ixn1,
            &[sigs(&ixn1, &[(&k0, 0)]), couples(&ixn1, &[&w1, &w2])],
        ),
    ]);
    assert_eq!(
        readings(&later),
        vec![seen(), ("rejected".into(), "seen".into(), true), seen()]
    );
}

#[test]
fn a_receipt_message_is_never_seen_and_never_on_the_trunk() {
    let (k0, k1) = (signer(1), signer(2));
    let w1 = witness(11);
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let result = process(&[stream(&icp, &[sigs(&icp, &[(&k0, 0)])]), rct(&icp, &[&w1])]);
    assert_eq!(readings(&result), vec![seen(), rejected()]);
    assert!(reason(&result, 1).starts_with("routing: "), "{result}");
    assert!(reason(&result, 1).contains("receipt"), "{result}");
}

fn delegator_and_delegate() -> (Signer, Signer, Signer, Signer) {
    (signer(1), signer(2), signer(21), signer(22))
}

#[test]
fn a_delegated_inception_anchored_by_its_delegator_is_seen() {
    let (d0, d1, e0, e1) = delegator_and_delegate();
    let dicp = Icp::single(&[&d0], &[&d1]).icp();
    let dpre = said(&dicp);
    let dip = Icp::single(&[&e0], &[&e1]).dip(&dpre);
    let epre = said(&dip);
    let anchor = ixn(
        &dpre,
        1,
        &dpre,
        json!([{"i": epre.clone(), "s": "0", "d": epre.clone()}]),
    );
    let first_three = [
        stream(&dicp, &[sigs(&dicp, &[(&d0, 0)])]),
        stream(&anchor, &[sigs(&anchor, &[(&d0, 0)])]),
        stream(
            &dip,
            &[sigs(&dip, &[(&e0, 0)]), seal_source(1, &said(&anchor))],
        ),
    ];
    let result = process(&first_three);
    assert_eq!(readings(&result), vec![seen(); 3]);
    assert_eq!(result["key_states"][&epre]["delegator"], json!(dpre));
    assert_eq!(result["key_states"][&dpre]["delegator"], Value::Null);

    // A delegated rotation, in Affinidi's form, anchored by a later delegator event.
    let e2 = signer(23);
    let drt1 = drt(&epre, 1, &epre, &[&e1], &[&e2], &dpre);
    let anchor2 = ixn(
        &dpre,
        2,
        &said(&anchor),
        json!([{"i": epre.clone(), "s": "1", "d": said(&drt1)}]),
    );
    let mut all = first_three.to_vec();
    all.push(stream(&anchor2, &[sigs(&anchor2, &[(&d0, 0)])]));
    all.push(stream(
        &drt1,
        &[sigs(&drt1, &[(&e1, 0)]), seal_source(2, &said(&anchor2))],
    ));
    let more = process(&all);
    assert_eq!(readings(&more), vec![seen(); 5]);
    assert_eq!(more["key_states"][&epre]["keys"], json!([key(&e1)]));
}

#[test]
fn a_delegated_event_without_a_verified_anchor_is_rejected() {
    let (d0, d1, e0, e1) = delegator_and_delegate();
    let dicp = Icp::single(&[&d0], &[&d1]).icp();
    let dpre = said(&dicp);
    let dip = Icp::single(&[&e0], &[&e1]).dip(&dpre);
    let epre = said(&dip);
    let anchor = ixn(
        &dpre,
        1,
        &dpre,
        json!([{"i": epre.clone(), "s": "0", "d": epre.clone()}]),
    );
    let unanchoring = ixn(&dpre, 1, &dpre, json!([]));
    let icp_stream = stream(&dicp, &[sigs(&dicp, &[(&d0, 0)])]);
    let dip_signed = sigs(&dip, &[(&e0, 0)]);

    // The anchoring event is not signed, so it was never accepted.
    let unverified = process(&[
        icp_stream.clone(),
        stream(&anchor, &[]),
        stream(&dip, &[dip_signed.clone(), seal_source(1, &said(&anchor))]),
    ]);
    assert_eq!(readings(&unverified), vec![seen(), rejected(), rejected()]);
    assert_eq!(unverified["key_states"].as_object().unwrap().len(), 1);

    // The named delegator event anchors nothing.
    let empty = process(&[
        icp_stream.clone(),
        stream(&unanchoring, &[sigs(&unanchoring, &[(&d0, 0)])]),
        stream(
            &dip,
            &[dip_signed.clone(), seal_source(1, &said(&unanchoring))],
        ),
    ]);
    assert_eq!(readings(&empty), vec![seen(), seen(), rejected()]);

    // No seal source couple at all.
    let bare = process(&[
        icp_stream.clone(),
        stream(&anchor, &[sigs(&anchor, &[(&d0, 0)])]),
        stream(&dip, std::slice::from_ref(&dip_signed)),
    ]);
    assert_eq!(readings(&bare), vec![seen(), seen(), rejected()]);
    assert!(reason(&bare, 2).starts_with("routing: "), "{bare}");
    assert!(reason(&bare, 2).contains("seal source"), "{bare}");

    // A delegated event delivered before its delegator exists.
    let early = process(&[
        stream(&dip, &[dip_signed, seal_source(1, &said(&anchor))]),
        icp_stream,
        stream(&anchor, &[sigs(&anchor, &[(&d0, 0)])]),
    ]);
    assert_eq!(readings(&early), vec![rejected(), seen(), seen()]);
}

#[test]
fn a_delegated_rotation_needs_its_own_anchor() {
    let (d0, d1, e0, e1) = delegator_and_delegate();
    let dicp = Icp::single(&[&d0], &[&d1]).icp();
    let dpre = said(&dicp);
    let dip = Icp::single(&[&e0], &[&e1]).dip(&dpre);
    let epre = said(&dip);
    let anchor = ixn(
        &dpre,
        1,
        &dpre,
        json!([{"i": epre.clone(), "s": "0", "d": epre.clone()}]),
    );
    let e2 = signer(23);
    let drt1 = drt(&epre, 1, &epre, &[&e1], &[&e2], &dpre);
    let result = process(&[
        stream(&dicp, &[sigs(&dicp, &[(&d0, 0)])]),
        stream(&anchor, &[sigs(&anchor, &[(&d0, 0)])]),
        stream(
            &dip,
            &[sigs(&dip, &[(&e0, 0)]), seal_source(1, &said(&anchor))],
        ),
        // Points at the anchor of the dip, which does not seal this drt.
        stream(
            &drt1,
            &[sigs(&drt1, &[(&e1, 0)]), seal_source(1, &said(&anchor))],
        ),
        // No seal source couple.
        stream(&drt1, &[sigs(&drt1, &[(&e1, 0)])]),
    ]);
    assert_eq!(
        readings(&result),
        vec![seen(), seen(), seen(), rejected(), rejected()]
    );
    // A drt for a prefix with no key state.
    let orphan = process(&[stream(
        &drt1,
        &[sigs(&drt1, &[(&e1, 0)]), seal_source(1, &said(&anchor))],
    )]);
    assert_eq!(readings(&orphan), vec![rejected()]);
}

#[test]
fn streams_affinidi_cannot_read_as_one_key_event_are_rejected() {
    let (k0, k1) = (signer(1), signer(2));
    let icp = Icp::single(&[&k0], &[&k1]).icp();
    let one = stream(&icp, &[sigs(&icp, &[(&k0, 0)])]);
    let two = format!("{one}{one}");
    // A message that parses but is not a key event.
    let qry = finish(
        json!({"v": "", "t": "qry", "d": "", "i": said(&icp), "s": "0"}),
        false,
    );
    // Inceptions whose keys cannot be read: none at all, and one that is not a key.
    let keyless = finish(
        json!({"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1", "nt": "1", "n": [],
               "bt": "0", "b": [], "c": [], "a": []}),
        true,
    );
    let badkey = finish(
        json!({"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1", "k": ["Dnotakey"],
               "nt": "1", "n": [], "bt": "0", "b": [], "c": [], "a": []}),
        true,
    );
    // Bodies Affinidi frames but whose ilk, or sequence number, it cannot read.
    let no_ilk = finish(json!({"v": "", "d": "", "i": said(&icp), "s": "0"}), false);
    let no_sn = finish(
        json!({"v": "", "t": "ixn", "d": "", "i": said(&icp), "p": said(&icp), "a": []}),
        false,
    );
    let numeric_key = finish(
        json!({"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1", "k": [1],
               "nt": "1", "n": [], "bt": "0", "b": [], "c": [], "a": []}),
        true,
    );
    let no_prefix = bare(json!({"v": "", "t": "ixn", "d": said(&icp), "s": "1"}));
    let no_said = bare(json!({"v": "", "t": "ixn", "i": said(&icp), "s": "1"}));
    let streams = [
        String::new(),
        "2d4b".to_string(),
        stream(&no_prefix, &[]),
        stream(&no_said, &[]),
        stream(&no_ilk, &[]),
        stream(&no_sn, &[]),
        stream(&numeric_key, &[]),
        "7b7d".to_string(),
        two,
        stream(&qry, &[]),
        stream(&keyless, &[]),
        stream(&badkey, &[]),
    ];
    let result = process(&streams);
    assert_eq!(readings(&result), vec![rejected(); streams.len()]);
    for i in 0..streams.len() {
        assert!(!reason(&result, i).is_empty(), "{result}");
    }
    assert_eq!(result["key_states"], json!({}));
}

#[test]
fn the_request_must_name_a_validator_and_carry_hex_messages() {
    let ask = |request: Value| handle_line(&serde_json::to_vec(&request).unwrap());
    let refused = ask(json!({"id": 1, "op": "keri.process",
                             "perspective": {"role": "witness"}, "messages": []}));
    assert_eq!(refused["error"]["kind"], "unsupported", "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(E_PERSPECTIVE)
    );
    for bad in [
        json!({"id": 2, "op": "keri.process", "messages": []}),
        json!({"id": 2, "op": "keri.process", "perspective": "validator", "messages": []}),
        json!({"id": 2, "op": "keri.process", "perspective": {"role": "validator"}}),
        json!({"id": 2, "op": "keri.process", "perspective": {"role": "validator"},
               "messages": [1]}),
        json!({"id": 2, "op": "keri.process", "perspective": {"role": "validator"},
               "messages": [{"stream": "ABCD"}]}),
        json!({"id": 2, "op": "keri.process", "perspective": {"role": "validator"},
               "messages": [{"source": "x"}]}),
    ] {
        let response = ask(bad);
        assert_eq!(response["error"]["kind"], "harness", "{response}");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with(E_MALFORMED),
            "{response}"
        );
    }
    let empty = ask(
        json!({"id": 3, "op": "keri.process", "perspective": {"role": "validator"},
                           "messages": []}),
    );
    assert_eq!(
        empty["result"],
        json!({"dispositions": [], "key_states": {}})
    );
}
