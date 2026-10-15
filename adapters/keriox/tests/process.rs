//! keri.process against keri-core 0.17.13: each message's readings and every key state, as
//! keri-core's own processor, escrows and tables give them. The fixtures are keripy 1.2.14 KELs
//! from the 2026-09 Rust survey's corpus, plus a keriox-built witnessed KEL with separate receipts
//! and a keripy 1.2.14 transferable receipt; tests/fixtures/kel/README.md says where each came from.
//!
//! Where keri-core's answer differs from keripy's, the test pins keri-core's answer and says so,
//! so that a change in keri-core shows up here rather than silently in the results.

use std::process::{Command, Stdio};

use kcs_adapter_keriox::kel::{process, E_STORAGE};
use kcs_adapter_keriox::protocol::{handle_line, E_PERSPECTIVE};
use serde_json::{json, Value};

/// The messages of a fixture, split before each KERI 1.0 body.
fn messages(name: &str) -> Vec<Vec<u8>> {
    let path = format!(
        "{}/tests/fixtures/kel/{name}.cesr",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let marker = br#"{"v":"KERI10"#;
    let starts: Vec<usize> = (0..raw.len())
        .filter(|&i| raw[i..].starts_with(marker))
        .collect();
    assert_eq!(starts.first(), Some(&0), "{name} starts with a body");
    starts
        .iter()
        .zip(starts.iter().skip(1).chain(std::iter::once(&raw.len())))
        .map(|(&a, &b)| raw[a..b].to_vec())
        .collect()
}

fn run(streams: Vec<Vec<u8>>) -> Value {
    process(streams).expect("a result")
}

/// Each disposition as "<initial> <final> <trunk>", for compact comparison.
fn readings(result: &Value) -> Vec<String> {
    result["dispositions"]
        .as_array()
        .expect("dispositions")
        .iter()
        .map(|d| {
            format!(
                "{} {} {}",
                d["initial"].as_str().unwrap(),
                d["final"].as_str().unwrap(),
                d["trunk"]
            )
        })
        .collect()
}

fn reason(result: &Value, message: usize) -> String {
    result["dispositions"][message]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

const SEEN: &str = "seen seen true";

const BASIC: &str = "ENezN4Mwtje2ehG9q44RAJfqmxq_XQFd38FbTACtxINb";

#[test]
fn a_valid_kel_is_seen_on_the_trunk_with_keri_cores_key_state() {
    let result = run(messages("kel-basic"));
    assert_eq!(readings(&result), vec![SEEN; 5]);
    for d in result["dispositions"].as_array().unwrap() {
        assert!(d.get("reason").is_none(), "{d}");
    }
    let states = result["key_states"].as_object().unwrap();
    assert_eq!(states.len(), 1);
    let state = &states[BASIC];
    assert_eq!(state["sn"], 4);
    assert!(state["said"].as_str().unwrap().starts_with("ECKMme_lBb"));
    assert_eq!(state["kt"], "1");
    assert_eq!(state["nt"], "1");
    assert_eq!(state["keys"].as_array().unwrap().len(), 1);
    assert_eq!(state["ndigs"].as_array().unwrap().len(), 1);
    assert_eq!(state["wits"], json!([]));
    assert_eq!(state["bt"], "0");
    assert_eq!(state["delegator"], Value::Null);
    assert_eq!(state.as_object().unwrap().len(), 9);
}

#[test]
fn every_request_starts_from_an_empty_validator() {
    let kel = messages("kel-basic");
    run(kel.clone());
    // A rot for an identifier this validator has never seen; keri-core refuses it outright.
    let result = run(vec![kel[1].clone()]);
    assert_eq!(readings(&result), vec!["rejected rejected false"]);
    assert_eq!(result["key_states"], json!({}));
}

#[test]
fn an_event_ahead_of_its_prior_is_held_out_of_order_and_accepted_when_the_prior_arrives() {
    let kel = messages("kel-basic");
    let reordered = vec![
        kel[0].clone(),
        kel[2].clone(),
        kel[1].clone(),
        kel[3].clone(),
        kel[4].clone(),
    ];
    let result = run(reordered);
    assert_eq!(
        readings(&result),
        vec![SEEN, "pending seen true", SEEN, SEEN, SEEN]
    );
    // The final reading carries no escrow reason once the event is seen.
    assert_eq!(reason(&result, 1), "");
    assert_eq!(result["key_states"][BASIC]["sn"], 4);
}

#[test]
fn keri_core_drops_an_event_for_an_identifier_it_has_not_seen_rather_than_escrowing_it() {
    // keripy escrows the early rot and ends at sn 4; keri-core refuses it ("Prefix does not
    // match"), so the later events wait out of order for an sn 1 that never comes (survey D1).
    let kel = messages("kel-basic");
    let mut reordered = vec![kel[1].clone(), kel[0].clone()];
    reordered.extend(kel[2..].iter().cloned());
    let result = run(reordered);
    assert_eq!(
        readings(&result),
        vec![
            "rejected rejected false",
            SEEN,
            "pending pending false",
            "pending pending false",
            "pending pending false",
        ]
    );
    assert!(
        reason(&result, 0).contains("Prefix does not match"),
        "{result}"
    );
    assert_eq!(reason(&result, 2), "out of order");
    assert_eq!(result["key_states"][BASIC]["sn"], 0);
}

#[test]
fn an_unsatisfied_partial_rotation_is_held_as_partially_signed() {
    let result = run(messages("kel-partial-rotation-unsatisfied"));
    assert_eq!(readings(&result), vec![SEEN, SEEN, "pending pending false"]);
    assert_eq!(reason(&result, 2), "partially signed");
}

#[test]
fn a_weighted_threshold_is_reported_as_keri_core_holds_it() {
    let result = run(messages("kel-weighted-multisig"));
    assert_eq!(readings(&result), vec![SEEN; 3]);
    let state = result["key_states"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert!(state["kt"].is_array(), "{state}");
    assert!(state["nt"].is_array(), "{state}");
}

#[test]
fn a_non_transferable_inception_is_seen() {
    let result = run(messages("kel-nontrans"));
    assert_eq!(readings(&result), vec![SEEN]);
    let state = &result["key_states"]["BNVDXq5kAIzLKy3DKCdL5FmiuvXZHiBNH5z9ZZVdgUwG"];
    assert_eq!(state["sn"], 0);
    assert_eq!(state["ndigs"], json!([]));
}

const DELEGATOR: &str = "EO0rCUsgl9HGMXu7-uMOOY189GdwpL4DGF4uaHPb1RhW";
const DELEGATE: &str = "ELAFBqpCp2y8Ru6LGUXKNudNajxytvaf69o4LT2MUElW";

#[test]
fn a_delegated_kel_is_seen_after_its_delegator_and_names_its_delegator() {
    let mut kel = messages("kel-delegator");
    kel.extend(messages("kel-delegate"));
    let result = run(kel);
    assert_eq!(readings(&result), vec![SEEN; 6]);
    assert_eq!(result["key_states"][DELEGATE]["delegator"], DELEGATOR);
    assert_eq!(result["key_states"][DELEGATE]["sn"], 2);
    assert_eq!(result["key_states"][DELEGATOR]["sn"], 2);
}

#[test]
fn a_delegated_inception_waits_for_its_anchoring_seal() {
    let delegator = messages("kel-delegator");
    let delegate = messages("kel-delegate");
    let result = run(vec![delegator[0].clone(), delegate[0].clone()]);
    assert_eq!(readings(&result), vec![SEEN, "pending pending false"]);
    assert_eq!(reason(&result, 1), "awaiting delegation");
    let result = run(vec![
        delegator[0].clone(),
        delegate[0].clone(),
        delegator[1].clone(),
    ]);
    assert_eq!(readings(&result), vec![SEEN, "pending seen true", SEEN]);
}

#[test]
fn keri_core_accepts_a_delegated_rotation_without_its_anchoring_seal() {
    // The drt's source seal names the delegator's rot at sn 2, which is never delivered, so
    // keripy holds the drt. keri-core 0.17.13 deserializes every drt body as a plain rotation
    // (EventData is an untagged enum and Rot precedes Drt), so it never checks the delegating
    // seal and accepts the drt at once. ~3bpx
    let delegator = messages("kel-delegator");
    let delegate = messages("kel-delegate");
    let result = run(vec![
        delegator[0].clone(),
        delegate[0].clone(),
        delegator[1].clone(),
        delegate[1].clone(),
    ]);
    assert_eq!(
        readings(&result),
        vec![SEEN, "pending seen true", SEEN, SEEN]
    );
    assert_eq!(result["key_states"][DELEGATOR]["sn"], 1);
    assert_eq!(result["key_states"][DELEGATE]["sn"], 1);
}

#[test]
fn keri_core_cannot_parse_a_delegated_event_inside_an_attachment_frame() {
    // keripy's replay wraps each event's attachments in -V; keri-core reads the delegator's
    // events but refuses the dip's frame (survey D2), so the delegate is never seen.
    let result = run(messages("kel-delegated-replay"));
    let got = readings(&result);
    assert_eq!(&got[..3], &[SEEN, SEEN, SEEN]);
    assert_eq!(got[3], "rejected rejected false");
    assert!(reason(&result, 3).starts_with("keri-core cannot parse the stream"));
    assert!(result["key_states"].get(DELEGATE).is_none());
}

#[test]
fn an_under_receipted_inception_is_held_as_partially_witnessed() {
    let result = run(messages("kel-witnessed-underreceipted"));
    assert_eq!(readings(&result), vec!["pending pending false"]);
    assert_eq!(reason(&result, 0), "partially witnessed");
}

const WITNESSED: &str = "EMFHFLMIzVjuNqGeKMfMZVsfygEkNAikhaVWQ1UFMaYN";

#[test]
fn a_witness_receipt_completes_its_event_and_is_seen_but_never_on_the_trunk() {
    let result = run(messages("keriox-witnessed-rct"));
    assert_eq!(
        readings(&result),
        vec![
            "pending seen true",
            "seen seen false",
            "pending seen true",
            "seen seen false"
        ]
    );
    assert_eq!(result["key_states"][WITNESSED]["sn"], 1);
    assert_eq!(result["key_states"][WITNESSED]["bt"], "2");
    assert_eq!(
        result["key_states"][WITNESSED]["wits"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn a_receipt_ahead_of_its_event_is_held_and_seen_once_the_event_arrives() {
    let kel = messages("keriox-witnessed-rct");
    let result = run(vec![kel[1].clone()]);
    assert_eq!(readings(&result), vec!["pending pending false"]);
    assert_eq!(reason(&result, 0), "receipt of an event not yet accepted");
    let result = run(vec![kel[1].clone(), kel[0].clone()]);
    assert_eq!(
        readings(&result),
        vec!["pending seen false", "seen seen true"]
    );
}

/// A copy of `stream` with the character at `at` changed, to break a signature.
fn tampered(stream: &[u8], at: usize) -> Vec<u8> {
    let mut copy = stream.to_vec();
    copy[at] = if copy[at] == b'A' { b'B' } else { b'A' };
    copy
}

#[test]
fn a_receipt_whose_signatures_do_not_verify_is_rejected() {
    let kel = messages("keriox-witnessed-rct");
    let rct = &kel[1];
    let forged = tampered(rct, rct.len() - 10);
    let result = run(vec![kel[0].clone(), forged]);
    assert_eq!(
        readings(&result),
        vec!["pending pending false", "rejected rejected false"]
    );
}

#[test]
fn a_transferable_receipt_from_a_known_validator_is_seen() {
    let basic = messages("kel-basic");
    let validator = messages("validator-icp");
    let vrc = messages("vrc-basic-icp");
    let result = run(vec![basic[0].clone(), validator[0].clone(), vrc[0].clone()]);
    assert_eq!(readings(&result), vec![SEEN, SEEN, "seen seen false"]);
}

#[test]
fn a_transferable_receipt_keri_core_cannot_verify_is_rejected() {
    let basic = messages("kel-basic");
    let validator = messages("validator-icp");
    let vrc = messages("vrc-basic-icp");
    // keri-core has no escrow for a receipt from a validator it has not seen.
    let result = run(vec![basic[0].clone(), vrc[0].clone()]);
    assert_eq!(readings(&result), vec![SEEN, "rejected rejected false"]);
    let forged = tampered(&vrc[0], vrc[0].len() - 10);
    let result = run(vec![basic[0].clone(), validator[0].clone(), forged]);
    assert_eq!(
        readings(&result),
        vec![SEEN, SEEN, "rejected rejected false"]
    );
}

#[test]
fn a_second_interaction_at_the_same_sequence_number_is_duplicitous() {
    let result = run(messages("kel-duplicitous"));
    assert_eq!(
        readings(&result),
        vec![SEEN, SEEN, "duplicitous duplicitous false"]
    );
    assert!(result["key_states"]
        .as_object()
        .unwrap()
        .values()
        .all(|s| s["sn"] == 1));
}

#[test]
fn keri_core_has_no_superseding_recovery_and_files_the_rotation_as_duplicitous() {
    // keripy accepts the rot at sn 1 and leaves the two ixns seen off the trunk; keri-core keeps
    // them on its trunk and files the rot as duplicitous (survey D3).
    let result = run(messages("kel-recovery"));
    assert_eq!(
        readings(&result),
        vec![SEEN, SEEN, SEEN, "duplicitous duplicitous false"]
    );
}

#[test]
fn an_event_with_a_bad_signature_is_rejected_with_keri_cores_reason() {
    let result = run(messages("kel-bad-signature"));
    assert_eq!(
        readings(&result),
        vec![SEEN, SEEN, SEEN, "rejected rejected false"]
    );
    assert!(reason(&result, 3).contains("Signature"), "{result}");
}

#[test]
fn a_stream_keri_core_cannot_read_is_rejected() {
    let result = run(vec![b"not a KERI message".to_vec(), Vec::new()]);
    assert_eq!(readings(&result), vec!["rejected rejected false"; 2]);
    assert_eq!(
        reason(&result, 0),
        "keri-core found no message in the stream"
    );
    assert_eq!(result["key_states"], json!({}));
}

#[test]
fn a_stream_of_several_messages_delivers_them_all_and_reads_the_first() {
    let kel = messages("kel-basic");
    let result = run(vec![kel[..2].concat(), kel[2].clone()]);
    assert_eq!(readings(&result), vec![SEEN, SEEN]);
    assert_eq!(result["key_states"][BASIC]["sn"], 2);
}

#[test]
fn keri_process_over_the_protocol() {
    let kel = messages("kel-basic");
    let request = json!({"id": 9, "op": "keri.process", "perspective": {"role": "validator"},
                         "messages": [{"stream": hex(&kel[0]), "source": "controller"}]});
    let response: Value =
        serde_json::from_str(&handle_line(request.to_string().as_bytes())).unwrap();
    assert_eq!(response["id"], 9);
    assert_eq!(readings(&response["result"]), vec![SEEN]);
}

#[test]
fn only_a_validator_perspective_is_supported() {
    let request = r#"{"id":3,"op":"keri.process","perspective":{"role":"witness"},"messages":[]}"#;
    let response: Value = serde_json::from_str(&handle_line(request.as_bytes())).unwrap();
    assert_eq!(response["error"]["kind"], "unsupported");
    let message = response["error"]["message"].as_str().unwrap();
    assert!(message.starts_with(E_PERSPECTIVE), "{message}");
    assert!(message.contains("\"witness\""), "{message}");
}

#[test]
fn an_unusable_temporary_directory_is_a_retryable_harness_error() {
    let kel = messages("kel-basic");
    let request = json!({"id": 5, "op": "keri.process", "perspective": {"role": "validator"},
                         "messages": [{"stream": hex(&kel[0])}]});
    let output = Command::new(env!("CARGO_BIN_EXE_kcs-adapter-keriox"))
        .env("TMPDIR", "/nonexistent/kcs-keriox-test")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            writeln!(stdin, "{request}")?;
            drop(stdin);
            child.wait_with_output()
        })
        .unwrap();
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["id"], 5);
    assert_eq!(response["error"]["kind"], "harness");
    let message = response["error"]["message"].as_str().unwrap();
    assert!(message.starts_with(E_STORAGE), "{message}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
