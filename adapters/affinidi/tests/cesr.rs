//! cesr.parse and cesr.encode against Affinidi. The vectors are keripy-produced KERI 1.0 bytes,
//! written out here so this crate stays self-contained.

use kcs_adapter_affinidi::cesr;
use kcs_adapter_affinidi::protocol::{OpError, handle_line};
use serde_json::{Value, json};

/// A keripy KERI 1.0 JSON inception, 299 bytes, framed by `KERI10JSON00012b_`.
const ICP: &str = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","i":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","s":"0","kt":"1","k":["DPFk75lB_TCllSQXTjv6jdGHX7wuds-JNfsVHeJdRi-p"],"nt":"1","n":["EIMUgrgEee9DvExWqJTtUB-g-OiybftXfWNuqMO-FGXQ"],"bt":"0","b":[],"c":[],"a":[]}"#;
/// Its 1.00 `-A` group of two Ed25519 indexed signatures.
const SIGS: &str = "-AACAABf2cU3-Kq8uockoXWwzLU68GE8M1cvOt1532moMq5axyInXDxQ20ru5A_D2oZ9ab9kSRkHSOlkRYpIpCbi5xYHABC9PqgmFCHjj4mXiHMZFR04LFyLiyZVl9f7f4ZGVfnPQ1GQ6z-XjoA3Jop4KqDv5GyX61Mt4Uj8WQ9dhcTDhJ4_";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse(stream: &[u8]) -> Value {
    handle_line(
        &serde_json::to_vec(&json!({"id": 1, "op": "cesr.parse", "stream": hex(stream)})).unwrap(),
    )
}

fn summary(consumed: usize) -> Value {
    json!({"id": 1, "result": {"accepted": {"consumed": consumed}}})
}

fn rejection_class(response: &Value) -> String {
    response["result"]["reject"]["class"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string()
}

// The adapter does not declare cesr.item-extents: Affinidi's parser does not say where each item
// lay, so every stream it accepts is answered with the protocol's summary, never with items.

#[test]
fn an_empty_stream_is_accepted_with_nothing_consumed() {
    assert_eq!(parse(b""), summary(0));
}

#[test]
fn a_bare_body_is_accepted_whole() {
    assert_eq!(parse(ICP.as_bytes()), summary(299));
}

#[test]
fn consecutive_bodies_are_consumed_one_after_another() {
    assert_eq!(parse(format!("{ICP}{ICP}{ICP}").as_bytes()), summary(897));
}

#[test]
fn a_stream_affinidi_accepts_with_attachments_is_summarized_not_unsupported() {
    let stream = format!("{ICP}{SIGS}");
    assert_eq!(parse(stream.as_bytes()), summary(stream.len()));
}

#[test]
fn attachments_on_a_later_message_are_summarized_too() {
    let stream = format!("{ICP}{ICP}{SIGS}");
    assert_eq!(parse(stream.as_bytes()), summary(stream.len()));
}

#[test]
fn an_empty_quadlet_group_is_consumed() {
    // -VAA: a 1.00 attachment group of zero quadlets. Affinidi consumes it but decodes no group.
    assert_eq!(parse(format!("{ICP}-VAA").as_bytes()), summary(303));
}

#[test]
fn whitespace_affinidi_skips_between_messages_counts_as_consumed() {
    assert_eq!(parse(format!("{ICP} {ICP}").as_bytes()), summary(599));
    assert_eq!(parse(format!("{ICP}\n").as_bytes()), summary(300));
}

#[test]
fn rejections_carry_affinidis_error_class() {
    // A genus/version code at the start of the stream: Affinidi does not read genus codes.
    let genus = format!("-_AAACAA{ICP}");
    assert_eq!(
        rejection_class(&parse(genus.as_bytes())),
        "CoreError::ParseError"
    );
    // A body cut short of its declared size.
    assert_eq!(
        rejection_class(&parse(&ICP.as_bytes()[..200])),
        "CoreError::ParseError"
    );
    // A stream that ends inside a signature.
    let cut = format!("{ICP}{}", &SIGS[..100]);
    assert_eq!(
        rejection_class(&parse(cut.as_bytes())),
        "CoreError::ParseError"
    );
    // Binary bytes where an attachment is expected.
    let binary = [ICP.as_bytes(), &[0x2d, 0xff, 0x00]].concat();
    assert!(rejection_class(&parse(&binary)).starts_with("CoreError::"));
}

#[test]
fn a_reject_anywhere_in_the_stream_wins_over_earlier_unreportable_messages() {
    let stream = format!("{ICP}{SIGS}{}", &ICP[..100]);
    assert_eq!(
        rejection_class(&parse(stream.as_bytes())),
        "CoreError::ParseError"
    );
}

#[test]
fn class_of_names_the_variant() {
    #[derive(Debug)]
    #[allow(dead_code)]
    enum E {
        Unit,
        Tuple(u8),
        Struct { a: u8 },
    }
    assert_eq!(cesr::class_of("E", &E::Unit), "E::Unit");
    assert_eq!(cesr::class_of("E", &E::Tuple(1)), "E::Tuple");
    assert_eq!(cesr::class_of("E", &E::Struct { a: 1 }), "E::Struct");
}

fn encode(code: &str, raw: &str, domain: &str) -> Value {
    handle_line(
        &serde_json::to_vec(
            &json!({"id": 2, "op": "cesr.encode", "code": code, "raw": raw, "domain": domain}),
        )
        .unwrap(),
    )
}

const KEY: &str = "f2cefc7d5bf37693976576b8ac8cd82eb3aca234699fd7328a963463a19e55f5";

#[test]
fn encode_text_returns_the_base64_characters_as_hex() {
    let expected =
        "44504c4f5f483162383361546c325632754b794d3243367a724b4930615a5f584d6f71574e474f686e6c5831";
    assert_eq!(
        encode("D", KEY, "text"),
        json!({"id": 2, "result": {"encoded": expected}})
    );
}

#[test]
fn encode_binary_returns_the_raw_encoded_bytes() {
    assert_eq!(
        encode("D", KEY, "binary")["result"]["encoded"],
        format!("0c{KEY}")
    );
}

#[test]
fn encode_refusals_are_unsupported_errors_naming_affinidis_error() {
    for (code, raw) in [("D", "00"), ("~", KEY)] {
        let response = encode(code, raw, "text");
        assert_eq!(response["error"]["kind"], "unsupported", "{response}");
        let message = response["error"]["message"].as_str().unwrap();
        assert!(
            message.starts_with(cesr::E_ENCODE_REFUSED)
                && message.contains("CesrError::")
                && message.ends_with('.'),
            "{message}"
        );
    }
}

#[test]
fn the_operations_can_be_called_directly() {
    assert_eq!(
        cesr::parse(b"").unwrap(),
        json!({"accepted": {"consumed": 0}})
    );
    assert!(matches!(
        cesr::encode("D", vec![0], false),
        Err(OpError::Unsupported(_))
    ));
}
