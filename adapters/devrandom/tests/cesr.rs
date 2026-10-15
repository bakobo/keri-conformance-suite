//! cesr.parse and cesr.encode through devrandom's CESR layer.

mod support;

use kcs_adapter_devrandom::cesr;
use serde_json::{Value, json};
use support::*;

fn ask(request: Value) -> Value {
    kcs_adapter_devrandom::protocol::handle_line(&serde_json::to_vec(&request).unwrap())
}

fn parse(stream: &[u8]) -> Value {
    let response = ask(json!({"id": 1, "op": "cesr.parse", "stream": hex(stream)}));
    response["result"].clone()
}

#[test]
fn a_kel_devrandom_frames_is_accepted_whole() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let mut stream = alice.frame(&icp);
    let ixn = alice.ixn(vec![]);
    stream.extend(bare(
        &ixn,
        &[sig_group(&alice.sigs(&ixn)), first_seen_group(1)],
    ));
    assert_eq!(
        parse(&stream),
        json!({"accepted": {"consumed": stream.len()}})
    );
    assert_eq!(parse(b""), json!({"accepted": {"consumed": 0}}));
    // A bare attachment group is a message of its own to the framer.
    let group = sig_group(&alice.sigs(&ixn));
    assert_eq!(
        parse(group.as_bytes()),
        json!({"accepted": {"consumed": group.len()}})
    );
}

#[test]
fn streams_devrandom_cannot_frame_are_rejected_with_its_error() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let whole = alice.frame(&icp);
    let w = Witness::new(30);
    let bad_couple = {
        let mut group = couple_group(&w, icp.as_bytes());
        group.replace_range(4..6, "4Z");
        bare(&icp, &[sig_group(&alice.sigs(&icp)), group])
    };
    let nested = {
        let inner = sig_group(&alice.sigs(&icp));
        let frame = |body: &str| {
            format!(
                "{}{body}",
                count(
                    ::cesr::core::counter::CounterCodeV1::AttachmentGroup,
                    u32::try_from(body.len() / 4).unwrap()
                )
            )
        };
        bare(&icp, &[frame(&frame(&inner))])
    };
    let nested_bad = {
        let mut inner = sig_group(&alice.sigs(&icp));
        inner.replace_range(4..5, "_");
        let frame = |body: &str| {
            format!(
                "{}{body}",
                count(
                    ::cesr::core::counter::CounterCodeV1::AttachmentGroup,
                    u32::try_from(body.len() / 4).unwrap()
                )
            )
        };
        bare(&icp, &[frame(&frame(&inner))])
    };
    // devrandom's CESR layer accepts a nested attachment frame; its message layer is what refuses
    // one (tests/kel.rs).
    assert_eq!(
        parse(&nested),
        json!({"accepted": {"consumed": nested.len()}})
    );
    for stream in [
        whole[..whole.len() - 1].to_vec(),
        whole[..icp.as_bytes().len() + 2].to_vec(),
        icp.as_bytes()[..10].to_vec(),
        [b"-_AAACAA".as_slice(), &whole].concat(),
        b"-".to_vec(),
        bad_couple,
        nested_bad,
    ]
    .into_iter()
    .enumerate()
    {
        let (index, stream) = stream;
        let result = parse(&stream);
        let class = result["reject"]["class"].as_str().unwrap_or_default();
        assert!(class.starts_with("ParseError::"), "{index}: {result}");
        assert!(class.len() > "ParseError::".len(), "{result}");
    }
}

#[test]
fn encode_uses_devrandoms_primitive_builder() {
    let raw = "00".repeat(32);
    let response =
        ask(json!({"id": 2, "op": "cesr.encode", "code": "E", "raw": raw, "domain": "text"}));
    assert_eq!(
        response["result"]["encoded"],
        hex(format!("E{}", "A".repeat(43)).as_bytes())
    );
    let binary = ask(
        json!({"id": 3, "op": "cesr.encode", "code": "E", "raw": "00".repeat(32), "domain": "binary"}),
    );
    assert_eq!(binary["error"]["kind"], "unsupported", "{binary}");
    assert!(
        binary["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with(cesr::E_BINARY)
    );
    // Each class is read from the error devrandom raised: its type and variant.
    for (code, raw, class) in [
        ("!?", "00".repeat(32), "ParsingError::UnknownCode"),
        ("E", "00".repeat(3), "MatterBuildError::Validation"),
        ("4B", "00".repeat(3), "MatterBuildError::Validation"),
        ("E", String::new(), "ParsingError::EmptyStream"),
    ] {
        let response =
            ask(json!({"id": 3, "op": "cesr.encode", "code": code, "raw": raw, "domain": "text"}));
        assert_eq!(
            response["result"],
            json!({"reject": {"class": class}}),
            "{code}"
        );
    }
}
