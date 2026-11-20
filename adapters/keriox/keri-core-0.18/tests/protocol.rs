//! What this build declares: the keri-core 0.18.0 line's hello, keri.process left undeclared, and
//! how its answers reach the runner. ../tests/mechanics.rs has the protocol mechanics every keriox
//! build shares.

use kcs_adapter_keriox::protocol::handle_line;
use serde_json::{json, Value};

fn answer(line: &str) -> Value {
    serde_json::from_str(&handle_line(line.as_bytes())).expect("a response is JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn hello_reports_the_keri_core_0_18_line_and_only_the_cesr_operations() {
    let r = answer(r#"{"id":0,"op":"hello","protocol":1,"supported":[1]}"#);
    let result = &r["result"];
    assert_eq!(result["protocol"], 1);
    assert_eq!(result["adapter"]["name"], "kcs-adapter-keriox");
    assert!(result["adapter"]["version"].is_string());
    assert_eq!(result["implementation"]["name"], "keri-core");
    assert_eq!(
        result["implementation"]["version"],
        "0.18.0 (cesrox 2.0.0-beta.8, said 0.5.4)"
    );
    assert_eq!(
        result["implementation"]["commit"],
        "411f6d4e0591d81e771ae5636ffa8f57ac1a01e3 (cesrox ca35e3efe1cadfcc08fd237e76281b3994524825, \
         said 86a3f81ca9cdac9535d3405cdd3906d31c89598b)"
    );
    assert_eq!(result["operations"], json!(["cesr.parse", "cesr.encode"]));
    assert_eq!(
        result["features"],
        json!([
            "cesr.genus-2.00",
            "cesr.serialization.json",
            "keri.version-1.x"
        ])
    );
    assert_eq!(result["composes"], json!([]));
    assert_eq!(result.as_object().unwrap().len(), 6);
}

/// cesr.item-extents promises items for every accepted stream, and cesrox keeps no offsets inside
/// first-seen couples, pathed material, TSP payloads, tags or variable-length primitives, so the
/// build answers those with a summary and must not declare the feature (hostile pass on PR #91).
#[test]
fn a_build_that_answers_some_accepted_streams_with_a_summary_does_not_declare_item_extents() {
    let r = answer(r#"{"id":0,"op":"hello","protocol":1,"supported":[1]}"#);
    let features = r["result"]["features"].as_array().unwrap();
    assert!(!features.contains(&json!("cesr.item-extents")));
    let first_seen = "-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
    let r = answer(&format!(
        r#"{{"id":1,"op":"cesr.parse","stream":"{}"}}"#,
        hex(first_seen.as_bytes())
    ));
    assert_eq!(
        r["result"],
        json!({"accepted": {"consumed": first_seen.len()}})
    );
}

#[test]
fn keri_process_is_not_offered() {
    for line in [
        r#"{"id":4,"op":"keri.process","perspective":{"role":"validator"},"messages":[]}"#,
        r#"{"id":4,"op":"keri.process"}"#,
    ] {
        let r = answer(line);
        assert_eq!(r["id"], 4);
        assert_eq!(r["error"]["kind"], "unsupported", "{line}");
        assert!(r["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("e.feature.unsupported.undeclared-op.f"));
    }
}

/// CESR-0013's stream: a genus 2.00 code, a KERI 1.0 body, and -CAX-KAW, whose counts the
/// specification reads as 23 and 22 quadlets. cesrox 2.0.0-beta.8 reads -KAW as 22 signatures,
/// runs out of input inside the second and panics, which is a harness error, never a rejection.
#[test]
fn cesrox_panicking_on_a_quadlet_counted_signature_group_is_a_harness_error() {
    let stream = concat!(
        r#"-_AAACAA{"v":"KERI10JSON00012b_","t":"icp","d":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","i":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","s":"0","kt":"1","k":["DPFk75lB_TCllSQXTjv6jdGHX7wuds-JNfsVHeJdRi-p"],"nt":"1","n":["EIMUgrgEee9DvExWqJTtUB-g-OiybftXfWNuqMO-FGXQ"],"bt":"0","b":[],"c":[],"a":[]}"#,
        "-CAX-KAWAABDgvDPKFRmjqKFiYH_eAV9y1Dz82RB5z_XsDGTYzXZuUBlR26gbw-f1v8ZRmb9eXiO62KK5BQhV1b_chcLR7te"
    );
    let r = answer(&format!(
        r#"{{"id":5,"op":"cesr.parse","stream":"{}"}}"#,
        hex(stream.as_bytes())
    ));
    assert_eq!(r["id"], 5);
    assert_eq!(r["error"]["kind"], "harness", "{r}");
    assert!(r["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("e.self.unknown.panic.f"));
}

#[test]
fn a_stream_that_is_not_utf8_is_unsupported_because_cesrox_reads_only_text() {
    let r = answer(r#"{"id":6,"op":"cesr.parse","stream":"ff00"}"#);
    assert_eq!(r["error"]["kind"], "unsupported", "{r}");
    assert!(r["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("e.feature.unsupported.binary-domain.f"));
}
