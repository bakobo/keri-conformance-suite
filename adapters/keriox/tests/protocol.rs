//! What this build declares: the keri-core 0.17.13 line's hello and its keri.process request
//! checks. tests/mechanics.rs has the protocol mechanics every keriox build shares.

use kcs_adapter_keriox::protocol::handle_line;
use serde_json::{json, Value};

fn answer(line: &str) -> Value {
    serde_json::from_str(&handle_line(line.as_bytes())).expect("a response is JSON")
}

#[test]
fn hello_answers_protocol_one_and_declares_what_it_implements() {
    let r = answer(r#"{"id":0,"op":"hello","protocol":1,"supported":[1]}"#);
    assert_eq!(r["id"], 0);
    let result = &r["result"];
    assert_eq!(result["protocol"], 1);
    assert_eq!(result["adapter"]["name"], "kcs-adapter-keriox");
    assert!(result["adapter"]["version"].is_string());
    assert_eq!(result["implementation"]["name"], "keri-core");
    assert_eq!(
        result["implementation"]["version"],
        "0.17.13 (cesrox 0.1.8, said 0.4.3)"
    );
    assert_eq!(
        result["implementation"]["commit"],
        "b25ba2b1b276706cbe103bc185224071a5e73579 (cesrox 40840948fb669424a0b7629979291ee0c777bb0e, \
         said a385e69028fa2d9bd8fda31a9401ad0a630e1361)"
    );
    assert_eq!(
        result["operations"],
        json!(["cesr.parse", "cesr.encode", "keri.process"])
    );
    assert_eq!(
        result["features"],
        json!([
            "cesr.genus-1.00",
            "cesr.serialization.json",
            "crypto.ed25519",
            "kel.basic",
            "kel.delegation",
            "kel.multisig.numeric",
            "kel.multisig.weighted",
            "kel.nontransferable",
            "kel.partial-rotation",
            "kel.witness",
            "keri.duplicity",
            "keri.escrow",
            "keri.routing",
            "keri.version-1.x"
        ])
    );
    assert_eq!(result["composes"], json!([]));
    assert_eq!(result.as_object().unwrap().len(), 6);
}

#[test]
fn malformed_keri_process_fields_are_harness_errors() {
    for line in [
        r#"{"id":2,"op":"keri.process","messages":[]}"#,
        r#"{"id":2,"op":"keri.process","perspective":"validator","messages":[]}"#,
        r#"{"id":2,"op":"keri.process","perspective":{"role":"validator"}}"#,
        r#"{"id":2,"op":"keri.process","perspective":{"role":"validator"},"messages":{}}"#,
        r#"{"id":2,"op":"keri.process","perspective":{"role":"validator"},"messages":["00"]}"#,
        r#"{"id":2,"op":"keri.process","perspective":{"role":"validator"},"messages":[{}]}"#,
        r#"{"id":2,"op":"keri.process","perspective":{"role":"validator"},"messages":[{"stream":"0G"}]}"#,
    ] {
        let r = answer(line);
        assert_eq!(r["id"], 2, "{line}");
        assert_eq!(r["error"]["kind"], "harness", "{line}");
    }
}
