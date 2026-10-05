//! Protocol mechanics: hello negotiation, id handling, unreadable lines, bounded line reads,
//! undeclared and unknown operations, and the process lifecycle of the binary.

use std::io::Write;
use std::process::{Command, Stdio};

use kcs_adapter_keriox::protocol::{handle_line, serve, MAX_REQUEST_LINE};
use serde_json::{json, Value};

fn answer(line: &str) -> Value {
    serde_json::from_str(&handle_line(line.as_bytes())).expect("a response is JSON")
}

fn error_kind(response: &Value) -> &str {
    response["error"]["kind"]
        .as_str()
        .expect("an error response")
}

/// Every response is exactly {id, result} or {id, error:{kind, message}}.
fn assert_well_formed(response: &Value) {
    let object = response.as_object().expect("a response is an object");
    assert!(object.contains_key("id"), "{response}");
    assert_eq!(object.len(), 2, "{response}");
    if let Some(error) = object.get("error") {
        let error = error.as_object().unwrap();
        assert_eq!(error.len(), 2, "{response}");
        assert!(matches!(
            error["kind"].as_str(),
            Some("harness" | "unsupported")
        ));
        assert!(error["message"].is_string());
    } else {
        assert!(object["result"].is_object(), "{response}");
    }
}

#[test]
fn hello_answers_protocol_one_and_declares_what_it_implements() {
    let r = answer(r#"{"id":0,"op":"hello","protocol":1,"supported":[1]}"#);
    assert_well_formed(&r);
    assert_eq!(r["id"], 0);
    let result = &r["result"];
    assert_eq!(result["protocol"], 1);
    assert_eq!(result["adapter"]["name"], "kcs-adapter-keriox");
    assert!(result["adapter"]["version"].is_string());
    assert_eq!(result["implementation"]["name"], "cesrox");
    assert_eq!(result["implementation"]["version"], "0.1.8 (said 0.4.3)");
    assert_eq!(
        result["implementation"]["commit"],
        "40840948fb669424a0b7629979291ee0c777bb0e (said a385e69028fa2d9bd8fda31a9401ad0a630e1361)"
    );
    assert_eq!(result["operations"], json!(["cesr.parse", "cesr.encode"]));
    assert_eq!(
        result["features"],
        json!([
            "cesr.genus-1.00",
            "cesr.item-extents",
            "cesr.serialization.json",
            "keri.version-1.x"
        ])
    );
    assert_eq!(result["composes"], json!([]));
    assert_eq!(result.as_object().unwrap().len(), 6);
}

#[test]
fn hello_negotiates_from_supported_not_protocol() {
    let r = answer(r#"{"id":1,"op":"hello","protocol":3,"supported":[1,2,3]}"#);
    assert_eq!(r["result"]["protocol"], 1);
}

#[test]
fn hello_without_a_shared_version_is_an_unsupported_error() {
    let r = answer(r#"{"id":1,"op":"hello","protocol":2,"supported":[2]}"#);
    assert_well_formed(&r);
    assert_eq!(r["id"], 1);
    assert_eq!(error_kind(&r), "unsupported");
}

#[test]
fn hello_without_supported_falls_back_to_protocol() {
    assert_eq!(
        answer(r#"{"id":1,"op":"hello","protocol":1}"#)["result"]["protocol"],
        1
    );
    assert_eq!(
        error_kind(&answer(r#"{"id":1,"op":"hello","protocol":2}"#)),
        "unsupported"
    );
}

#[test]
fn unknown_request_fields_are_ignored() {
    let r = answer(r#"{"id":5,"op":"hello","protocol":1,"supported":[1],"future":{"x":1}}"#);
    assert_eq!(r["result"]["protocol"], 1);
    let r = answer(r#"{"id":6,"op":"cesr.parse","stream":"","extra":[1,2]}"#);
    assert_eq!(r["result"]["items"], json!([]));
}

#[test]
fn the_id_is_echoed() {
    let r = answer(r#"{"id":7919,"op":"cesr.parse","stream":"2d4b"}"#);
    assert_well_formed(&r);
    assert_eq!(r["id"], 7919);
}

#[test]
fn unreadable_lines_get_an_error_whose_id_is_null() {
    for line in [
        "this line is not JSON",
        "",
        "\n",
        "[1,2]",
        "7",
        r#"{"op":"hello"}"#,
        r#"{"id":-1,"op":"hello"}"#,
        r#"{"id":"7","op":"hello"}"#,
        r#"{"id":1.5,"op":"hello"}"#,
        r#"{"id":null,"op":"hello"}"#,
        r#"{"id":true,"op":"hello"}"#,
    ] {
        let r = answer(line);
        assert_well_formed(&r);
        assert!(r["id"].is_null(), "{line:?} -> {r}");
        assert_eq!(error_kind(&r), "harness", "{line:?}");
    }
    let r: Value = serde_json::from_str(&handle_line(&[0xff, 0xfe, b'{'])).unwrap();
    assert!(r["id"].is_null());
}

#[test]
fn a_request_without_a_string_op_is_a_harness_error_with_its_id() {
    for line in [
        r#"{"id":3}"#,
        r#"{"id":3,"op":["hello"]}"#,
        r#"{"id":3,"op":{}}"#,
    ] {
        let r = answer(line);
        assert_eq!(r["id"], 3, "{line}");
        assert_eq!(error_kind(&r), "harness");
    }
}

#[test]
fn an_unknown_op_is_a_harness_error() {
    let r = answer(r#"{"id":4,"op":"kcs.probe.no-such-op"}"#);
    assert_eq!(r["id"], 4);
    assert_eq!(error_kind(&r), "harness");
}

#[test]
fn undeclared_operations_are_unsupported() {
    for op in ["keri.process", "keri.emit"] {
        let r = answer(&format!(r#"{{"id":4,"op":"{op}"}}"#));
        assert_eq!(r["id"], 4);
        assert_eq!(error_kind(&r), "unsupported", "{op}");
    }
}

#[test]
fn malformed_operation_fields_are_harness_errors() {
    for line in [
        r#"{"id":2,"op":"cesr.parse"}"#,
        r#"{"id":2,"op":"cesr.parse","stream":"ABCD"}"#,
        r#"{"id":2,"op":"cesr.parse","stream":"abc"}"#,
        r#"{"id":2,"op":"cesr.parse","stream":7}"#,
        r#"{"id":2,"op":"cesr.encode","raw":"00","domain":"text"}"#,
        r#"{"id":2,"op":"cesr.encode","code":"","raw":"00","domain":"text"}"#,
        r#"{"id":2,"op":"cesr.encode","code":"D","raw":"0","domain":"text"}"#,
        r#"{"id":2,"op":"cesr.encode","code":"D","raw":"00","domain":"qb3"}"#,
    ] {
        let r = answer(line);
        assert_eq!(r["id"], 2, "{line}");
        assert_eq!(error_kind(&r), "harness", "{line}");
    }
}

#[test]
fn serve_answers_each_line_and_keeps_going_after_an_unreadable_one() {
    let input = b"not json\n\n{\"id\":1,\"op\":\"cesr.parse\",\"stream\":\"\"}\n".to_vec();
    let mut out = Vec::new();
    serve(&input[..], &mut out, MAX_REQUEST_LINE).unwrap();
    let lines: Vec<Value> = out
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0]["id"].is_null());
    assert!(lines[1]["id"].is_null());
    assert_eq!(lines[2]["id"], 1);
    assert_eq!(lines[2]["result"]["items"], json!([]));
}

#[test]
fn serve_answers_a_final_line_without_a_newline() {
    let mut out = Vec::new();
    serve(
        &b"{\"id\":9,\"op\":\"cesr.parse\",\"stream\":\"\"}"[..],
        &mut out,
        MAX_REQUEST_LINE,
    )
    .unwrap();
    let r: Value = serde_json::from_slice(out.strip_suffix(b"\n").unwrap()).unwrap();
    assert_eq!(r["id"], 9);
}

#[test]
fn an_oversize_line_gets_a_null_id_error_and_is_skipped() {
    let max = 64;
    let mut input = vec![b'x'; 1000];
    input.push(b'\n');
    input.extend_from_slice(b"{\"id\":2,\"op\":\"cesr.parse\",\"stream\":\"\"}\n");
    let mut exact = vec![b' '; max - 2];
    exact.splice(0..0, b"[]".iter().copied()); // exactly `max` bytes: read, not oversize
    input.extend_from_slice(&exact);
    input.push(b'\n');
    let mut out = Vec::new();
    serve(&input[..], &mut out, max).unwrap();
    let lines: Vec<Value> = out
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[0]["id"].is_null());
    assert!(lines[0]["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("e.input.range.request-size.f"));
    assert_eq!(lines[1]["id"], 2);
    assert!(lines[2]["id"].is_null());
    assert!(lines[2]["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("e.input.format.request.f"));
}

#[test]
fn every_error_message_starts_with_a_stable_code() {
    for line in [
        "nope",
        r#"{"id":1,"op":"hello","protocol":2,"supported":[2]}"#,
        r#"{"id":1,"op":"what"}"#,
        r#"{"id":1,"op":"keri.emit"}"#,
        r#"{"id":1,"op":"cesr.parse","stream":"zz"}"#,
    ] {
        let r = answer(line);
        let message = r["error"]["message"].as_str().unwrap();
        let code = message.split(':').next().unwrap();
        assert!(code.starts_with("e.") && code.ends_with(".f"), "{message}");
    }
}

fn run_binary(input: &[u8]) -> (std::process::ExitStatus, Vec<Value>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kcs-adapter-keriox"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    let lines = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).expect("stdout carries only response lines"))
        .collect();
    (output.status, lines)
}

#[test]
fn the_binary_exits_zero_at_end_of_input() {
    let (status, lines) =
        run_binary(b"{\"id\":0,\"op\":\"hello\",\"protocol\":1,\"supported\":[1]}\n");
    assert!(status.success());
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["result"]["protocol"], 1);
}
