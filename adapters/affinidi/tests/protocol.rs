//! Protocol mechanics (docs/adapter-protocol.md): hello negotiation, ids, unreadable lines, bounded
//! reads, unknown ops and fields. None of these depend on what Affinidi does with a stream.

use kcs_adapter_affinidi::protocol::{self, handle_line, serve_with_limit};
use serde_json::{Value, json};

fn ask(request: Value) -> Value {
    handle_line(&serde_json::to_vec(&request).unwrap())
}

fn error_kind(response: &Value) -> &str {
    response["error"]["kind"]
        .as_str()
        .expect("an error response")
}

fn error_message(response: &Value) -> &str {
    response["error"]["message"]
        .as_str()
        .expect("an error response")
}

fn assert_null_id_error(response: &Value, code: &str) {
    assert_eq!(response["id"], Value::Null, "{response}");
    assert_eq!(error_kind(response), "harness", "{response}");
    assert!(error_message(response).starts_with(code), "{response}");
    assert_eq!(response.as_object().unwrap().len(), 2, "{response}");
}

#[test]
fn hello_negotiates_the_highest_version_both_speak_from_supported() {
    let response = ask(json!({"id": 0, "op": "hello", "protocol": 3, "supported": [1, 2, 3]}));
    let result = &response["result"];
    assert_eq!(response["id"], 0);
    assert_eq!(result["protocol"], 1);
    assert_eq!(
        result["adapter"],
        json!({"name": "kcs-adapter-affinidi", "version": "0.1.0"})
    );
    assert_eq!(
        result["implementation"],
        json!({"name": "affinidi-keri-core", "version": "0.4.0 (affinidi-cesr 0.1.3)",
               "commit": "6277ae866c5761edb5cfa807a5f7ac83ebf3700c (affinidi-cesr b970cb01bdd1acd0530137b67460579e4624ab47)"})
    );
    assert_eq!(result["operations"], json!(["cesr.parse", "cesr.encode"]));
    assert_eq!(
        result["features"],
        json!(["cesr.serialization.json", "keri.version-1.x"])
    );
    assert_eq!(result["composes"], json!([]));
}

#[test]
fn hello_without_supported_uses_protocol() {
    assert_eq!(
        ask(json!({"id": 1, "op": "hello", "protocol": 1}))["result"]["protocol"],
        1
    );
    let refused = ask(json!({"id": 2, "op": "hello", "protocol": 2}));
    assert_eq!(refused["id"], 2);
    assert_eq!(error_kind(&refused), "unsupported");
    assert!(error_message(&refused).starts_with(protocol::E_VERSION));
}

#[test]
fn hello_is_refused_when_version_1_is_not_offered() {
    for supported in [
        json!([2, 3]),
        json!([]),
        json!([true]),
        json!(["1"]),
        json!([1.0]),
    ] {
        let response = ask(json!({"id": 4, "op": "hello", "protocol": 1, "supported": supported}));
        assert_eq!(
            error_kind(&response),
            "unsupported",
            "{supported}: {response}"
        );
        assert!(error_message(&response).starts_with(protocol::E_VERSION));
    }
}

#[test]
fn unknown_request_fields_are_ignored() {
    let response =
        ask(json!({"id": 5, "op": "hello", "protocol": 1, "supported": [1], "x": {"y": 1}}));
    assert_eq!(response["result"]["protocol"], 1);
    let response = ask(json!({"id": 6, "op": "cesr.parse", "stream": "", "future": [1, 2]}));
    assert_eq!(response, json!({"id": 6, "result": {"items": []}}));
}

#[test]
fn unreadable_lines_get_a_null_id_error() {
    for line in [
        &b""[..],
        b"   ",
        b"not json",
        b"[1,2]",
        b"\"s\"",
        b"{\"id\":",
        b"\xff\xfe{}",
    ] {
        assert_null_id_error(&handle_line(line), protocol::E_MALFORMED);
    }
}

#[test]
fn requests_without_a_usable_id_get_a_null_id_error() {
    for id in [
        json!(null),
        json!(-1),
        json!(1.5),
        json!(1.0),
        json!("7"),
        json!(true),
        json!([7]),
    ] {
        let response = ask(json!({"id": id, "op": "hello", "protocol": 1}));
        assert_null_id_error(&response, protocol::E_MALFORMED);
    }
    assert_null_id_error(
        &ask(json!({"op": "hello", "protocol": 1})),
        protocol::E_MALFORMED,
    );
}

#[test]
fn a_request_without_a_string_op_is_a_harness_error_with_its_id() {
    for op in [json!(null), json!(["hello"]), json!({"a": 1}), json!(3)] {
        let response = ask(json!({"id": 9, "op": op}));
        assert_eq!(response["id"], 9);
        assert_eq!(error_kind(&response), "harness");
        assert!(error_message(&response).starts_with(protocol::E_MALFORMED));
    }
    let response = ask(json!({"id": 10}));
    assert_eq!(error_kind(&response), "harness");
}

#[test]
fn unknown_and_undeclared_ops_are_errors() {
    let unknown = ask(json!({"id": 11, "op": "kcs.probe.no-such-op"}));
    assert_eq!(unknown["id"], 11);
    assert_eq!(error_kind(&unknown), "harness");
    assert!(error_message(&unknown).starts_with(protocol::E_UNKNOWN_OP));
    for op in ["keri.process", "keri.emit"] {
        let response = ask(json!({"id": 12, "op": op}));
        assert_eq!(error_kind(&response), "unsupported");
        assert!(error_message(&response).starts_with(protocol::E_UNDECLARED_OP));
    }
}

#[test]
fn ids_are_echoed_exactly() {
    for id in [0u64, 7919, u64::MAX] {
        let response = ask(json!({"id": id, "op": "cesr.parse", "stream": "2d4b"}));
        assert_eq!(response["id"], json!(id));
    }
}

#[test]
fn malformed_operation_fields_are_harness_errors() {
    for request in [
        json!({"id": 1, "op": "cesr.parse"}),
        json!({"id": 1, "op": "cesr.parse", "stream": 12}),
        json!({"id": 1, "op": "cesr.parse", "stream": "abc"}),
        json!({"id": 1, "op": "cesr.parse", "stream": "AB"}),
        json!({"id": 1, "op": "cesr.parse", "stream": "zz"}),
        json!({"id": 1, "op": "cesr.encode", "raw": "00", "domain": "text"}),
        json!({"id": 1, "op": "cesr.encode", "code": "", "raw": "00", "domain": "text"}),
        json!({"id": 1, "op": "cesr.encode", "code": "D", "raw": "00", "domain": "qb64"}),
        json!({"id": 1, "op": "cesr.encode", "code": "D", "domain": "text"}),
        json!({"id": 1, "op": "cesr.encode", "code": "D", "raw": "0", "domain": "binary"}),
    ] {
        let response = ask(request.clone());
        assert_eq!(error_kind(&response), "harness", "{request}");
        assert!(
            error_message(&response).starts_with(protocol::E_MALFORMED),
            "{request}"
        );
    }
}

#[test]
fn a_panic_becomes_a_harness_error() {
    let outcome: Result<(), _> = protocol::guarded("a test", || panic!("boom"));
    let Err(protocol::OpError::Harness(message)) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        message.starts_with(protocol::E_PANIC) && message.contains("boom"),
        "{message}"
    );
    let outcome: Result<(), _> = protocol::guarded("a test", || std::panic::panic_any(5u8));
    assert!(matches!(outcome, Err(protocol::OpError::Harness(_))));
}

fn serve_lines(input: &[u8], limit: usize) -> Vec<Value> {
    let mut output = Vec::new();
    serve_with_limit(input, &mut output, limit).unwrap();
    assert!(output.ends_with(b"\n") || output.is_empty());
    output
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect()
}

#[test]
fn serve_answers_every_line_in_order_and_stops_at_end_of_file() {
    let input = b"{\"id\":1,\"op\":\"hello\",\"protocol\":1}\nnot json\n\n{\"id\":2,\"op\":\"cesr.parse\",\"stream\":\"\"}";
    let responses = serve_lines(input, 1024);
    assert_eq!(responses.len(), 4);
    assert_eq!(responses[0]["result"]["protocol"], 1);
    assert_null_id_error(&responses[1], protocol::E_MALFORMED);
    assert_null_id_error(&responses[2], protocol::E_MALFORMED);
    assert_eq!(responses[3], json!({"id": 2, "result": {"items": []}}));
    assert!(serve_lines(b"", 1024).is_empty());
}

#[test]
fn an_oversize_line_is_skipped_and_the_next_request_is_answered() {
    let long = format!(
        "{{\"id\":1,\"op\":\"cesr.parse\",\"stream\":\"{}\"}}",
        "00".repeat(200)
    );
    let input = format!("{long}\n{{\"id\":3,\"op\":\"cesr.parse\",\"stream\":\"\"}}\n{long}");
    let responses = serve_lines(input.as_bytes(), 64);
    assert_eq!(responses.len(), 3);
    assert_null_id_error(&responses[0], protocol::E_OVERSIZE);
    assert_eq!(responses[1], json!({"id": 3, "result": {"items": []}}));
    assert_null_id_error(&responses[2], protocol::E_OVERSIZE);
}

#[test]
fn a_line_exactly_at_the_limit_is_read() {
    let line = br#"{"id":4,"op":"cesr.parse","stream":""}"#;
    let responses = serve_lines(&[&line[..], b"\n"].concat(), line.len());
    assert_eq!(responses, vec![json!({"id": 4, "result": {"items": []}})]);
    let responses = serve_lines(&[&line[..], b"\n"].concat(), line.len() - 1);
    assert_null_id_error(&responses[0], protocol::E_OVERSIZE);
}

/// A reader that hands out one byte at a time, so a line spans many buffer fills.
struct Trickle<'a>(&'a [u8]);

impl std::io::Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.0.is_empty() || buf.is_empty() {
            return Ok(0);
        }
        buf[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}

#[test]
fn lines_split_across_reads_are_reassembled() {
    let input = b"{\"id\":5,\"op\":\"cesr.parse\",\"stream\":\"\"}\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";
    let mut output = Vec::new();
    serve_with_limit(
        std::io::BufReader::with_capacity(4, Trickle(input)),
        &mut output,
        50,
    )
    .unwrap();
    let lines: Vec<Value> = output
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(lines[0], json!({"id": 5, "result": {"items": []}}));
    assert_null_id_error(&lines[1], protocol::E_OVERSIZE);
}
