//! Adapter protocol v1 over stdio: one JSON request per line in, one JSON response per line out.
//!
//! `handle_line` never panics and always returns exactly one response line. Operations that call
//! into cesrox or said run on a worker thread (see `isolate`), so a panic inside them becomes a
//! `harness` error for that request and the adapter answers the next one.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use serde_json::{json, Map, Value};

use crate::cesr::{self, OpError};

pub const PROTOCOL: u64 = 1;
pub const ADAPTER_NAME: &str = "kcs-adapter-keriox";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const OPERATIONS: [&str; 2] = ["cesr.parse", "cesr.encode"];
/// Drawn from profiles/features.json; README.md says why each is or is not declared.
pub const FEATURES: [&str; 3] = [
    "cesr.genus-1.00",
    "cesr.serialization.json",
    "keri.version-1.x",
];

/// The longest request line the adapter reads, in bytes, not counting its newline. A longer line
/// is answered with an error whose id is null and skipped without being held in memory.
pub const MAX_REQUEST_LINE: usize = 64 * 1024 * 1024;

/// Stack for the worker thread each operation runs on. cesrox's parsers recurse into nested
/// frames; this leaves room for that without changing what cesrox does.
const WORKER_STACK: usize = 64 * 1024 * 1024;

pub const E_OVERSIZE: &str = "e.input.range.request-size.f";
pub const E_MALFORMED: &str = "e.input.format.request.f";
pub const E_UNKNOWN_OP: &str = "e.input.range.unknown-op.f";
pub const E_UNDECLARED_OP: &str = "e.feature.unsupported.undeclared-op.f";
pub const E_VERSION: &str = "e.feature.unsupported.protocol-version.f";
pub const E_PANIC: &str = "e.self.unknown.panic.f";
pub const E_WORKER: &str = "e.self.resource.worker-thread.r";

fn error(id: Value, kind: &str, message: String) -> Value {
    json!({"id": id, "error": {"kind": kind, "message": message}})
}

fn from_op_error(id: Value, err: OpError) -> Value {
    match err {
        OpError::Harness(message) => error(id, "harness", message),
        OpError::Unsupported(message) => error(id, "unsupported", message),
    }
}

fn implementation() -> Value {
    json!({
        "name": "cesrox",
        "version": format!("{} (said {})", env!("KCS_CESROX_VERSION"), env!("KCS_SAID_VERSION")),
        "commit": format!("{} (said {})", env!("KCS_CESROX_COMMIT"), env!("KCS_SAID_COMMIT")),
    })
}

fn hello(request: &Map<String, Value>) -> Result<Value, OpError> {
    let offered: Vec<Value> = match request.get("supported") {
        Some(Value::Array(list)) => list.clone(),
        _ => vec![request.get("protocol").cloned().unwrap_or(Value::Null)],
    };
    if !offered
        .iter()
        .any(|v| v.as_u64() == Some(PROTOCOL) && v.is_u64())
    {
        return Err(OpError::Unsupported(format!(
            "{E_VERSION}: This adapter implements adapter protocol version {PROTOCOL} only, and \
             the runner offered {}.",
            Value::Array(offered)
        )));
    }
    Ok(json!({
        "protocol": PROTOCOL,
        "adapter": {"name": ADAPTER_NAME, "version": ADAPTER_VERSION},
        "implementation": implementation(),
        "operations": OPERATIONS,
        "features": FEATURES,
        "composes": [],
    }))
}

fn hex_field(request: &Map<String, Value>, field: &str) -> Result<Vec<u8>, OpError> {
    let malformed = || {
        OpError::Harness(format!(
            "{E_MALFORMED}: \"{field}\" must be a lowercase hex string."
        ))
    };
    let text = request
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    if text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed());
    }
    let nibble = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    Ok(text
        .as_bytes()
        .chunks(2)
        .map(|p| nibble(p[0]) << 4 | nibble(p[1]))
        .collect())
}

fn parse_op(request: &Map<String, Value>) -> Result<Value, OpError> {
    let stream = hex_field(request, "stream")?;
    isolate(move || cesr::parse(&stream))
}

fn encode_op(request: &Map<String, Value>) -> Result<Value, OpError> {
    let code = match request.get("code").and_then(Value::as_str) {
        Some(code) if !code.is_empty() => code.to_string(),
        _ => {
            return Err(OpError::Harness(format!(
                "{E_MALFORMED}: \"code\" must be a non-empty string."
            )))
        }
    };
    let domain = match request.get("domain").and_then(Value::as_str) {
        Some(d @ ("text" | "binary")) => d.to_string(),
        _ => {
            return Err(OpError::Harness(format!(
                "{E_MALFORMED}: \"domain\" must be \"text\" or \"binary\"."
            )))
        }
    };
    let raw = hex_field(request, "raw")?;
    isolate(move || cesr::encode(&code, &raw, &domain))
}

/// Run one operation on a fresh worker thread and turn a panic into a harness error. The panic's
/// own message also reaches standard error through Rust's default panic hook.
pub(crate) fn isolate<F>(work: F) -> Result<Value, OpError>
where
    F: FnOnce() -> Result<Value, OpError> + Send + 'static,
{
    let worker = std::thread::Builder::new()
        .name("kcs-op".into())
        .stack_size(WORKER_STACK)
        .spawn(move || panic::catch_unwind(AssertUnwindSafe(work)));
    let joined = match worker {
        Ok(handle) => handle.join(),
        Err(err) => {
            return Err(OpError::Harness(format!(
                "{E_WORKER}: The adapter could not start a worker thread for this request: \
                 {err}."
            )))
        }
    };
    match joined {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(payload)) | Err(payload) => {
            let what = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "a panic without a message".into());
            Err(OpError::Harness(format!(
                "{E_PANIC}: Code inside the adapter process panicked while handling this \
                 request, so it was not answered: {what}. Standard error has the location."
            )))
        }
    }
}

fn handle(id: Value, request: &Map<String, Value>) -> Value {
    let op = match request.get("op") {
        Some(Value::String(op)) => op.as_str(),
        _ => {
            return error(
                id,
                "harness",
                format!("{E_MALFORMED}: The request has no string \"op\"."),
            )
        }
    };
    let outcome = match op {
        "hello" => hello(request),
        "cesr.parse" => parse_op(request),
        "cesr.encode" => encode_op(request),
        "keri.process" | "keri.emit" => Err(OpError::Unsupported(format!(
            "{E_UNDECLARED_OP}: This adapter does not implement {op} and did not declare it in \
             hello."
        ))),
        _ => Err(OpError::Harness(format!(
            "{E_UNKNOWN_OP}: {} is not an operation of adapter protocol version {PROTOCOL}.",
            Value::String(op.into())
        ))),
    };
    match outcome {
        Ok(result) => json!({"id": id, "result": result}),
        Err(err) => from_op_error(id, err),
    }
}

/// Answer one request line (with or without its newline).
pub fn handle_line(line: &[u8]) -> String {
    let request: Option<Value> = serde_json::from_slice(line).ok();
    let response = match request {
        Some(Value::Object(request)) => match request.get("id") {
            Some(id @ Value::Number(n)) if n.is_u64() => handle(id.clone(), &request),
            _ => error(
                Value::Null,
                "harness",
                format!("{E_MALFORMED}: The request has no usable \"id\"; it must be a non-negative integer."),
            ),
        },
        _ => error(
            Value::Null,
            "harness",
            format!("{E_MALFORMED}: The request line is not a UTF-8 JSON object."),
        ),
    };
    response.to_string()
}

fn oversize(max_line: usize) -> String {
    error(
        Value::Null,
        "harness",
        format!(
            "{E_OVERSIZE}: The request line is longer than {max_line} bytes, the most this \
             adapter reads."
        ),
    )
    .to_string()
}

enum Line {
    Complete(Vec<u8>),
    Oversize,
    Eof,
}

/// Read one line, holding at most `max_line + 1` bytes of it. The rest of an oversize line is
/// consumed from the reader's buffer and dropped.
fn read_line<R: BufRead>(input: &mut R, max_line: usize) -> io::Result<Line> {
    let mut line = Vec::new();
    let mut over = false;
    let mut saw_any = false;
    loop {
        let buf = input.fill_buf()?;
        if buf.is_empty() {
            return Ok(match (saw_any, over) {
                (false, _) => Line::Eof,
                (true, true) => Line::Oversize,
                (true, false) => Line::Complete(line),
            });
        }
        saw_any = true;
        let (chunk, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..i], i + 1),
            None => (buf, buf.len()),
        };
        let ends_line = done > chunk.len();
        if !over {
            if line.len() + chunk.len() > max_line {
                over = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        input.consume(done);
        if ends_line {
            return Ok(if over {
                Line::Oversize
            } else {
                Line::Complete(line)
            });
        }
    }
}

/// Answer each request line until end of input. A blank line is not JSON, so it is answered like
/// any other unreadable request, with an error whose id is null.
pub fn serve<R: BufRead, W: Write>(mut input: R, mut output: W, max_line: usize) -> io::Result<()> {
    loop {
        let response = match read_line(&mut input, max_line)? {
            Line::Eof => return Ok(()),
            Line::Oversize => oversize(max_line),
            Line::Complete(line) => handle_line(&line),
        };
        output.write_all(response.as_bytes())?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_in_an_operation_becomes_a_harness_error_and_the_next_request_is_answered() {
        let first = isolate(|| panic!("synthetic panic for the test"));
        match first {
            Err(OpError::Harness(m)) => {
                assert!(m.starts_with(E_PANIC), "{m}");
                assert!(m.contains("synthetic panic for the test"), "{m}");
            }
            other => panic!("{other:?}"),
        }
        let second = isolate(|| Ok(json!({"items": []})));
        assert_eq!(second, Ok(json!({"items": []})));
    }

    #[test]
    fn a_panic_with_a_formatted_message_is_reported_too() {
        let n = 3;
        match isolate(move || panic!("formatted {n}")) {
            Err(OpError::Harness(m)) => assert!(m.contains("formatted 3"), "{m}"),
            other => panic!("{other:?}"),
        }
    }
}
