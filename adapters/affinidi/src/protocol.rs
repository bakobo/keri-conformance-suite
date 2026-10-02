//! Adapter protocol v1 over stdio: one JSON request per line in, one JSON response per line out.
//!
//! `handle_line` never panics and never fails: whatever happens, it returns exactly one response.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use serde_json::{Map, Value, json};

use crate::cesr;

pub const PROTOCOL: u64 = 1;
pub const ADAPTER_NAME: &str = "kcs-adapter-affinidi";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const OPERATIONS: [&str; 2] = ["cesr.parse", "cesr.encode"];

/// The implementation under test, as pinned in Cargo.toml and Cargo.lock. `tests/pins.rs` checks
/// these against Cargo.lock and against the `.cargo_vcs_info.json` that crates.io published with
/// each crate, so they cannot drift from what is actually built.
pub const IMPLEMENTATION_NAME: &str = "affinidi-keri-core";
pub const IMPLEMENTATION_VERSION: &str = "0.4.0";
pub const IMPLEMENTATION_COMMIT: &str = "6277ae866c5761edb5cfa807a5f7ac83ebf3700c";
pub const CESR_CRATE_VERSION: &str = "0.1.3";
pub const CESR_CRATE_COMMIT: &str = "b970cb01bdd1acd0530137b67460579e4624ab47";

/// Features from profiles/features.json that Affinidi and this adapter together support. See
/// README.md for why each of the others, cesr.genus-1.00 included, is not declared.
pub const FEATURES: [&str; 2] = ["cesr.serialization.json", "keri.version-1.x"];

/// The longest request line the adapter reads, in bytes, not counting its newline. A longer line
/// is answered with an error whose id is null and is skipped without being held in memory.
pub const MAX_REQUEST_LINE: usize = 64 * 1024 * 1024;

pub const E_OVERSIZE: &str = "e.input.range.request-size.f";
pub const E_MALFORMED: &str = "e.input.format.request.f";
pub const E_UNKNOWN_OP: &str = "e.input.range.unknown-op.f";
pub const E_UNDECLARED_OP: &str = "e.feature.unsupported.undeclared-op.f";
pub const E_VERSION: &str = "e.feature.unsupported.protocol-version.f";
pub const E_PANIC: &str = "e.self.unknown.panic.f";

/// Why an operation produced an error response rather than a result.
#[derive(Debug, PartialEq, Eq)]
pub enum OpError {
    /// The request itself is unusable: answered as a `harness` error.
    Malformed(String),
    /// Affinidi, or this adapter, cannot perform the operation for this input: `unsupported`.
    Unsupported(String),
    /// Something panicked, or the adapter found Affinidi inconsistent with itself: `harness`.
    Harness(String),
}

fn error(id: Value, kind: &str, message: &str) -> Value {
    json!({"id": id, "error": {"kind": kind, "message": message}})
}

/// Run `f`, turning a panic (in this adapter or in Affinidi) into an `OpError::Harness`, so that a
/// panicking parser still produces exactly one response and the session continues.
pub fn guarded<T>(what: &str, f: impl FnOnce() -> Result<T, OpError>) -> Result<T, OpError> {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "a panic with no message".to_string());
            Err(OpError::Harness(format!(
                "{E_PANIC}: The process panicked during {what}: {detail}. A panic inside \
                 Affinidi's code on this input is a defect in the implementation, not a rejection."
            )))
        }
    }
}

fn hex_field(request: &Map<String, Value>, field: &str) -> Result<Vec<u8>, OpError> {
    let bad = || {
        OpError::Malformed(format!(
            "{E_MALFORMED}: \"{field}\" must be a lowercase hex string."
        ))
    };
    let text = request.get(field).and_then(Value::as_str).ok_or_else(bad)?;
    if text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad());
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

/// The implementation identity: both pinned crates, so that moving either pin changes the identity
/// the CI baseline gate compares.
pub fn implementation() -> Value {
    json!({
        "name": IMPLEMENTATION_NAME,
        "version": format!("{IMPLEMENTATION_VERSION} (affinidi-cesr {CESR_CRATE_VERSION})"),
        "commit": format!("{IMPLEMENTATION_COMMIT} (affinidi-cesr {CESR_CRATE_COMMIT})"),
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

fn parse(request: &Map<String, Value>) -> Result<Value, OpError> {
    let stream = hex_field(request, "stream")?;
    guarded("cesr.parse", || cesr::parse(&stream))
}

fn encode(request: &Map<String, Value>) -> Result<Value, OpError> {
    let code = match request.get("code").and_then(Value::as_str) {
        Some(code) if !code.is_empty() => code,
        _ => {
            return Err(OpError::Malformed(format!(
                "{E_MALFORMED}: \"code\" must be a non-empty string."
            )));
        }
    };
    let binary = match request.get("domain").and_then(Value::as_str) {
        Some("text") => false,
        Some("binary") => true,
        _ => {
            return Err(OpError::Malformed(format!(
                "{E_MALFORMED}: \"domain\" must be \"text\" or \"binary\"."
            )));
        }
    };
    let raw = hex_field(request, "raw")?;
    guarded("cesr.encode", || cesr::encode(code, raw, binary))
}

/// Answer one request that has already been read as a JSON object with a usable id.
pub fn handle(id: Value, request: &Map<String, Value>) -> Value {
    let Some(op) = request.get("op").and_then(Value::as_str) else {
        return error(
            id,
            "harness",
            &format!("{E_MALFORMED}: The request has no string \"op\"."),
        );
    };
    let outcome = match op {
        "hello" => hello(request),
        "cesr.parse" => parse(request),
        "cesr.encode" => encode(request),
        "keri.process" | "keri.emit" => Err(OpError::Unsupported(format!(
            "{E_UNDECLARED_OP}: This adapter does not implement {op} and did not declare it in hello."
        ))),
        _ => Err(OpError::Malformed(format!(
            "{E_UNKNOWN_OP}: {} is not an operation of adapter protocol version {PROTOCOL}.",
            Value::String(op.to_string())
        ))),
    };
    match outcome {
        Ok(result) => json!({"id": id, "result": result}),
        Err(OpError::Unsupported(message)) => {
            eprintln!("{ADAPTER_NAME}: id {id}: {message}");
            error(id, "unsupported", &message)
        }
        Err(OpError::Malformed(message) | OpError::Harness(message)) => {
            eprintln!("{ADAPTER_NAME}: id {id}: {message}");
            error(id, "harness", &message)
        }
    }
}

fn oversize(limit: usize) -> Value {
    error(
        Value::Null,
        "harness",
        &format!(
            "{E_OVERSIZE}: The request line is longer than {limit} bytes, the most this adapter reads."
        ),
    )
}

/// Answer one request line (without its newline).
pub fn handle_line(line: &[u8]) -> Value {
    if line.len() > MAX_REQUEST_LINE {
        return oversize(MAX_REQUEST_LINE);
    }
    let request = serde_json::from_slice::<Value>(line).ok();
    let Some(Value::Object(request)) = request else {
        return error(
            Value::Null,
            "harness",
            &format!("{E_MALFORMED}: The request line is not a UTF-8 JSON object."),
        );
    };
    match request.get("id") {
        // The protocol: a request with no usable id is answered with an error whose id is null.
        Some(id @ Value::Number(n)) if n.is_u64() => handle(id.clone(), &request),
        _ => error(
            Value::Null,
            "harness",
            &format!(
                "{E_MALFORMED}: The request has no usable \"id\"; it must be a non-negative integer."
            ),
        ),
    }
}

/// What reading one line produced.
enum Line {
    Complete(Vec<u8>),
    /// Longer than the limit; the rest of it has already been skipped.
    Oversize,
    Eof,
}

/// Read one line of at most `limit` bytes (plus its newline). A longer line is skipped in
/// buffer-sized pieces, never held whole.
fn read_line(input: &mut impl BufRead, limit: usize) -> io::Result<Line> {
    let mut line = Vec::new();
    let mut oversize = false;
    loop {
        let buf = match input.fill_buf() {
            Ok(buf) => buf,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            return Ok(if oversize {
                Line::Oversize
            } else if line.is_empty() {
                Line::Eof
            } else {
                Line::Complete(line)
            });
        }
        let (take, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        if !oversize {
            if line.len() + take > limit {
                oversize = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&buf[..take]);
            }
        }
        input.consume(if done { take + 1 } else { take });
        if done {
            return Ok(if oversize {
                Line::Oversize
            } else {
                Line::Complete(line)
            });
        }
    }
}

/// Answer each request line until end of file, reading lines of at most `limit` bytes. A blank
/// line is not JSON, so it is answered like any other unreadable request, with an error whose id
/// is null.
pub fn serve_with_limit(
    mut input: impl BufRead,
    mut output: impl Write,
    limit: usize,
) -> io::Result<()> {
    loop {
        let response = match read_line(&mut input, limit)? {
            Line::Eof => break,
            Line::Oversize => oversize(limit),
            Line::Complete(line) => handle_line(&line),
        };
        let mut bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
        bytes.push(b'\n');
        output.write_all(&bytes)?;
        output.flush()?;
    }
    eprintln!("{ADAPTER_NAME}: end of input, exiting");
    Ok(())
}

pub fn serve(input: impl BufRead, output: impl Write) -> io::Result<()> {
    serve_with_limit(input, output, MAX_REQUEST_LINE)
}
