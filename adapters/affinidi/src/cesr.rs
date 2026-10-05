//! `cesr.parse` and `cesr.encode`, answered from Affinidi's public API only.
//!
//! The accept/reject verdict is `parse_all`'s. Affinidi's parser does not expose where it found
//! each item, nor the count codes it read, so the adapter does not declare `cesr.item-extents`
//! and answers every stream Affinidi accepts with the protocol's summary: the bytes Affinidi
//! consumed, measured as the sum of what `parse_next` says it consumed for each message. It
//! never reconstructs items. README.md lists every value and its source.

use affinidi_cesr::Matter;
use affinidi_keri_core::parser;
use serde_json::{Value, json};

use crate::protocol::OpError;

pub const E_ENCODE_REFUSED: &str = "e.input.format.encode-refused.f";
pub const E_INCONSISTENT: &str = "e.self.unknown.measurement.f";

/// The name of an error's enum variant, from its derived `Debug` form: `CoreError::ParseError`.
pub fn class_of(enum_name: &str, error: &impl std::fmt::Debug) -> String {
    let debug = format!("{error:?}");
    let end = debug
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(debug.len());
    format!("{enum_name}::{}", &debug[..end])
}

fn reject(class: String) -> Value {
    json!({"reject": {"class": class}})
}

fn inconsistent(why: String) -> OpError {
    OpError::Harness(format!("{E_INCONSISTENT}: {why}"))
}

/// Decode a stream with Affinidi's strict parser.
pub fn parse(stream: &[u8]) -> Result<Value, OpError> {
    // The verdict is Affinidi's whole-stream entry point, exactly as Affinidi's own callers use it.
    let messages = match parser::parse_all(stream) {
        Ok(messages) => messages,
        Err(error) => {
            eprintln!("affinidi rejected the stream: {error}");
            return Ok(reject(class_of("CoreError", &error)));
        }
    };
    // parse_all accepted it. Walk it again as parse_all does, skipping the whitespace it skips
    // between messages and calling parse_next once per message, to measure how many bytes
    // Affinidi consumed from what parse_next says it consumed.
    let mut offset = 0;
    let mut found = 0;
    while offset < stream.len() {
        if stream[offset].is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        let (_, consumed) = parser::parse_next(&stream[offset..]).map_err(|error| {
            inconsistent(format!(
                "parse_all accepted the stream but parse_next rejected the message at offset \
                 {offset}: {error}."
            ))
        })?;
        if consumed == 0 || consumed > stream.len() - offset {
            return Err(inconsistent(format!(
                "parse_next said it consumed {consumed} bytes of the {} left at offset {offset}.",
                stream.len() - offset
            )));
        }
        offset += consumed;
        found += 1;
    }
    if found != messages.len() {
        return Err(inconsistent(format!(
            "parse_all found {} messages but parse_next found {found}.",
            messages.len()
        )));
    }
    Ok(json!({"accepted": {"consumed": offset}}))
}

/// Encode a primitive with Affinidi's `Matter`.
pub fn encode(code: &str, raw: Vec<u8>, binary: bool) -> Result<Value, OpError> {
    let encoded = Matter::new(code, raw).and_then(|matter| {
        if binary {
            matter.qb2()
        } else {
            matter.qb64().map(String::into_bytes)
        }
    });
    match encoded {
        Ok(bytes) => Ok(json!({"encoded": hex(&bytes)})),
        Err(error) => Err(OpError::Unsupported(format!(
            "{E_ENCODE_REFUSED}: Affinidi refused to encode code {}: {}: {error}.",
            Value::String(code.to_string()),
            class_of("CesrError", &error)
        ))),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
