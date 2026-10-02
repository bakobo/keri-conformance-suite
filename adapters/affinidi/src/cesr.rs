//! `cesr.parse` and `cesr.encode`, answered from Affinidi's public API only.
//!
//! Every reported value is Affinidi's own: the accept/reject verdict is `parse_all`'s, message
//! boundaries are the bytes `parse_next` says it consumed and the body size its `Serder` holds, and
//! the message fields come from the `Version` Affinidi parsed. Affinidi's parser does not expose
//! where it found each attachment, nor the count codes it read, so a stream it accepts with any
//! attachment is answered `unsupported` rather than reconstructed by the adapter. README.md lists
//! every value and its source.

use affinidi_cesr::Matter;
use affinidi_keri_core::parser::{self, ParsedMessage};
use serde_json::{Value, json};

use crate::protocol::OpError;

pub const E_ITEM_EXTENT: &str = "e.feature.unsupported.item-extent.f";
pub const E_SKIPPED_BYTES: &str = "e.feature.unsupported.skipped-bytes.f";
pub const E_NO_VERSION: &str = "e.feature.unsupported.message-version.f";
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

/// The message item for one message Affinidi parsed at `start`, or why it cannot be reported.
fn message_item(start: usize, message: &ParsedMessage, consumed: usize) -> Result<Value, OpError> {
    let body = message.serder.size();
    if !message.attachments.is_empty() || consumed != body {
        return Err(OpError::Unsupported(format!(
            "{E_ITEM_EXTENT}: Affinidi accepted the stream. The message at offset {start} has a \
             {body}-byte body and Affinidi consumed {consumed} bytes for it, so {} bytes of \
             attachments, which it decoded into {} group(s). Its public parser reports neither \
             where each attachment item lies nor the count codes it read, so the adapter cannot \
             report the items without parsing them itself, which it does not do.",
            consumed - body.min(consumed),
            message.attachments.len()
        )));
    }
    let Some(version) = message.serder.version.as_ref() else {
        return Err(OpError::Unsupported(format!(
            "{E_NO_VERSION}: Affinidi accepted the stream, but for the message at offset {start} \
             it found no version string, so it holds no protocol, version or declared size to report."
        )));
    };
    if version.size != body {
        return Err(OpError::Harness(format!(
            "{E_INCONSISTENT}: Affinidi framed a {body}-byte body at offset {start} but holds a \
             declared size of {}; the adapter does not report a message it cannot account for.",
            version.size
        )));
    }
    Ok(json!({
        "kind": "message",
        "start": start,
        "end": start + body,
        "proto": version.protocol,
        "version": format!("{}.{}", version.major, version.minor),
        "serialization": version.kind.tag(),
        "size": version.size,
    }))
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
    // parse_all accepted it. Walk it again one message at a time with parse_next, the function
    // parse_all calls, to learn where each message starts: the end of the bytes Affinidi says it
    // consumed for the one before.
    let mut items = Vec::with_capacity(messages.len());
    let mut offset = 0;
    while offset < stream.len() {
        if stream[offset].is_ascii_whitespace() {
            return Err(OpError::Unsupported(format!(
                "{E_SKIPPED_BYTES}: Affinidi accepted the stream, skipping whitespace at offset \
                 {offset} between messages (parse_all does this); the protocol has no item for \
                 bytes a parser skips."
            )));
        }
        let (message, consumed) = parser::parse_next(&stream[offset..]).map_err(|error| {
            OpError::Harness(format!(
                "{E_INCONSISTENT}: parse_all accepted the stream but parse_next rejected the \
                 message at offset {offset}: {error}"
            ))
        })?;
        if consumed == 0 {
            return Err(OpError::Harness(format!(
                "{E_INCONSISTENT}: parse_next consumed no bytes at offset {offset}."
            )));
        }
        items.push(message_item(offset, &message, consumed)?);
        offset += consumed;
    }
    if items.len() != messages.len() {
        return Err(OpError::Harness(format!(
            "{E_INCONSISTENT}: parse_all found {} messages but parse_next found {}.",
            messages.len(),
            items.len()
        )));
    }
    Ok(json!({"items": items}))
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
            "{E_ENCODE_REFUSED}: Affinidi refused to encode code {}: {}: {error}",
            Value::String(code.to_string()),
            class_of("CesrError", &error)
        ))),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
