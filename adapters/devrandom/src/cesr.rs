//! cesr.parse and cesr.encode, through devrandom's CESR layer: cesr-stream frames each message and
//! parses its attachment groups, and cesr-rs encodes primitives. The adapter never reads a count
//! code or a primitive itself.

use std::str::FromStr;

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::MatterCode;
use cesr_stream::{CesrGroup, FrameLimits, Groups, MessageFramer, ParseError, V1};
use serde_json::{Value, json};

use crate::protocol::OpError;

pub const E_BINARY: &str = "e.feature.unsupported.binary-domain.f";
pub const E_CODE: &str = "e.feature.unsupported.code.f";
pub const E_ENCODE: &str = "e.input.format.encode-refused.f";

/// The work bounds handed to devrandom's framer. The runner already bounds every request; these
/// are generous enough never to be what decides a case, and exist because the framer takes no
/// unbounded policy.
pub const LIMITS: FrameLimits = FrameLimits {
    max_body_bytes: 16 * 1024 * 1024,
    max_attachment_bytes: 16 * 1024 * 1024,
    max_attachment_groups: 4096,
    max_group_elements: 65_536,
    max_signatures: 65_536,
    max_nested_groups: 4096,
    max_nesting_depth: 64,
};

/// A rejection result whose class names the variant of devrandom's error.
fn reject(error: &ParseError) -> Value {
    let debug = format!("{error:?}");
    let variant = debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or("ParseError");
    eprintln!("devrandom rejected the stream: {error}");
    json!({"reject": {"class": format!("ParseError::{variant}")}})
}

/// Decode every element of one group, so that a malformed primitive inside a group devrandom has
/// framed is rejected, as it is when devrandom's own message layer reads the group. A `-V`
/// attachment frame's inner groups are decoded the same way, however deep devrandom's framer
/// allowed the nesting (its limits bound the depth). Other quadlet-counted frames are carried
/// opaquely by devrandom and are left as its framer took them.
fn decode(group: CesrGroup) -> Result<(), ParseError> {
    macro_rules! elements {
        ($($variant:ident),*) => {
            match group {
                $(CesrGroup::$variant(g) => g.iter().try_for_each(|e| e.map(drop)),)*
                CesrGroup::AttachmentGroup(frame) => {
                    frame.into_iter().try_for_each(|inner| decode(inner?))
                }
                _ => Ok(()),
            }
        };
    }
    elements!(
        ControllerIdxSigs,
        WitnessIdxSigs,
        NonTransReceiptCouples,
        TransReceiptQuadruples,
        FirstSeenReplayCouples,
        TransIdxSigGroups,
        SealSourceCouples,
        TransLastIdxSigGroups,
        SealSourceTriples,
        DigestSealSingles,
        MerkleRootSealSingles,
        SealSourceLastSingles,
        BackerRegistrarSealCouples,
        TypedDigestSealCouples,
        BlindedStateQuadruples,
        BoundStateSextuples,
        TypedMediaQuadruples
    )
}

/// Frame one message (a body and its attachments, or a bare group) at the head of `input` with
/// devrandom's framer, decode its attachment groups with devrandom's V1 group parser, and return
/// the number of bytes the message took.
fn frame_one(input: &[u8]) -> Result<usize, ParseError> {
    let span = MessageFramer::new(LIMITS)
        .advance(input, true)?
        .ok_or(ParseError::Truncated { missing: 1 })?;
    let frame = input
        .get(..span.total_len)
        .ok_or(ParseError::Truncated { missing: 1 })?;
    let attachments = &frame[span.body_len.unwrap_or(0).min(frame.len())..];
    for group in Groups::<V1>::over(attachments) {
        decode(group?)?;
    }
    Ok(span.total_len)
}

/// cesr.parse: the stream is accepted if devrandom frames it message by message to its end. The
/// adapter reports the accepted summary, never items: devrandom's framer reports spans of whole
/// messages, not where each item lay (README.md, "How a stream is parsed").
pub fn parse(stream: &[u8]) -> Value {
    let mut consumed = 0;
    while consumed < stream.len() {
        match frame_one(&stream[consumed..]) {
            Ok(0) => return reject(&ParseError::Truncated { missing: 1 }),
            Ok(n) => consumed += n,
            Err(error) => return reject(&error),
        }
    }
    json!({"accepted": {"consumed": consumed}})
}

/// cesr.encode: devrandom's `MatterBuilder` for the code, in the text domain.
pub fn encode(code: &str, raw: &[u8], binary: bool) -> Result<Value, OpError> {
    if binary {
        return Err(OpError::Unsupported(format!(
            "{E_BINARY}: This adapter encodes in the text domain only; devrandom's primitive \
             builder has no binary-domain output."
        )));
    }
    let code = MatterCode::from_str(code).map_err(|_| {
        OpError::Unsupported(format!(
            "{E_CODE}: devrandom's primitive code table has no code {code:?}."
        ))
    })?;
    let matter = MatterBuilder::new()
        .with_code(code)
        .with_raw(raw)
        .map_err(|e| {
            OpError::Unsupported(format!("{E_ENCODE}: devrandom refused the raw value: {e}."))
        })?
        .build()
        .map_err(|e| {
            OpError::Unsupported(format!("{E_ENCODE}: devrandom refused to encode: {e}."))
        })?;
    Ok(json!({"encoded": hex(matter.to_qb64().as_bytes())}))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
