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

/// The class of a refusal by devrandom: the name of the error's own type and its variant, both
/// read from the error value, never asserted by the adapter.
fn class_of<E: std::fmt::Debug>(error: &E) -> String {
    let path = std::any::type_name::<E>();
    let ty = path.rsplit("::").next().unwrap_or(path);
    let debug = format!("{error:?}");
    let variant = debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default();
    format!("{ty}::{variant}")
}

fn reject(class: String, reason: &str) -> Value {
    eprintln!("devrandom rejected the stream: {reason}");
    json!({"reject": {"class": class}})
}

/// Why a stream did not frame: an error devrandom raised, or the framer reporting no frame or a
/// span the input does not hold, which the adapter names as its own observation rather than
/// dressing it as a library error.
enum Unframed {
    Library(ParseError),
    NoFrame(&'static str),
}

impl From<ParseError> for Unframed {
    fn from(error: ParseError) -> Self {
        Self::Library(error)
    }
}

impl Unframed {
    fn answer(&self) -> Value {
        match self {
            Self::Library(error) => reject(class_of(error), &error.to_string()),
            Self::NoFrame(what) => reject(format!("MessageFramer::{what}"), what),
        }
    }
}

/// Decode every element of one group, so that a malformed primitive inside a group devrandom has
/// framed is rejected, as it is when devrandom's own message layer reads the group. A `-V`
/// attachment frame's inner groups are decoded the same way, however deep devrandom's framer
/// allowed the nesting (its limits bound the depth). Other quadlet-counted frames are carried
/// opaquely by devrandom and are left as its framer took them.
fn decode(group: CesrGroup) -> Result<(), ParseError> {
    macro_rules! elements {
        ([$($counted:ident),*], [$($opaque:ident),*]) => {
            match group {
                $(CesrGroup::$counted(g) => g.iter().try_for_each(|e| e.map(drop)),)*
                CesrGroup::AttachmentGroup(frame) => {
                    frame.into_iter().try_for_each(|inner| decode(inner?))
                }
                $(CesrGroup::$opaque(_) => Ok(()),)*
            }
        };
    }
    // Every variant is named, so a group kind added to cesr-stream fails to compile here rather
    // than being accepted unread.
    elements!(
        [
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
        ],
        [
            PathedMaterialCouples,
            GenericGroup,
            BodyWithAttachmentGroup,
            NonNativeBodyGroup,
            ESSRPayloadGroup,
            DatagramSegmentGroup,
            ESSRWrapperGroup,
            FixBodyGroup,
            MapBodyGroup,
            GenericMapGroup,
            GenericListGroup
        ]
    )
}

/// Frame one message (a body and its attachments, or a bare group) at the head of `input` with
/// devrandom's framer, decode its attachment groups with devrandom's V1 group parser, and return
/// the number of bytes the message took.
fn frame_one(input: &[u8]) -> Result<usize, Unframed> {
    let span = MessageFramer::new(LIMITS)
        .advance(input, true)?
        .ok_or(Unframed::NoFrame("NoFrameAtEndOfInput"))?;
    let frame = input
        .get(..span.total_len)
        .filter(|f| !f.is_empty())
        .ok_or(Unframed::NoFrame("SpanOutsideInput"))?;
    let attachments = frame
        .get(span.body_len.unwrap_or(0)..)
        .ok_or(Unframed::NoFrame("SpanOutsideInput"))?;
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
            Ok(n) => consumed += n,
            Err(unframed) => return unframed.answer(),
        }
    }
    json!({"accepted": {"consumed": consumed}})
}

/// cesr.encode: devrandom's `MatterBuilder` for the code, in the text domain. A code devrandom's
/// table does not have, a raw value the builder refuses, and a code the builder cannot size are
/// devrandom's refusals, answered as rejections (docs/adapter-protocol.md, `cesr.encode`).
pub fn encode(code: &str, raw: &[u8], binary: bool) -> Result<Value, OpError> {
    if binary {
        return Err(OpError::Unsupported(format!(
            "{E_BINARY}: This adapter encodes in the text domain only; devrandom's primitive \
             builder has no binary-domain output."
        )));
    }
    let refused = |class: String, reason: String| {
        eprintln!("devrandom refused to encode {code:?}: {reason}");
        Ok(json!({"reject": {"class": class}}))
    };
    let Ok(matter_code) = MatterCode::from_str(code) else {
        return refused(
            "ParsingError::UnknownCode".to_string(),
            "no such code".to_string(),
        );
    };
    let builder = match MatterBuilder::new().with_code(matter_code).with_raw(raw) {
        Ok(builder) => builder,
        Err(e) => return refused(class_of(&e), format!("{e}")),
    };
    match builder.build() {
        Ok(matter) => Ok(json!({"encoded": hex(matter.to_qb64().as_bytes())})),
        Err(e) => refused(class_of(&e), format!("{e}")),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
