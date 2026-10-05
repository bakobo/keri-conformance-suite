//! cesr.parse and cesr.encode on cesrox 0.1.8, with said 0.4.3 for version strings.
//!
//! The verdict comes from cesrox's own whole-stream loop, `cesrox::parse_and_send`. cesrox returns
//! values, not offsets, so the adapter then measures where each item lay: it replays the same
//! public cesrox parser functions that cesrox's `parse` and `parse_group` call, on the same bytes,
//! records the offsets each one consumed, and checks that every replayed value and every end
//! equals what cesrox's own call returned. Nothing is computed from a count or a code table. See
//! README.md, "Measured, not sourced". Where cesrox does not retain what an item needs (a
//! first-seen couple's timestamp, a pathed-material group), the walk steps over that group to
//! the end cesrox's own `parse_group` gave it, and an accepted stream is answered with the
//! protocol's summary instead of items.

use std::str::FromStr;
use std::sync::mpsc;

use cesrox::derivation_code::DerivationCode;
use cesrox::group::codes::GroupCode;
use cesrox::group::parsers::{group_code, parse_group};
use cesrox::group::Group;
use cesrox::payload::{parse_payload, Payload};
use cesrox::primitives::codes::attached_signature_code::{AttachedSignatureCode, Index};
use cesrox::primitives::codes::basic::Basic;
use cesrox::primitives::codes::self_addressing::SelfAddressing;
use cesrox::primitives::codes::self_signing::SelfSigning;
use cesrox::primitives::codes::serial_number::SerialNumberCode;
use cesrox::primitives::parsers::{identifier, parse_primitive, serial_number_parser};
use cesrox::primitives::{CesrPrimitive, Identifier, IdentifierCode, IndexedSignature};
use cesrox::ParsedData;
use said::version::SerializationInfo;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub enum OpError {
    Harness(String),
    Unsupported(String),
}

pub const E_REPLAY: &str = "e.self.unknown.replay-mismatch.f";
pub const E_SERIALIZATION: &str = "e.feature.unsupported.serialization.f";
pub const E_BINARY: &str = "e.feature.unsupported.binary-domain.f";
pub const E_CODE: &str = "e.feature.unsupported.code.f";

/// The rejection class for a stream cesrox's whole-stream loop refuses.
pub const REJECT_CESROX: &str = "ParsingError";
/// The rejection class for a body whose "v" field said cannot read as a version string.
pub const REJECT_VERSION: &str = "VersionString";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn replay_error(what: impl std::fmt::Display) -> OpError {
    OpError::Harness(format!(
        "{E_REPLAY}: Replaying cesrox's parser to measure offsets did not reproduce what cesrox \
         itself returned ({what}), so no offsets are reported."
    ))
}

fn ok_or_replay<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> Result<T, OpError> {
    r.map_err(|e| replay_error(format!("{what}: {e:?}")))
}

/// The part of a KERI body keri-core reads first: its version string, deserialized with said's
/// `SerializationInfo` as keri-core's event types do.
#[derive(Deserialize)]
struct Head {
    v: SerializationInfo,
}

pub fn parse(stream: &[u8]) -> Result<Value, OpError> {
    let (tx, rx) = mpsc::channel();
    let verdict = cesrox::parse_and_send(stream, &tx);
    drop(tx);
    let messages: Vec<ParsedData> = rx.iter().collect();
    if let Err(err) = verdict {
        eprintln!(
            "kcs-adapter-keriox: cesrox::parse_and_send rejected the stream after {} complete \
             message(s): {}",
            messages.len(),
            truncate(&err.to_string())
        );
        return Ok(json!({"reject": {"class": REJECT_CESROX}}));
    }
    let mut walker = Walker {
        stream,
        items: Vec::new(),
        unitemized: None,
    };
    let mut at = 0;
    for message in &messages {
        match walker.message(at, message)? {
            Ok(end) => at = end,
            Err((class, why)) => {
                eprintln!("kcs-adapter-keriox: rejected: {why}");
                return Ok(json!({"reject": {"class": class}}));
            }
        }
    }
    if at != stream.len() {
        return Err(replay_error(format!(
            "cesrox accepted the whole stream, but the replay ended at offset {at} of {}",
            stream.len()
        )));
    }
    if let Some(why) = walker.unitemized {
        eprintln!("kcs-adapter-keriox: cesrox accepted the stream; answering a summary: {why}");
        return Ok(json!({"accepted": {"consumed": at}}));
    }
    Ok(json!({"items": walker.items}))
}

fn truncate(s: &str) -> String {
    if s.len() <= 200 {
        return s.to_string();
    }
    let mut cut = 200;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &s[..cut])
}

struct Walker<'a> {
    stream: &'a [u8],
    items: Vec<Value>,
    /// Why the stream cannot be itemized, once a group cesrox does not itemize has been seen.
    unitemized: Option<String>,
}

impl<'a> Walker<'a> {
    /// The stream offset of a slice cesrox returned. Every slice it returns is a sub-slice of the
    /// input it was given, and every input is a sub-slice of the stream.
    fn offset(&self, slice: &[u8]) -> usize {
        let at = slice.as_ptr() as usize - self.stream.as_ptr() as usize;
        assert!(at <= self.stream.len(), "a slice outside the stream");
        at
    }

    /// Measure one message cesrox returned. The inner Err is a rejection: said could not read the
    /// body's version string.
    fn message(
        &mut self,
        start: usize,
        expected: &ParsedData,
    ) -> Result<Result<usize, (&'static str, String)>, OpError> {
        let (rest, payload) = ok_or_replay(parse_payload(&self.stream[start..]), "body")?;
        if payload != expected.payload {
            return Err(replay_error("the body differs"));
        }
        let end = self.offset(rest);
        let body = match &payload {
            Payload::JSON(body) => body,
            Payload::CBOR(_) | Payload::MGPK(_) => {
                return Err(OpError::Unsupported(format!(
                    "{E_SERIALIZATION}: cesrox framed a CBOR or MessagePack body at offset \
                     {start}. keri-core 0.17.13 reads only JSON bodies, so the adapter has no keriox \
                     reader for this body's version string."
                )))
            }
        };
        let info = match serde_json::from_slice::<Head>(body) {
            Ok(head) => head.v,
            Err(err) => {
                return Ok(Err((
                    REJECT_VERSION,
                    format!(
                    "said could not read the version string of the body at offset {start}: {err}"
                ),
                )))
            }
        };
        self.items.push(json!({
            "kind": "message", "start": start, "end": end,
            "proto": info.protocol_code,
            "version": format!("{}.{}", info.major_version, info.minor_version),
            "serialization": info.kind.to_str(),
            "size": info.size,
        }));
        let mut at = end;
        for group in &expected.attachments {
            at = self.group(at, group)?;
        }
        Ok(Ok(at))
    }

    /// Measure one attachment group: cesrox's parse_group gives the group and where it ends; the
    /// replay inside [start, group_end) gives each item's place.
    fn group(&mut self, start: usize, expected: &Group) -> Result<usize, OpError> {
        let (rest, group) = ok_or_replay(parse_group(&self.stream[start..]), "group")?;
        if &group != expected {
            return Err(replay_error(format!("the group at offset {start} differs")));
        }
        let group_end = self.offset(rest);
        let bounded = &self.stream[start..group_end];
        let end = self.replay(bounded, &group, group_end)?;
        if end != group_end {
            return Err(replay_error(format!(
                "the group at offset {start} ends at {group_end}, the replay at {end}"
            )));
        }
        Ok(group_end)
    }

    fn counter(
        &mut self,
        s: &'a [u8],
        group_end: Option<usize>,
    ) -> Result<(&'a [u8], GroupCode, usize), OpError> {
        let (rest, code) = ok_or_replay(group_code(s), "count code")?;
        let text = code.to_str();
        let size = match code {
            GroupCode::IndexedControllerSignatures(n)
            | GroupCode::IndexedWitnessSignatures(n)
            | GroupCode::NontransferableReceiptCouples(n)
            | GroupCode::SealSourceCouples(n)
            | GroupCode::FirstSeenReplyCouples(n)
            | GroupCode::TransferableIndexedSigGroups(n)
            | GroupCode::LastEstSignaturesGroups(n)
            | GroupCode::Frame(n)
            | GroupCode::PathedMaterialQuadruple(n) => n,
        };
        let index = self.items.len();
        self.items.push(json!({
            "kind": "counter", "code": &text[..code.hard_size()], "size": size,
            "start": self.offset(s), "end": self.offset(rest), "group_end": group_end,
        }));
        Ok((rest, code, index))
    }

    fn set_group_end(&mut self, index: usize, end: usize) {
        self.items[index]["group_end"] = json!(end);
    }

    fn primitive(&mut self, start: &[u8], rest: &[u8], code: String, raw: &[u8]) {
        self.items.push(json!({
            "kind": "primitive", "code": code, "raw": hex(raw),
            "start": self.offset(start), "end": self.offset(rest),
        }));
    }

    fn indexed(&mut self, s: &'a [u8], expected: &IndexedSignature) -> Result<&'a [u8], OpError> {
        let (rest, sig) = ok_or_replay(
            parse_primitive::<AttachedSignatureCode>(s),
            "indexed signature",
        )?;
        if &sig != expected {
            return Err(replay_error("an indexed signature differs"));
        }
        let (code, raw) = sig;
        // The code is the first hard_size() characters of what cesrox consumed for this item:
        // what is on the wire, delimited by cesrox's own hard size for the code it parsed.
        let hard = String::from_utf8_lossy(&s[..code.hard_size()]).into_owned();
        let mut item = json!({
            "kind": "indexed", "code": hard, "raw": hex(&raw),
            "index": code.index.current(),
            "start": self.offset(s), "end": self.offset(rest),
        });
        if let Index::Dual(_, ondex) | Index::BigDual(_, ondex) = code.index {
            item["ondex"] = json!(ondex);
        }
        self.items.push(item);
        Ok(rest)
    }

    fn signatures(
        &mut self,
        mut s: &'a [u8],
        expected: &[IndexedSignature],
    ) -> Result<&'a [u8], OpError> {
        for sig in expected {
            s = self.indexed(s, sig)?;
        }
        Ok(s)
    }

    /// A sequence number, measured with parse_primitive::<SerialNumberCode>, which returns the raw
    /// bytes it decoded, and checked against serial_number_parser, which the groups call.
    fn serial_number(&mut self, s: &'a [u8], expected: u64) -> Result<&'a [u8], OpError> {
        let (rest, (code, raw)) =
            ok_or_replay(parse_primitive::<SerialNumberCode>(s), "sequence number")?;
        let (rest_sn, sn) = ok_or_replay(serial_number_parser(s), "sequence number")?;
        if sn != expected || rest_sn.len() != rest.len() {
            return Err(replay_error("a sequence number differs"));
        }
        self.primitive(s, rest, code.to_str(), &raw);
        Ok(rest)
    }

    fn identifier(&mut self, s: &'a [u8], expected: &Identifier) -> Result<&'a [u8], OpError> {
        let (rest, id) = ok_or_replay(identifier(s), "identifier")?;
        if &id != expected {
            return Err(replay_error("an identifier differs"));
        }
        let code = match &id.0 {
            IdentifierCode::Basic(b) => b.to_str(),
            IdentifierCode::SelfAddressing(sa) => sa.to_str(),
        };
        self.primitive(s, rest, code, &id.1);
        Ok(rest)
    }

    fn typed<C>(
        &mut self,
        s: &'a [u8],
        expected: &(C, Vec<u8>),
        what: &str,
    ) -> Result<&'a [u8], OpError>
    where
        C: DerivationCode + FromStr<Err = cesrox::error::Error> + PartialEq + std::fmt::Debug,
    {
        let (rest, value) = ok_or_replay(parse_primitive::<C>(s), what)?;
        if value.0 != expected.0 || value.1 != expected.1 {
            return Err(replay_error(format!("a {what} differs")));
        }
        self.primitive(s, rest, value.0.to_str(), &value.1);
        Ok(rest)
    }

    /// Items of one group, inside the bounded slice cesrox's parse_group consumed. Returns the
    /// offset at which the replay ended.
    fn replay(&mut self, s: &'a [u8], group: &Group, group_end: usize) -> Result<usize, OpError> {
        let (mut s, _code, _) = self.counter(s, Some(group_end))?;
        match group {
            Group::IndexedControllerSignatures(sigs) | Group::IndexedWitnessSignatures(sigs) => {
                s = self.signatures(s, sigs)?;
            }
            Group::NontransReceiptCouples(couples) => {
                for (key, sig) in couples {
                    s = self.typed::<Basic>(s, key, "receipt key")?;
                    s = self.typed::<SelfSigning>(s, sig, "receipt signature")?;
                }
            }
            Group::SourceSealCouples(couples) => {
                for (sn, digest) in couples {
                    s = self.serial_number(s, *sn)?;
                    s = self.typed::<SelfAddressing>(s, digest, "seal digest")?;
                }
            }
            Group::FirstSeenReplyCouples(_) => {
                self.unitemized.get_or_insert(format!(
                    "cesrox reads the timestamp (1AAG) of the first-seen couples in the group \
                     ending at offset {group_end} as text and never decodes its raw value."
                ));
                return Ok(group_end);
            }
            Group::TransIndexedSigGroups(groups) => {
                for (prefix, sn, digest, sigs) in groups {
                    s = self.identifier(s, prefix)?;
                    s = self.serial_number(s, *sn)?;
                    s = self.typed::<SelfAddressing>(s, digest, "event digest")?;
                    let (rest, _, index) = self.counter(s, None)?;
                    s = self.signatures(rest, sigs)?;
                    let end = self.offset(s);
                    self.set_group_end(index, end);
                }
            }
            Group::LastEstSignaturesGroups(groups) => {
                for (prefix, sigs) in groups {
                    s = self.identifier(s, prefix)?;
                    let (rest, _, index) = self.counter(s, None)?;
                    s = self.signatures(rest, sigs)?;
                    let end = self.offset(s);
                    self.set_group_end(index, end);
                }
            }
            Group::Frame(inner) => {
                for expected in inner {
                    let (rest, group) = ok_or_replay(parse_group(s), "framed group")?;
                    if &group != expected {
                        return Err(replay_error("a framed group differs"));
                    }
                    let inner_end = self.offset(rest);
                    let bounded = &s[..s.len() - rest.len()];
                    let end = self.replay(bounded, &group, inner_end)?;
                    if end != inner_end {
                        return Err(replay_error("a framed group's replay ended early"));
                    }
                    s = rest;
                }
            }
            Group::PathedMaterialQuadruplet(..) => {
                self.unitemized.get_or_insert(format!(
                    "cesrox keeps the path of the -L pathed-material group ending at offset \
                     {group_end} in private fields and its contents without offsets."
                ));
                return Ok(group_end);
            }
        }
        Ok(self.offset(s))
    }
}

pub fn encode(code: &str, raw: &[u8], domain: &str) -> Result<Value, OpError> {
    if domain == "binary" {
        return Err(OpError::Unsupported(format!(
            "{E_BINARY}: cesrox 0.1.8 has no binary-domain (qb2) encoding."
        )));
    }
    // cesrox splits the master code table into one type per family. The first family whose
    // FromStr accepts the code and whose to_str() gives it back exactly is the one cesrox means.
    let raw = raw.to_vec();
    let text = if let Some(c) = Basic::from_str(code).ok().filter(|c| c.to_str() == code) {
        (c, raw).to_str()
    } else if let Some(c) = SelfAddressing::from_str(code)
        .ok()
        .filter(|c| c.to_str() == code)
    {
        (c, raw).to_str()
    } else if let Some(c) = SelfSigning::from_str(code)
        .ok()
        .filter(|c| c.to_str() == code)
    {
        (c, raw).to_str()
    } else {
        return Err(OpError::Unsupported(format!(
            "{E_CODE}: cesrox 0.1.8 has no primitive encoder for code {}.",
            Value::String(code.into())
        )));
    };
    Ok(json!({"encoded": hex(text.as_bytes())}))
}
