//! cesr.parse and cesr.encode on cesrox 2.0.0-beta.8, with said 0.5.4 for version strings.
//!
//! The verdict comes from cesrox's own whole-stream loop, `cesrox::parse_and_send`, which calls
//! `cesrox::value::parse_value` until the stream is used up. cesrox returns values, not offsets,
//! so the adapter then measures where each item lay: it replays the public cesrox functions that
//! `parse_value` and `parse_group` call (`parse_value` itself, `genus_code`,
//! `short_universal_group_code`, `parse_group`, `group_code`, `parse_primitive`, `identifier`,
//! `serial_number_parser`), on the same text and the same bounded slices, records what each one
//! consumed, and checks every replayed value and every end against what cesrox returned. Nothing
//! is computed from a count or a code table. Where cesrox keeps no offsets for an item (a
//! first-seen couple's timestamp, pathed material, a TSP payload, a tag or a variable-length
//! primitive), the walk steps over it to the end cesrox gave it and an accepted stream is answered
//! with the protocol's summary instead of items. See ../README.md, "The keri-core 0.18.0 build".

use std::str::FromStr;
use std::sync::mpsc;

use cesrox::derivation_code::DerivationCode;
use cesrox::group::codes::GroupCode;
use cesrox::group::parsers::{group_code, parse_group};
use cesrox::group::Group;
use cesrox::payload::Payload;
use cesrox::primitives::codes::attached_signature_code::{AttachedSignatureCode, Index};
use cesrox::primitives::codes::basic::Basic;
use cesrox::primitives::codes::rand_128::Rand128Code;
use cesrox::primitives::codes::seed::SeedCode;
use cesrox::primitives::codes::self_addressing::SelfAddressing;
use cesrox::primitives::codes::self_signing::SelfSigning;
use cesrox::primitives::codes::timestamp::TimestampCode;
use cesrox::primitives::codes::PrimitiveCode;
use cesrox::primitives::parsers::{identifier, parse_primitive, serial_number_parser};
use cesrox::primitives::{Identifier, IndexedSignature};
use cesrox::universal_codes::{genus_code, short_universal_group_code, GenusCountCode};
use cesrox::value::{parse_value, Value as Cesr};
use said::version::SerializationInfo;
use serde::Deserialize;
use serde_json::{json, Value};

pub use crate::protocol::OpError;

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

/// A rejection found while measuring: its class and why, for standard error.
type Rejection = (&'static str, String);

pub fn parse(stream: &[u8]) -> Result<Value, OpError> {
    // cesrox 2.0 parses text (&str) only. keri-core 0.18.0 converts with from_utf8 before calling
    // it, but that is keri-core's step, not cesrox's verdict, so a stream that is not UTF-8 cannot
    // be handed to cesrox at all.
    let text = std::str::from_utf8(stream).map_err(|e| {
        OpError::Unsupported(format!(
            "{E_BINARY}: cesrox 2.0.0-beta.8 parses only text, and this stream is not UTF-8 \
             ({e}), so it cannot be handed to cesrox. This adapter does not declare \
             cesr.domain.binary."
        ))
    })?;
    let (tx, rx) = mpsc::channel();
    let verdict = cesrox::parse_and_send(text, &tx);
    drop(tx);
    let values: Vec<Cesr> = rx.iter().collect();
    if let Err(err) = verdict {
        eprintln!(
            "kcs-adapter-keriox: cesrox::parse_and_send rejected the stream after {} complete \
             value(s): {}",
            values.len(),
            truncate(&err.to_string())
        );
        return Ok(json!({"reject": {"class": REJECT_CESROX}}));
    }
    let mut walker = Walker {
        text,
        items: Vec::new(),
        unitemized: None,
    };
    let mut rest = text;
    for value in &values {
        match walker.value(rest, value)? {
            Ok(after) => rest = after,
            Err((class, why)) => {
                eprintln!("kcs-adapter-keriox: rejected: {why}");
                return Ok(json!({"reject": {"class": class}}));
            }
        }
    }
    if !rest.is_empty() {
        return Err(replay_error(format!(
            "cesrox accepted the whole stream, but the replay ended at offset {} of {}",
            walker.offset(rest),
            text.len()
        )));
    }
    if let Some(why) = walker.unitemized {
        eprintln!("kcs-adapter-keriox: cesrox accepted the stream; answering a summary: {why}");
        return Ok(json!({"accepted": {"consumed": text.len()}}));
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

fn group_count(code: &GroupCode) -> u16 {
    match code {
        GroupCode::IndexedControllerSignatures(n)
        | GroupCode::IndexedWitnessSignatures(n)
        | GroupCode::NontransferableReceiptCouples(n)
        | GroupCode::FirstSeenReplyCouples(n)
        | GroupCode::SealSourceCouples(n)
        | GroupCode::AnchoringEventSeals(n)
        | GroupCode::TransLastIdxSigGroups(n)
        | GroupCode::PathedMaterialQuadruple(n)
        | GroupCode::TSPPayload(n) => *n,
    }
}

struct Walker<'a> {
    text: &'a str,
    items: Vec<Value>,
    /// Why the stream cannot be itemized, once something cesrox does not itemize has been seen.
    unitemized: Option<String>,
}

impl<'a> Walker<'a> {
    /// The stream offset of a slice cesrox returned. Every slice it returns is a sub-slice of the
    /// input it was given, and every input is a sub-slice of the stream.
    fn offset(&self, slice: &str) -> usize {
        let at = slice.as_ptr() as usize - self.text.as_ptr() as usize;
        assert!(at <= self.text.len(), "a slice outside the stream");
        at
    }

    fn unitemized(&mut self, why: String) {
        self.unitemized.get_or_insert(why);
    }

    /// Measure one value cesrox returned, replaying `parse_value` on `s`, the same input cesrox
    /// parsed it from. Returns the remainder, or a rejection said made of a body.
    fn value(
        &mut self,
        s: &'a str,
        expected: &Cesr,
    ) -> Result<Result<&'a str, Rejection>, OpError> {
        let (rest, value) = ok_or_replay(parse_value(s), "value")?;
        if &value != expected {
            return Err(replay_error(format!(
                "the value at offset {} differs",
                self.offset(s)
            )));
        }
        let start = self.offset(s);
        let end = self.offset(rest);
        match &value {
            Cesr::Payload(payload) => {
                if let Err(rejection) = self.message(start, end, payload)? {
                    return Ok(Err(rejection));
                }
            }
            Cesr::VersionGenus(genus) => {
                // parse_value takes the leading '-' and hands the rest to genus_code.
                let (after, replayed) = ok_or_replay(genus_code(&s[1..]), "genus code")?;
                if &replayed != genus || after.len() != rest.len() {
                    return Err(replay_error("a genus code differs"));
                }
                let GenusCountCode::Keri { major, minor } = genus;
                let code = &s[..end - start];
                self.items.push(json!({
                    "kind": "genus", "start": start, "end": end, "code": code,
                    "genus": &code[2..5], "version": format!("{major}.{minor:02}"),
                }));
            }
            Cesr::Primitive(code, raw) => self.primitive_value(s, rest, code, raw),
            Cesr::UniversalGroup(code, inner) => {
                let (after_code, replayed) =
                    ok_or_replay(short_universal_group_code(&s[1..]), "universal count code")?;
                if &replayed != code {
                    return Err(replay_error("a universal count code differs"));
                }
                self.items.push(json!({
                    "kind": "counter", "code": &s[..code.hard_size()],
                    "size": code.value_size(), "start": start,
                    "end": self.offset(after_code), "group_end": end,
                }));
                // cesrox takes the group's quadlets and parses its members inside them alone.
                let mut members = &after_code[..after_code.len() - rest.len()];
                for member in inner {
                    match self.value(members, member)? {
                        Ok(after) => members = after,
                        Err(rejection) => return Ok(Err(rejection)),
                    }
                }
                if !members.is_empty() {
                    return Err(replay_error(format!(
                        "the universal group at offset {start} ends at {end}, its members at {}",
                        self.offset(members)
                    )));
                }
            }
            Cesr::SpecificGroup(group) => {
                let (after, replayed) = ok_or_replay(parse_group(s), "group")?;
                if &replayed != group || after.len() != rest.len() {
                    return Err(replay_error(format!("the group at offset {start} differs")));
                }
                let walked = self.replay(&s[..end - start], group, end)?;
                if walked != end {
                    return Err(replay_error(format!(
                        "the group at offset {start} ends at {end}, the replay at {walked}"
                    )));
                }
            }
            Cesr::Tag(_) => self.unitemized(format!(
                "cesrox reads the tag at offset {start} as a code with no raw value."
            )),
            Cesr::VariableLengthRaw(_) => self.unitemized(format!(
                "cesrox keeps the variable-length primitive at offset {start} in a private type."
            )),
        }
        Ok(Ok(rest))
    }

    /// A body. The inner Err is a rejection: said could not read its version string.
    fn message(
        &mut self,
        start: usize,
        end: usize,
        payload: &Payload,
    ) -> Result<Result<(), Rejection>, OpError> {
        let body = match payload {
            Payload::JSON(body) => body,
            Payload::CBOR(_) | Payload::MGPK(_) => {
                return Err(OpError::Unsupported(format!(
                    "{E_SERIALIZATION}: cesrox framed a CBOR or MessagePack body at offset \
                     {start}. keri-core 0.18.0 reads only JSON bodies, so the adapter has no \
                     keriox reader for this body's version string."
                )))
            }
        };
        let info = match serde_json::from_slice::<Head>(body) {
            Ok(head) => head.v,
            Err(err) => {
                return Ok(Err((
                    REJECT_VERSION,
                    format!(
                        "said could not read the version string of the body at offset \
                         {start}: {err}"
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
        Ok(Ok(()))
    }

    /// A primitive parse_value read on its own, with cesrox's merged code table.
    fn primitive_value(&mut self, s: &str, rest: &str, code: &PrimitiveCode, raw: &[u8]) {
        match code {
            PrimitiveCode::IndexedSignature(c) => self.indexed_item(s, rest, c, raw),
            other => self.primitive(s, rest, other.to_str(), raw),
        }
    }

    fn primitive(&mut self, start: &str, rest: &str, code: String, raw: &[u8]) {
        self.items.push(json!({
            "kind": "primitive", "code": code, "raw": hex(raw),
            "start": self.offset(start), "end": self.offset(rest),
        }));
    }

    fn indexed_item(&mut self, s: &str, rest: &str, code: &AttachedSignatureCode, raw: &[u8]) {
        // The code is the first hard_size() characters of what cesrox consumed for this item:
        // what is on the wire, delimited by cesrox's own hard size for the code it parsed.
        let mut item = json!({
            "kind": "indexed", "code": &s[..code.hard_size()], "raw": hex(raw),
            "index": code.index.current(),
            "start": self.offset(s), "end": self.offset(rest),
        });
        if let Index::Dual(_, ondex) | Index::BigDual(_, ondex) = code.index {
            item["ondex"] = json!(ondex);
        }
        self.items.push(item);
    }

    fn counter(&mut self, s: &'a str, group_end: usize) -> Result<&'a str, OpError> {
        let (rest, code) = ok_or_replay(group_code(s), "count code")?;
        self.items.push(json!({
            "kind": "counter", "code": &s[..code.hard_size()], "size": group_count(&code),
            "start": self.offset(s), "end": self.offset(rest), "group_end": group_end,
        }));
        Ok(rest)
    }

    fn signatures(
        &mut self,
        mut s: &'a str,
        expected: &[IndexedSignature],
    ) -> Result<&'a str, OpError> {
        for sig in expected {
            let (rest, replayed) = ok_or_replay(
                parse_primitive::<AttachedSignatureCode>(s),
                "indexed signature",
            )?;
            if &replayed != sig {
                return Err(replay_error("an indexed signature differs"));
            }
            self.indexed_item(s, rest, &replayed.0, &replayed.1);
            s = rest;
        }
        Ok(s)
    }

    /// A sequence number, measured with parse_primitive::<Rand128Code>, which returns the raw bytes
    /// it decoded, and checked against serial_number_parser, which the groups call.
    fn serial_number(&mut self, s: &'a str, expected: u64) -> Result<&'a str, OpError> {
        let (rest, (code, raw)) =
            ok_or_replay(parse_primitive::<Rand128Code>(s), "sequence number")?;
        let (rest_sn, sn) = ok_or_replay(serial_number_parser(s), "sequence number")?;
        if sn != expected || rest_sn.len() != rest.len() {
            return Err(replay_error("a sequence number differs"));
        }
        self.primitive(s, rest, code.to_str(), &raw);
        Ok(rest)
    }

    fn identifier(&mut self, s: &'a str, expected: &Identifier) -> Result<&'a str, OpError> {
        let (rest, id) = ok_or_replay(identifier(s), "identifier")?;
        if &id != expected {
            return Err(replay_error("an identifier differs"));
        }
        self.primitive(s, rest, PrimitiveCode::from(id.0).to_str(), &id.1);
        Ok(rest)
    }

    fn typed<C>(
        &mut self,
        s: &'a str,
        expected: &(C, Vec<u8>),
        what: &str,
    ) -> Result<&'a str, OpError>
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

    /// Items of one specific group, inside the bounded slice cesrox's parse_group consumed.
    /// Returns the offset at which the replay ended.
    fn replay(&mut self, s: &'a str, group: &Group, group_end: usize) -> Result<usize, OpError> {
        let start = self.offset(s);
        let mut s = self.counter(s, group_end)?;
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
            Group::AnchoringSeals(seals) => {
                for (id, sn, digest) in seals {
                    s = self.identifier(s, id)?;
                    s = self.serial_number(s, *sn)?;
                    s = self.typed::<SelfAddressing>(s, digest, "seal digest")?;
                }
            }
            Group::TransLastIdxSigGroups(groups) => {
                for (id, sigs) in groups {
                    s = self.identifier(s, id)?;
                    // cesrox reads each entry's signatures with parse_group on a -K group.
                    let (rest, inner) = ok_or_replay(parse_group(s), "nested signature group")?;
                    if inner != Group::IndexedControllerSignatures(sigs.clone()) {
                        return Err(replay_error("a nested signature group differs"));
                    }
                    let inner_end = self.offset(rest);
                    let walked = self.replay(&s[..s.len() - rest.len()], &inner, inner_end)?;
                    if walked != inner_end {
                        return Err(replay_error(
                            "a nested signature group's replay ended early",
                        ));
                    }
                    s = rest;
                }
            }
            Group::FirstSeenReplyCouples(_) => {
                self.unitemized(format!(
                    "cesrox reads the timestamps of the first-seen couples at offset {start} as \
                     dates and keeps no raw value."
                ));
                return Ok(group_end);
            }
            Group::PathedMaterialQuadruplet(..) => {
                self.unitemized(format!(
                    "cesrox keeps the path of the -P pathed-material group at offset {start} in \
                     private fields and its contents without offsets."
                ));
                return Ok(group_end);
            }
            Group::TSPPayload(_) => {
                self.unitemized(format!(
                    "cesrox keeps the members of the -Z group at offset {start} without offsets."
                ));
                return Ok(group_end);
            }
        }
        Ok(self.offset(s))
    }
}

/// The first of cesrox's matter code families whose FromStr accepts `code` and whose to_str()
/// gives it back exactly, as cesrox's merged PrimitiveCode. cesrox's own PrimitiveCode::from_str
/// tries the indexed signature table before the matter families, so it is not used here: a matter
/// code such as D would be read as an indexed code.
/// A matter code family's reading of a code: refused, read but not given back exactly, or found.
type Reading = Result<Option<PrimitiveCode>, cesrox::error::Error>;

fn matter_code(code: &str) -> Reading {
    fn exact<C: DerivationCode + FromStr<Err = cesrox::error::Error>>(
        code: &str,
        wrap: fn(C) -> PrimitiveCode,
    ) -> Reading {
        C::from_str(code).map(|c| (c.to_str() == code).then(|| wrap(c)))
    }
    let families: [fn(&str) -> Reading; 6] = [
        |c| exact::<Basic>(c, PrimitiveCode::Basic),
        |c| exact::<SelfAddressing>(c, PrimitiveCode::SelfAddressing),
        |c| exact::<SelfSigning>(c, PrimitiveCode::SelfSigning),
        |c| exact::<SeedCode>(c, PrimitiveCode::Seed),
        |c| exact::<Rand128Code>(c, PrimitiveCode::Random),
        |c| exact::<TimestampCode>(c, PrimitiveCode::Timestamp),
    ];
    let mut first_refusal = None;
    let mut read_inexactly = false;
    for family in families {
        match family(code) {
            Ok(Some(found)) => return Ok(Some(found)),
            Ok(None) => read_inexactly = true,
            Err(e) => {
                first_refusal.get_or_insert(e);
            }
        }
    }
    // Only when every family refuses: a family that reads the code and cannot give it back
    // exactly has not refused it.
    match (read_inexactly, first_refusal) {
        (false, Some(e)) => Err(e),
        _ => Ok(None),
    }
}

pub fn encode(code: &str, raw: &[u8], domain: &str) -> Result<Value, OpError> {
    if domain == "binary" {
        return Err(OpError::Unsupported(format!(
            "{E_BINARY}: cesrox 2.0.0-beta.8 has no binary-domain (qb2) encoding."
        )));
    }
    match matter_code(code) {
        // cesrox writes a primitive value with Value's Display, the same writer its own
        // round trips use.
        Ok(Some(found)) => {
            let text = Cesr::Primitive(found, raw.to_vec()).to_string();
            Ok(json!({"encoded": hex(text.as_bytes())}))
        }
        Ok(None) => Err(OpError::Unsupported(format!(
            "{E_CODE}: cesrox 2.0.0-beta.8 reads code {} but no encoder gives it back exactly.",
            Value::String(code.into())
        ))),
        // cesrox refusing the code is its answer, reported as a rejection whose class is the
        // variant of cesrox's own error (adapter protocol, cesr.encode).
        Err(e) => {
            let class = format!("{e:?}");
            let class = class.split('(').next().unwrap_or_default().to_string();
            eprintln!("cesrox refused to encode code {code:?}: {e}");
            Ok(json!({"reject": {"class": class}}))
        }
    }
}
