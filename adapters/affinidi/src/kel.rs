//! keri.process: deliver each message, in order, to fresh state, and report what Affinidi's `Kever`
//! decided about it.
//!
//! Every accept or reject is Affinidi's: `Kever::new`, `Kever::new_delegated`,
//! `Kever::verify_update`, `Kever::verify_update_delegated` and
//! `Kever::verify_witness_receipts_static` do all the checking. What this module adds is the routing
//! Affinidi leaves to its caller, declared as `keri.routing` in hello's `composes`: it picks which of
//! those calls a message needs from its ilk and prefix, holds one `Kever` per prefix, records the
//! bodies Affinidi accepted, and answers Affinidi's `DelegatorAnchors` lookup from that record only.
//! README.md, "keri.process", says where each reported value comes from.

use std::collections::BTreeMap;

use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, Attachment, ParsedMessage};
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_core::{CoreError, DelegationProof, DelegatorAnchors};
use affinidi_keri_crypto::{Siger, Verfer};
use serde_json::{Map, Value, json};

use crate::protocol::{E_MALFORMED, OpError, decode_hex};

pub const E_PERSPECTIVE: &str = "e.feature.unsupported.perspective.f";

/// One event body Affinidi accepted, kept so that a later delivery of the same body reads as seen
/// and so that a delegated event can be checked against its delegator's accepted anchors.
struct Accepted {
    prefix: String,
    sn: u64,
    said: String,
    body: Vec<u8>,
    anchors: Vec<Value>,
}

/// Fresh for every request: the protocol requires each request to start from empty state.
#[derive(Default)]
struct Validator {
    kevers: BTreeMap<String, Kever>,
    accepted: Vec<Accepted>,
}

impl DelegatorAnchors for Validator {
    /// Answers only from events Affinidi accepted, which is the trait's whole contract.
    fn anchors_at(
        &self,
        delegator: &str,
        sn: u64,
        said: &str,
    ) -> Result<Option<Vec<Value>>, CoreError> {
        Ok(self
            .accepted
            .iter()
            .find(|a| a.prefix == delegator && a.sn == sn && a.said == said)
            .map(|a| a.anchors.clone()))
    }
}

/// What the adapter knows about a delivered message: the body bytes of the key event it carries,
/// when Affinidi could read one.
type Ident = Option<Vec<u8>>;

impl Validator {
    fn holds(&self, ident: &Ident) -> bool {
        ident
            .as_ref()
            .is_some_and(|body| self.accepted.iter().any(|a| &a.body == body))
    }

    /// Deliver one stream. Returns the body of the key event it carries, if Affinidi could parse
    /// one, and why it was not accepted, if it was not.
    fn deliver(&mut self, stream: &[u8]) -> (Ident, Option<String>) {
        let parsed = match parser::parse_all(stream) {
            Ok(mut messages) if messages.len() == 1 => messages.remove(0),
            Ok(messages) => {
                return (
                    None,
                    Some(format!(
                        "the stream holds {} messages, not exactly one",
                        messages.len()
                    )),
                );
            }
            Err(e) => return (None, Some(format!("Affinidi cannot parse it: {e}"))),
        };
        let ilk = match parsed.serder.ilk() {
            Ok(ilk) => ilk,
            Err(e) => return (None, Some(format!("Affinidi cannot read its ilk: {e}"))),
        };
        if ilk == "rct" {
            return (
                None,
                Some(
                    "Affinidi's validator has no processing for a receipt message: Kever counts \
                     only receipt couples attached to the event they receipt"
                        .into(),
                ),
            );
        }
        if !matches!(ilk.as_str(), "icp" | "dip" | "rot" | "ixn" | "drt") {
            return (None, Some(format!("{ilk} is not a key event")));
        }
        // A body Affinidi already accepted is refused again by Kever (its sequence number is no
        // longer next), but it is the same event, and reads as seen by its body.
        let body = parsed.serder.raw().to_vec();
        let reason = self.validate(&ilk, &parsed).err().map(|e| e.to_string());
        (Some(body), reason)
    }

    /// Hand one key event to the Kever call its ilk needs, and record it if Affinidi accepts it.
    fn validate(&mut self, ilk: &str, msg: &ParsedMessage) -> Result<(), CoreError> {
        let serder = &msg.serder;
        let prefix = serder.prefix()?;
        let sn = serder.sn()?;
        let said = serder.said()?;
        let sigs = controller_sigs(msg);
        let couples = receipt_couples(msg);
        match ilk {
            "icp" | "dip" => {
                if self.kevers.contains_key(&prefix) {
                    return Err(CoreError::Validation(format!(
                        "an inception of {prefix} has already been accepted"
                    )));
                }
                let verfers = verfers(serder.sad())?;
                let kever = if ilk == "icp" {
                    Kever::new(serder, &sigs, &verfers)?
                } else {
                    Kever::new_delegated(serder, &sigs, &verfers, &proof(msg)?, self)?
                };
                kever.verify_witness_receipts(serder.raw(), &couples)?;
                self.kevers.insert(prefix.clone(), kever);
            }
            _ => {
                let kever = self.kevers.get(&prefix).ok_or_else(|| {
                    CoreError::Validation(format!("no key state is held for {prefix}"))
                })?;
                let state = if ilk == "drt" {
                    kever.verify_update_delegated(serder, &sigs, &proof(msg)?, self)?
                } else {
                    kever.verify_update(serder, &sigs)?
                };
                Kever::verify_witness_receipts_static(
                    serder.raw(),
                    &couples,
                    &state.backers,
                    state.backer_threshold,
                )?;
                self.kevers
                    .entry(prefix.clone())
                    .and_modify(|kever| kever.apply_verified_update(state));
            }
        }
        let anchors = serder
            .sad()
            .get("a")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        self.accepted.push(Accepted {
            prefix,
            sn,
            said,
            body: serder.raw().to_vec(),
            anchors,
        });
        Ok(())
    }
}

/// Every controller signature attached, across all `-A` groups, as Affinidi's direct mode gathers
/// them.
fn controller_sigs(msg: &ParsedMessage) -> Vec<Siger> {
    msg.attachments
        .iter()
        .filter_map(|a| match a {
            Attachment::ControllerSigs(s) => Some(s.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Every non-transferable receipt couple attached to the event itself, as Affinidi's direct mode
/// and did:webs verifier count them. Witness indexed signatures (`-B`) are not among them:
/// Affinidi parses them and counts none.
fn receipt_couples(msg: &ParsedMessage) -> Vec<(String, Vec<u8>)> {
    msg.attachments
        .iter()
        .filter_map(|a| match a {
            Attachment::ReceiptCouples(c) => Some(c.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// The event's `k` field as Affinidi's verifiers, as its direct mode builds them.
fn verfers(sad: &Value) -> Result<Vec<Verfer>, CoreError> {
    let keys = sad
        .get("k")
        .and_then(Value::as_array)
        .ok_or_else(|| CoreError::MissingField("k".into()))?;
    keys.iter()
        .map(|k| {
            let k = k
                .as_str()
                .ok_or_else(|| CoreError::Validation("a key in k is not a string".into()))?;
            Verfer::from_qb64(k).map_err(CoreError::Crypto)
        })
        .collect()
}

/// The delegation proof from the first seal source couple, as Affinidi's did:webs verifier reads it.
fn proof(msg: &ParsedMessage) -> Result<DelegationProof, CoreError> {
    let (sn, said) = msg.seal_source_couples().first().ok_or_else(|| {
        CoreError::Validation(
            "the delegated event carries no seal source couple, and Affinidi's Kever needs one \
             to find its delegator's anchoring event"
                .into(),
        )
    })?;
    DelegationProof::from_seal_source_couple(sn, said)
}

/// A threshold in the protocol's forms: a numeric one in hex, as KERI writes it, from the number
/// Affinidi holds; a weighted one as Affinidi renders it.
fn threshold(t: &Threshold) -> Value {
    match t {
        Threshold::Simple(n) => json!(format!("{n:x}")),
        weighted => weighted.to_json_value(),
    }
}

fn key_state(kever: &Kever) -> Value {
    let s = kever.state();
    json!({
        "sn": s.sn,
        "said": s.last_event_digest,
        "keys": s.keys,
        "kt": threshold(&s.threshold),
        "ndigs": s.next_keys,
        "nt": threshold(&s.next_threshold),
        "wits": s.backers,
        "bt": format!("{:x}", s.backer_threshold),
        "delegator": s.delegator,
    })
}

fn reading(validator: &Validator, ident: &Ident) -> &'static str {
    if validator.holds(ident) {
        "seen"
    } else {
        "rejected"
    }
}

/// The messages' streams, or Malformed naming what is wrong with the request.
fn streams(request: &Map<String, Value>) -> Result<Vec<Vec<u8>>, OpError> {
    let bad = |what: &str| OpError::Malformed(format!("{E_MALFORMED}: {what}"));
    let messages = request
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("\"messages\" must be a list of objects."))?;
    messages
        .iter()
        .map(|m| {
            let m = m
                .as_object()
                .ok_or_else(|| bad("\"messages\" must be a list of objects."))?;
            m.get("stream")
                .and_then(Value::as_str)
                .and_then(decode_hex)
                .ok_or_else(|| {
                    bad("every \"stream\" in \"messages\" must be a lowercase hex string.")
                })
        })
        .collect()
}

fn validator_perspective(request: &Map<String, Value>) -> Result<(), OpError> {
    let perspective = request
        .get("perspective")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OpError::Malformed(format!("{E_MALFORMED}: \"perspective\" must be an object."))
        })?;
    match perspective.get("role") {
        Some(Value::String(role)) if role == "validator" => Ok(()),
        role => Err(OpError::Unsupported(format!(
            "{E_PERSPECTIVE}: This adapter reports only an ordinary validator's perspective, \
             not {}.",
            role.cloned().unwrap_or(Value::Null)
        ))),
    }
}

pub fn process(request: &Map<String, Value>) -> Result<Value, OpError> {
    validator_perspective(request)?;
    let streams = streams(request)?;
    let mut validator = Validator::default();
    let mut delivered = Vec::with_capacity(streams.len());
    for stream in &streams {
        let (ident, reason) = validator.deliver(stream);
        let initial = reading(&validator, &ident);
        delivered.push((ident, initial, reason));
    }
    let dispositions: Vec<Value> = delivered
        .iter()
        .map(|(ident, initial, reason)| {
            let last = reading(&validator, ident);
            let mut d = json!({"initial": initial, "final": last, "trunk": last == "seen"});
            if let Some(reason) = reason.as_ref().filter(|_| *initial != "seen") {
                d["reason"] = json!(reason);
            }
            d
        })
        .collect();
    let key_states: Map<String, Value> = validator
        .kevers
        .iter()
        .map(|(prefix, kever)| (prefix.clone(), key_state(kever)))
        .collect();
    Ok(json!({"dispositions": dispositions, "key_states": key_states}))
}
