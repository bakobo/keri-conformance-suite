//! keri.process: deliver each message, in order, to fresh state, and report what Affinidi's `Kever`
//! decided about it.
//!
//! Every acceptance is Affinidi's: `Kever::new`, `Kever::new_delegated`, `Kever::verify_update`,
//! `Kever::verify_update_delegated` and `Kever::verify_witness_receipts_static` do all the checking,
//! and their refusals are Affinidi's verdicts. What this module adds is the routing
//! Affinidi leaves to its caller, declared as `keri.routing` in hello's `composes`: it picks which of
//! those calls a message needs from its ilk and prefix, holds one `Kever` per prefix, records the
//! bodies Affinidi accepted, and answers Affinidi's `DelegatorAnchors` lookups from that record and
//! from the `Kever`s only. A message routing cannot hand to a Kever is reported rejected with a
//! reason marked `routing:`. The trunk is read from Affinidi: an accepted event is on it when the
//! prior-event links of the accepted events lead to it from the last event Affinidi's `Kever`
//! holds, so an interaction a superseding rotation displaced stays seen but leaves the trunk.
//! README.md, "keri.process", says where each reported value comes from.

use std::collections::{BTreeMap, HashMap, HashSet};

use affinidi_keri_core::kever::Kever;
use affinidi_keri_core::parser::{self, Attachment, ParsedMessage};
use affinidi_keri_core::sad::SadValue;
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_core::{CoreError, DelegationProof, DelegatorAnchors};
use affinidi_keri_crypto::{Siger, Verfer};
use serde_json::{Map, Value, json};

use crate::protocol::{E_MALFORMED, OpError, decode_hex};

pub const E_PERSPECTIVE: &str = "e.feature.unsupported.perspective.f";

/// Fresh for every request: the protocol requires each request to start from empty state.
#[derive(Default)]
struct Validator {
    kevers: BTreeMap<String, Kever>,
    /// The body of every event Affinidi accepted, so that a later delivery of the same body reads
    /// as seen. A set, so that a long KEL costs one lookup per reading rather than a scan.
    bodies: HashSet<Vec<u8>>,
    /// The anchors (`a`) of every accepted event, by prefix, sequence number and SAID, so that a
    /// delegated event is checked only against its delegator's accepted events.
    anchors: HashMap<(String, u64, String), Vec<SadValue>>,
    /// Every accepted event by prefix and SAID: its body, and the SAID its `p` names (none for an
    /// inception), so that the trunk can be followed back from the last event a Kever holds.
    events: HashMap<(String, String), (Vec<u8>, Option<String>)>,
}

impl DelegatorAnchors for Validator {
    /// Answers only from events Affinidi accepted, which is the trait's whole contract.
    fn anchors_at(
        &self,
        delegator: &str,
        sn: u64,
        said: &str,
    ) -> Result<Option<Vec<SadValue>>, CoreError> {
        // Only an event on the delegator's trunk can authorize a delegation: a superseding
        // rotation displaces the seals the events it supersedes carried.
        if !self.trunk_of(delegator).contains(said) {
            return Ok(None);
        }
        Ok(self
            .anchors
            .get(&(delegator.to_string(), sn, said.to_string()))
            .cloned())
    }

    /// The configuration traits of the delegator's key state as Affinidi's `Kever` holds it, which
    /// exists only once Affinidi has accepted the delegator's inception.
    fn delegator_traits(&self, delegator: &str) -> Result<Option<Vec<String>>, CoreError> {
        Ok(self
            .kevers
            .get(delegator)
            .map(|kever| kever.state().config.clone()))
    }
}

/// What the adapter knows about a delivered message: the body bytes of the key event it carries,
/// when Affinidi could read one.
type Ident = Option<Vec<u8>>;

impl Validator {
    fn holds(&self, ident: &Ident) -> bool {
        ident
            .as_ref()
            .is_some_and(|body| self.bodies.contains(body))
    }

    /// The bodies of the events on each prefix's trunk: from the last event its Kever holds, back
    /// through each accepted event's prior-event link to the inception.
    fn trunk(&self) -> HashSet<Vec<u8>> {
        let mut trunk = HashSet::new();
        for prefix in self.kevers.keys() {
            for said in self.trunk_of(prefix) {
                trunk.insert(self.events[&(prefix.clone(), said)].0.clone());
            }
        }
        trunk
    }

    /// The SAIDs of the events on one prefix's trunk, followed back through each accepted
    /// event's prior-event link from the last event its Kever holds. Empty for a prefix
    /// Affinidi holds no Kever for.
    fn trunk_of(&self, prefix: &str) -> HashSet<String> {
        let mut saids = HashSet::new();
        let mut at = self
            .kevers
            .get(prefix)
            .map(|kever| kever.state().last_event_digest.clone());
        // Each step moves to a distinct accepted event, so the walk ends within their number.
        for _ in 0..=self.events.len() {
            let Some(said) = at else { break };
            let Some((_, prior)) = self.events.get(&(prefix.to_string(), said.clone())) else {
                break;
            };
            saids.insert(said);
            at = prior.clone();
        }
        saids
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
                        "routing: the stream holds {} messages, not exactly one",
                        messages.len()
                    )),
                );
            }
            Err(e) => {
                return (
                    None,
                    Some(format!("routing: Affinidi cannot parse it: {e}")),
                );
            }
        };
        let ilk = match parsed.serder.ilk() {
            Ok(ilk) => ilk,
            Err(e) => {
                return (
                    None,
                    Some(format!("routing: Affinidi cannot read its ilk: {e}")),
                );
            }
        };
        if ilk == "rct" {
            return (
                None,
                Some(
                    "routing: Affinidi's validator has no processing for a receipt message; \
                     Kever counts only receipt couples attached to the event they receipt"
                        .into(),
                ),
            );
        }
        if !matches!(ilk.as_str(), "icp" | "dip" | "rot" | "ixn" | "drt") {
            return (None, Some(format!("routing: {ilk} is not a key event")));
        }
        // A body Affinidi already accepted is refused again by Kever (its sequence number is no
        // longer next), but it is the same event, and reads as seen by its body.
        let body = parsed.serder.raw().to_vec();
        let reason = self.validate(&ilk, &parsed).err().map(|e| e.to_string());
        (Some(body), reason)
    }

    /// Hand one key event to the Kever call its ilk needs, and record it if Affinidi accepts it.
    fn validate(&mut self, ilk: &str, msg: &ParsedMessage) -> Result<(), Refusal> {
        let serder = &msg.serder;
        let prefix = serder.prefix()?;
        let sn = serder.sn()?;
        let said = serder.said()?;
        let sigs = controller_sigs(msg);
        let couples = receipt_couples(msg);
        match ilk {
            "icp" | "dip" => {
                if self.kevers.contains_key(&prefix) {
                    return Err(routing(format!(
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
                let kever = self
                    .kevers
                    .get(&prefix)
                    .ok_or_else(|| routing(format!("no key state is held for {prefix}")))?;
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
            .and_then(SadValue::as_array)
            .cloned()
            .unwrap_or_default();
        let prior = serder
            .sad()
            .get("p")
            .and_then(SadValue::as_str)
            .map(str::to_string);
        self.events.insert(
            (prefix.clone(), said.clone()),
            (serder.raw().to_vec(), prior),
        );
        self.anchors.insert((prefix, sn, said), anchors);
        self.bodies.insert(serder.raw().to_vec());
        Ok(())
    }
}

/// Why an event was not accepted: Affinidi's verdict, or a refusal the adapter's routing made
/// without asking a Kever, which its reason marks so that a reader can tell the two apart.
enum Refusal {
    Affinidi(CoreError),
    Routing(String),
}

impl From<CoreError> for Refusal {
    fn from(e: CoreError) -> Self {
        Refusal::Affinidi(e)
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Affinidi(e) => write!(f, "{e}"),
            Refusal::Routing(why) => write!(f, "routing: {why}"),
        }
    }
}

fn routing(why: String) -> Refusal {
    Refusal::Routing(why)
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
fn verfers(sad: &SadValue) -> Result<Vec<Verfer>, CoreError> {
    let keys = sad
        .get("k")
        .and_then(SadValue::as_array)
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
fn proof(msg: &ParsedMessage) -> Result<DelegationProof, Refusal> {
    let (sn, said) = msg.seal_source_couples().first().ok_or_else(|| {
        routing(
            "the delegated event carries no seal source couple, and Affinidi's Kever needs one \
             to find its delegator's anchoring event"
                .into(),
        )
    })?;
    Ok(DelegationProof::from_seal_source_couple(sn, said)?)
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
    let trunk = validator.trunk();
    let dispositions: Vec<Value> = delivered
        .iter()
        .map(|(ident, initial, reason)| {
            let last = reading(&validator, ident);
            let on_trunk = ident.as_ref().is_some_and(|body| trunk.contains(body));
            let mut d = json!({"initial": initial, "final": last, "trunk": on_trunk});
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
