//! keri.process: deliver each message, in order, to a fresh host around devrandom's sans-IO KERI
//! core, and report what it holds.
//!
//! devrandom judges one event against a key state it is handed and stores nothing (keri-rs
//! lib.rs). Everything a validator needs between those judgments is the caller's, by the
//! library's own account, and this module is that caller: it routes each message to the KEL it
//! belongs to, holds events the library classifies as awaiting evidence and re-drives them,
//! looks up the delegator's anchoring event, rewinds on a superseding rotation, records a
//! duplicitous event, and attaches a witness's receipt to the event it receipts. hello declares
//! those as composed. The adapter decides no verdict: acceptance, the escrow classification, the
//! same-sequence-number judgment and every signature check are the library's (README.md,
//! "keri.process").

use std::collections::{BTreeMap, HashSet};

use cesr::core::indexer::IndexerBuilder;
use cesr::core::indexer::code::IndexedSigCode;
use cesr::core::primitives::{Number, Siger};
use cesr_stream::{CesrGroup, Groups, MessageFramer, ParseError, V1};
use keri::{
    AnchoredDelegation, DelegationContest, DelegationEvidence, Disposition, KeyState,
    KeyStateSnapshot, ReceiptError, ReceiptedEvent, ReceiptorEstablishment, Rejection,
    SameSnVerdict, Signed, TransferableEndorsement, Witnessing,
};
use keri_codec::{
    Deserialize, EventMessageError, JsonLimits, Message, MessageError, MessageLimits,
    ReceiptMessage,
};
use keri_events::{BasicPrefix, Identifier, KeriEvent, SigningThreshold, Toad};
use serde_json::{Value, json};

use crate::cesr::LIMITS;
use crate::protocol::OpError;

pub const E_QUIESCENCE: &str = "e.self.unknown.quiescence.f";

/// The JSON work bounds handed to devrandom's body deserializer, generous for any KERI event.
pub const JSON_LIMITS: JsonLimits = JsonLimits::new(65_536, 64);

/// Escrow passes after one delivery before the adapter stops and reports that it could not reach
/// quiescence. Every pass that changes anything moves at least one message to a later state, so a
/// request of n messages needs at most a few times n passes.
pub const MAX_PASSES: usize = 10_000;

fn limits() -> MessageLimits {
    MessageLimits::new(LIMITS, JSON_LIMITS)
}

pub fn ident(identifier: &Identifier<'_>) -> String {
    match identifier {
        Identifier::Basic(prefix) => prefix.to_qb64(),
        Identifier::SelfAddressing(said) => said.to_qb64(),
    }
}

/// One key event as delivered: the event devrandom parsed, the exact bytes it was parsed from
/// (what its signatures sign), its attached signatures, and an attached seal-source couple.
pub struct Event<'a> {
    pub event: KeriEvent<'a>,
    pub body: &'a [u8],
    pub sigs: Vec<Siger<'a>>,
    pub wigs: Vec<Siger<'a>>,
    /// The first `-G` seal-source couple, as (sequence number, SAID): where the delegator's
    /// anchoring event is, for a delegated event.
    pub seal: Option<(u128, String)>,
}

/// What one delivered stream turned out to be.
pub enum Item<'a> {
    Event(Box<Event<'a>>),
    Receipt(Box<ReceiptMessage<'a>>),
    /// Not a message this validator processes: unreadable to devrandom, more than one message,
    /// or a message that is not a key event or receipt. The reason is devrandom's.
    Refused(String),
}

/// Read one delivered stream. devrandom's own `Message::parse` decides, with one exception: its
/// message layer routes only `-A` and `-B` groups on a key event, so it refuses an event carrying
/// a seal-source couple (`-G`, how a delegated event names its delegator's anchor) or a
/// first-seen replay couple (`-E`). For exactly those two refusals the frame is read again with
/// devrandom's own framer, body deserializer and group parser (`reread`).
pub fn read(stream: &[u8]) -> Item<'_> {
    match Message::parse(stream, limits()) {
        Ok((_, rest)) if !rest.is_empty() => Item::Refused(format!(
            "the stream holds more than one message: {} bytes follow the first",
            rest.len()
        )),
        Ok((Message::Event(message), _)) => Item::Event(Box::new(Event {
            event: message.event().clone(),
            body: message.body(),
            sigs: message.sigs().to_vec(),
            wigs: message.wigs().to_vec(),
            seal: None,
        })),
        Ok((Message::Receipt(message), _)) => Item::Receipt(message),
        Ok(_) => Item::Refused("not a key event or receipt".to_string()),
        Err(MessageError::Event(EventMessageError::UnexpectedGroup {
            group: "SealSourceCouples" | "FirstSeenReplayCouples",
        })) => reread(stream).unwrap_or_else(Item::Refused),
        Err(error) => Item::Refused(format!("{error}")),
    }
}

fn number(raw: &[u8]) -> Option<u128> {
    if raw.len() > 16 {
        return None;
    }
    Some(raw.iter().fold(0u128, |acc, b| (acc << 8) | u128::from(*b)))
}

/// The second reading of a key event whose `-G` or `-E` group devrandom's message layer does not
/// route: devrandom's framer finds the frame, its strict body deserializer reads the event, and
/// its V1 group parser reads the attachments. `-A` and `-B` become the event's signatures as in
/// the message layer, the first `-G` couple names the delegator's anchoring event, and `-E` is
/// dropped, as a remote validator drops first-seen replay ordinals. Any other group is refused,
/// as the message layer refuses it.
fn reread(stream: &[u8]) -> Result<Item<'_>, String> {
    let span = MessageFramer::new(LIMITS)
        .advance(stream, true)
        .map_err(|e| format!("{e}"))?
        .ok_or("the stream ends inside its first message")?;
    if span.total_len != stream.len() {
        return Err(format!(
            "the stream holds more than one message: {} bytes follow the first",
            stream.len() - span.total_len
        ));
    }
    let body_len = span
        .body_len
        .ok_or("the stream is a bare attachment group")?;
    let (body, attachments) = stream.split_at(body_len);
    let event = KeriEvent::deserialize(body, JSON_LIMITS).map_err(|e| format!("{e}"))?;
    let mut parsed = Event {
        event,
        body,
        sigs: Vec::new(),
        wigs: Vec::new(),
        seal: None,
    };
    let route = |group: CesrGroup, parsed: &mut Event<'_>| -> Result<(), String> {
        let fail = |e: ParseError| format!("{e}");
        match group {
            CesrGroup::ControllerIdxSigs(g) => parsed.sigs.extend(g.into_vec().map_err(fail)?),
            CesrGroup::WitnessIdxSigs(g) => parsed.wigs.extend(g.into_vec().map_err(fail)?),
            CesrGroup::SealSourceCouples(g) => {
                for (sn, said) in g.into_vec().map_err(fail)? {
                    let sn =
                        number(sn.raw()).ok_or("a seal-source sequence number is too large")?;
                    parsed.seal.get_or_insert((sn, said.to_qb64()));
                }
            }
            CesrGroup::FirstSeenReplayCouples(g) => {
                g.into_vec().map_err(fail)?;
            }
            other => {
                let name = format!("{other:?}");
                return Err(format!(
                    "unexpected attachment group for a key event message: {}",
                    name.split(|c: char| !c.is_ascii_alphanumeric())
                        .next()
                        .unwrap_or("?")
                ));
            }
        }
        Ok(())
    };
    for group in Groups::<V1>::over(attachments) {
        match group.map_err(|e| format!("{e}"))? {
            CesrGroup::AttachmentGroup(frame) => {
                for inner in frame {
                    match inner.map_err(|e| format!("{e}"))? {
                        CesrGroup::AttachmentGroup(_) => {
                            return Err("a nested attachment frame".to_string());
                        }
                        inner => route(inner, &mut parsed)?,
                    }
                }
            }
            group => route(group, &mut parsed)?,
        }
    }
    Ok(Item::Event(Box::new(parsed)))
}

/// The host's reading of one event version (by SAID), and of one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Seen,
    Pending,
    Rejected,
    Duplicitous,
}

impl State {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Seen => "seen",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Duplicitous => "duplicitous",
        }
    }
}

/// What became of a receipt message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Receipted {
    /// Its event is not known yet; held, as keripy holds an unverified receipt.
    Held,
    /// Its signatures verified and were attached to the event with this SAID, which was then
    /// pending; the receipt's reading follows that event's.
    Attached(String),
    /// Every endorsement verified against the accepted event.
    Verified,
    Rejected(String),
}

/// An event version held by the host: the delivery whose body it uses and every signature
/// delivered for it so far, controller and witness.
struct Candidate<'e> {
    delivery: usize,
    sigs: Vec<Siger<'e>>,
    wigs: Vec<Siger<'e>>,
    seal: Option<(u128, String)>,
}

fn merge<'e>(into: &mut Vec<Siger<'e>>, from: &[Siger<'e>]) {
    for sig in from {
        if !into.iter().any(|s| s.to_qb64() == sig.to_qb64()) {
            into.push(sig.clone());
        }
    }
}

/// An event version put to devrandom's fold: the event, the bytes it was parsed from, every
/// signature held for it, and the seal-source couple it arrived with. The `Signed` the fold takes
/// is built from it at each judgment, so that it shares the lifetime of the key state it is
/// judged against.
struct Proposal<'p> {
    event: &'p KeriEvent<'p>,
    body: &'p [u8],
    sigs: &'p [Siger<'p>],
    wigs: &'p [Siger<'p>],
    seal: Option<&'p (u128, String)>,
}

impl Proposal<'_> {
    /// The event and its bytes are asserted to belong together because devrandom's own parser
    /// produced the event from exactly those bytes (`read`).
    fn signed<'x>(&'x self) -> Signed<'x> {
        Signed::from_host_asserted_parts(
            self.event,
            self.body,
            self.sigs.to_vec(),
            self.wigs.to_vec(),
        )
    }
}

/// One identifier's KEL: the trunk, each entry the key state after an event and the delivery it
/// came from.
struct Kel {
    trunk: Vec<(KeyStateSnapshot, usize)>,
}

impl Kel {
    fn head(&self) -> &KeyStateSnapshot {
        &self.trunk[self.trunk.len() - 1].0
    }
}

enum Outcome {
    Accepted(KeyStateSnapshot),
    Superseded(usize, KeyStateSnapshot),
    Held(String),
    Refused(String),
    Duplicitous(String),
}

fn classify(rejection: &Rejection) -> Outcome {
    let reason = format!("{rejection:?}");
    match rejection.disposition() {
        Disposition::Awaiting(kind) => Outcome::Held(format!("{reason} [awaiting {kind:?}]")),
        Disposition::Terminal | Disposition::Contested => Outcome::Refused(reason),
    }
}

fn accepted(result: Result<KeyState<'_>, Rejection>) -> Outcome {
    match result {
        Ok(state) => Outcome::Accepted(KeyStateSnapshot::from(&state)),
        Err(rejection) => classify(&rejection),
    }
}

pub struct Host<'e> {
    items: &'e [Item<'e>],
    kels: BTreeMap<String, Kel>,
    /// Every event version the host has an opinion on, by SAID.
    states: BTreeMap<String, (State, String)>,
    candidates: BTreeMap<String, Candidate<'e>>,
    /// Seen events no longer on the trunk because a superseding rotation displaced them.
    displaced: HashSet<String>,
    /// Every seen event, by SAID: the key state after it and its delivery.
    seen: BTreeMap<String, (KeyStateSnapshot, usize)>,
    receipts: BTreeMap<usize, Receipted>,
}

impl<'e> Host<'e> {
    pub fn new(items: &'e [Item<'e>]) -> Self {
        Self {
            items,
            kels: BTreeMap::new(),
            states: BTreeMap::new(),
            candidates: BTreeMap::new(),
            displaced: HashSet::new(),
            seen: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    fn event(&self, delivery: usize) -> &'e Event<'e> {
        match &self.items[delivery] {
            Item::Event(event) => event,
            _ => unreachable!("only key event deliveries become candidates"),
        }
    }

    fn state(&self, said: &str) -> Option<State> {
        self.states.get(said).map(|(state, _)| *state)
    }

    /// Deliver message `index`, then drive the host to quiescence.
    pub fn deliver(&mut self, index: usize) -> Result<(), OpError> {
        match &self.items[index] {
            Item::Event(event) => {
                let said = event.event.said().to_qb64();
                match self.state(&said) {
                    Some(State::Seen | State::Duplicitous) => {}
                    Some(State::Pending) => {
                        let candidate = self.candidates.get_mut(&said).expect("pending held");
                        merge(&mut candidate.sigs, &event.sigs);
                        merge(&mut candidate.wigs, &event.wigs);
                        candidate.delivery = index;
                        if event.seal.is_some() {
                            candidate.seal.clone_from(&event.seal);
                        }
                        self.drive(&said);
                    }
                    Some(State::Rejected) | None => {
                        self.candidates.insert(
                            said.clone(),
                            Candidate {
                                delivery: index,
                                sigs: event.sigs.clone(),
                                wigs: event.wigs.clone(),
                                seal: event.seal.clone(),
                            },
                        );
                        self.drive(&said);
                    }
                }
            }
            Item::Receipt(_) => {
                let outcome = self.receipt(index);
                self.receipts.insert(index, outcome);
            }
            Item::Refused(reason) => {
                eprintln!("message {index} not processed: {reason}");
            }
        }
        self.quiesce()
    }

    /// Re-drive every held event and receipt until a pass changes nothing.
    fn quiesce(&mut self) -> Result<(), OpError> {
        for _ in 0..MAX_PASSES {
            let before = (self.states.clone(), self.receipts.clone());
            let pending: Vec<String> = self
                .states
                .iter()
                .filter(|(_, (state, _))| *state == State::Pending)
                .map(|(said, _)| said.clone())
                .collect();
            for said in pending {
                self.drive(&said);
            }
            let held: Vec<usize> = self
                .receipts
                .iter()
                .filter(|(_, r)| matches!(r, Receipted::Held | Receipted::Attached(_)))
                .map(|(index, _)| *index)
                .collect();
            for index in held {
                if self.receipts[&index] == Receipted::Held {
                    let outcome = self.receipt(index);
                    self.receipts.insert(index, outcome);
                }
            }
            if before == (self.states.clone(), self.receipts.clone()) {
                return Ok(());
            }
        }
        Err(OpError::Harness(format!(
            "{E_QUIESCENCE}: Re-driving held events still changed the host's state after \
             {MAX_PASSES} passes, so the readings would depend on when the adapter stopped."
        )))
    }

    /// Judge the held event version `said` once, and record the outcome.
    fn drive(&mut self, said: &str) {
        let candidate = &self.candidates[said];
        let delivery = candidate.delivery;
        let event = self.event(delivery);
        let proposal = Proposal {
            event: &event.event,
            body: event.body,
            sigs: &candidate.sigs,
            wigs: &candidate.wigs,
            seal: candidate.seal.as_ref(),
        };
        let prefix = ident(event.event.prefix());
        let outcome = match self.kels.get(&prefix) {
            None => self.genesis(&proposal),
            Some(kel) if event.event.sn().value() <= kel.head().view().sn().value() => {
                self.contest(kel, &proposal)
            }
            Some(kel) => self.advance(kel.head(), &proposal),
        };
        let state = match outcome {
            Outcome::Accepted(snapshot) => {
                self.seen
                    .insert(said.to_string(), (snapshot.clone(), delivery));
                self.kels
                    .entry(prefix)
                    .or_insert_with(|| Kel { trunk: Vec::new() })
                    .trunk
                    .push((snapshot, delivery));
                (State::Seen, String::new())
            }
            Outcome::Superseded(sn, snapshot) => {
                let kel = self.kels.get_mut(&prefix).expect("a contested KEL exists");
                for (_, displaced) in kel.trunk.drain(sn..) {
                    let displaced = match &self.items[displaced] {
                        Item::Event(e) => e.event.said().to_qb64(),
                        _ => unreachable!("the trunk holds key events"),
                    };
                    self.displaced.insert(displaced);
                }
                kel.trunk.push((snapshot.clone(), delivery));
                self.seen.insert(said.to_string(), (snapshot, delivery));
                (State::Seen, "superseding rotation".to_string())
            }
            Outcome::Held(reason) => (State::Pending, reason),
            Outcome::Refused(reason) => (State::Rejected, reason),
            Outcome::Duplicitous(reason) => (State::Duplicitous, reason),
        };
        if state.0 != State::Pending {
            self.candidates.remove(said);
        }
        self.states.insert(said.to_string(), state);
    }

    /// The first event of an identifier the host holds no KEL for.
    fn genesis(&self, proposal: &Proposal<'_>) -> Outcome {
        let event = proposal.event;
        match event {
            KeriEvent::Inception(_) => accepted(KeyState::incept(&proposal.signed())),
            KeriEvent::DelegatedInception(dip) => match self.evidence(dip.delegator(), proposal) {
                Ok((delegator, delegating_event)) => {
                    let state = delegator.view();
                    let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
                        delegator: &state,
                        delegating_event,
                    });
                    accepted(KeyState::incept_delegated(&proposal.signed(), &evidence))
                }
                Err(reason) => Outcome::Held(reason),
            },
            _ => Outcome::Held(format!(
                "no KEL is held for {} yet, so its event at sn {} cannot be judged [awaiting \
                 prior events]",
                ident(event.prefix()),
                event.sn().value()
            )),
        }
    }

    /// An event above the head of its KEL.
    fn advance(&self, head: &KeyStateSnapshot, proposal: &Proposal<'_>) -> Outcome {
        let state = head.view();
        match (proposal.event, state.delegator()) {
            (KeriEvent::DelegatedRotation(_), Some(delegator)) => {
                match self.evidence(delegator, proposal) {
                    Ok((delegator, delegating_event)) => {
                        let delegator = delegator.view();
                        let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
                            delegator: &delegator,
                            delegating_event,
                        });
                        accepted(state.ingest_delegated(&proposal.signed(), &evidence))
                    }
                    Err(reason) => Outcome::Held(reason),
                }
            }
            _ => accepted(state.ingest(&proposal.signed())),
        }
    }

    /// The delegator's head and the anchoring event that evidences `event`, or the held outcome
    /// if the host does not hold them yet. The anchoring event is the one a `-G` couple names, or
    /// else the first trunk event of the delegator's KEL whose seals anchor `event`.
    fn evidence(
        &self,
        delegator: &Identifier<'_>,
        proposal: &Proposal<'_>,
    ) -> Result<(&KeyStateSnapshot, &'e KeriEvent<'e>), String> {
        let event = proposal.event;
        let held = || {
            format!(
                "the delegator {}'s anchoring event is not held yet [awaiting DelegationEvidence]",
                ident(delegator)
            )
        };
        let kel = self.kels.get(&ident(delegator)).ok_or_else(held)?;
        let delegating = match proposal.seal {
            Some((sn, said)) => usize::try_from(*sn)
                .ok()
                .and_then(|sn| kel.trunk.get(sn))
                .map(|(_, delivery)| &self.event(*delivery).event)
                .filter(|e| e.said().to_qb64() == *said),
            None => kel
                .trunk
                .iter()
                .map(|(_, delivery)| &self.event(*delivery).event)
                .find(|e| e.anchor_position(event).is_some()),
        };
        Ok((kel.head(), delegating.ok_or_else(held)?))
    }

    /// The first trunk event of `delegator`'s KEL whose seals anchor `delegated`, if the host
    /// holds one.
    fn anchor_in(&self, delegator: &str, delegated: &KeriEvent<'_>) -> Option<&'e KeriEvent<'e>> {
        self.kels.get(delegator)?.trunk.iter().find_map(|(_, d)| {
            let e = &self.event(*d).event;
            e.anchor_position(delegated).is_some().then_some(e)
        })
    }

    /// The delegating events behind two delegated rotations contesting one sequence number,
    /// level by level up the delegation chain, for `judge_same_sn`: at each level, the events in
    /// the delegator's KEL that anchor the recorded side and the incoming side. The chain is
    /// complete when it reaches a delegator that is not itself delegated, the root of every
    /// delegation; it stops short, and is reported incomplete, where the host does not hold a
    /// delegating event yet.
    fn contests(
        &self,
        recorded: &KeriEvent<'_>,
        incoming: &KeriEvent<'_>,
        delegator: &Identifier<'_>,
    ) -> (Vec<DelegationContest<'e>>, bool) {
        let mut chain = Vec::new();
        let (mut old, mut new): (&KeriEvent<'_>, &KeriEvent<'_>) = (recorded, incoming);
        let mut delegator = ident(delegator);
        loop {
            let (Some(incumbent), Some(challenger)) = (
                self.anchor_in(&delegator, old),
                self.anchor_in(&delegator, new),
            ) else {
                return (chain, false);
            };
            chain.push(DelegationContest {
                incumbent,
                challenger,
            });
            match self.kels[&delegator].head().view().delegator() {
                Some(next) => {
                    (old, new, delegator) = (incumbent, challenger, ident(next));
                }
                None => return (chain, true),
            }
        }
    }

    /// An event at a sequence number its KEL already holds: devrandom's same-sn judgment decides,
    /// and on a superseding rotation the host rewinds to the state before that sn and re-drives
    /// the library's validating fold there.
    fn contest(&self, kel: &Kel, proposal: &Proposal<'_>) -> Outcome {
        let incoming = proposal.event;
        let Ok(sn) = usize::try_from(incoming.sn().value()) else {
            return Outcome::Refused("sequence number out of range".to_string());
        };
        let recorded_delivery = kel.trunk[sn].1;
        let recorded = &self.event(recorded_delivery).event;
        let head = kel.head().view();
        let (chain, complete) = match (incoming, recorded, head.delegator()) {
            (KeriEvent::DelegatedRotation(_), KeriEvent::DelegatedRotation(_), Some(d)) => {
                self.contests(recorded, incoming, d)
            }
            _ => (Vec::new(), true),
        };
        match head.judge_same_sn(incoming, recorded, &chain) {
            Ok(SameSnVerdict::Duplicitous { recorded }) => Outcome::Duplicitous(format!(
                "conflicts with the seen event {} at sn {sn}",
                recorded.to_qb64()
            )),
            Ok(SameSnVerdict::Supersedes) if sn > 0 => {
                match self.advance(&kel.trunk[sn - 1].0, proposal) {
                    Outcome::Accepted(snapshot) => Outcome::Superseded(sn, snapshot),
                    other => other,
                }
            }
            Ok(SameSnVerdict::Undecided) if !complete => Outcome::Held(
                "the same-sn judgment needs delegating events the host does not hold yet \
                 [awaiting DelegationEvidence]"
                    .to_string(),
            ),
            Ok(verdict) => Outcome::Refused(format!("same-sn verdict {verdict:?}")),
            Err(error) => Outcome::Refused(format!("same-sn judgment refused: {error:?}")),
        }
    }

    /// The witness set and threshold that govern a held event: an inception's own, else the
    /// head's set updated by a rotation's cuts and then its additions in order, as a rotation
    /// defines them, with the rotation's own threshold. A wrong position here could only make a
    /// valid receipt fail, never a forged one pass: devrandom's fold verifies every witness
    /// signature against the witness its index selects.
    fn governing(&self, event: &KeriEvent<'e>) -> Option<(Vec<BasicPrefix<'static>>, Toad)> {
        let owned = |set: &[BasicPrefix<'_>]| -> Vec<BasicPrefix<'static>> {
            set.iter().map(|w| w.clone().into_static()).collect()
        };
        let head = || {
            let state = self.kels.get(&ident(event.prefix()))?.head().view();
            Some((owned(state.witnesses()), state.witness_threshold()))
        };
        let rotation = |cuts: &[BasicPrefix<'_>], adds: &[BasicPrefix<'_>], toad: Toad| {
            let cuts = owned(cuts);
            let mut set: Vec<BasicPrefix<'static>> = head()?
                .0
                .into_iter()
                .filter(|w| !cuts.contains(w))
                .collect();
            for add in owned(adds) {
                if !set.contains(&add) {
                    set.push(add);
                }
            }
            Some((set, toad))
        };
        match event {
            KeriEvent::Inception(icp) => Some((owned(icp.witnesses()), icp.witness_threshold())),
            KeriEvent::DelegatedInception(dip) => {
                let icp = dip.inception();
                Some((owned(icp.witnesses()), icp.witness_threshold()))
            }
            KeriEvent::Interaction(_) => head(),
            KeriEvent::Rotation(rot) => rotation(
                rot.witness_removals(),
                rot.witness_additions(),
                rot.witness_threshold(),
            ),
            KeriEvent::DelegatedRotation(drt) => {
                let rot = drt.rotation();
                rotation(
                    rot.witness_removals(),
                    rot.witness_additions(),
                    rot.witness_threshold(),
                )
            }
        }
    }

    /// Judge receipt message `index` against what the host holds now.
    fn receipt(&mut self, index: usize) -> Receipted {
        let items = self.items;
        let Item::Receipt(message) = &items[index] else {
            unreachable!("only receipt deliveries are judged as receipts");
        };
        let receipt = message.receipt();
        let said = receipt.said().to_qb64();
        match self.state(&said) {
            Some(State::Seen) => self.late(message, &said),
            Some(State::Pending) => self.attach(message, &said),
            _ => Receipted::Held,
        }
    }

    /// A receipt of a seen event: devrandom judges each endorsement on its own, the wig against
    /// the governing witness set, the couple by plain signature verification, the transferable
    /// endorsement against the receiptor's establishment event.
    fn late(&self, message: &ReceiptMessage<'_>, said: &str) -> Receipted {
        let (snapshot, delivery) = &self.seen[said];
        let event = self.event(*delivery);
        let receipted = ReceiptedEvent {
            prefix: event.event.prefix(),
            sn: event.event.sn(),
            said: event.event.said(),
            signed_bytes: event.body,
        };
        if let Err(error) = receipted.named_by(message.receipt()) {
            return Receipted::Rejected(format!("{error:?}"));
        }
        let state = snapshot.view();
        let witnessing = Witnessing::new(state.witnesses(), state.witness_threshold());
        for wig in message.wigs() {
            if let Err(error) = witnessing.receipt(event.body, wig) {
                return Receipted::Rejected(format!("{error:?}"));
            }
        }
        for couple in message.couples() {
            if let Err(error) = cesr::crypto::verify(
                couple.receiptor().as_matter(),
                event.body,
                couple.signature(),
            ) {
                return Receipted::Rejected(format!("{error:?}"));
            }
        }
        for endorsement in message.trans_receipts() {
            let receiptor = self.establishment(
                &ident(endorsement.receiptor()),
                endorsement.sn(),
                endorsement.said().to_qb64(),
            );
            let evidence = receiptor
                .as_ref()
                .map(|(said, view)| ReceiptorEstablishment {
                    said,
                    keys: view.view().keys(),
                });
            match receipted.endorsed_by(
                &TransferableEndorsement::from(endorsement),
                evidence.as_ref(),
            ) {
                Ok(()) => {}
                Err(ReceiptError::EvidenceRequired) => return Receipted::Held,
                Err(error) => return Receipted::Rejected(format!("{error:?}")),
            }
        }
        Receipted::Verified
    }

    /// The receiptor's seen establishment event at `sn`: its SAID and the key state after it.
    fn establishment(
        &self,
        receiptor: &str,
        sn: Number,
        said: String,
    ) -> Option<(keri_events::Said<'static>, KeyStateSnapshot)> {
        let kel = self.kels.get(receiptor)?;
        let (snapshot, delivery) = kel.trunk.get(usize::try_from(sn.value()).ok()?)?;
        let event = &self.event(*delivery).event;
        if event.said().to_qb64() != said || matches!(event, KeriEvent::Interaction(_)) {
            return None;
        }
        Some((event.said().clone().into_static(), snapshot.clone()))
    }

    /// A receipt of a held event: each witness signature and each couple is verified by
    /// devrandom against the governing witness set, and attached to the held event as an indexed
    /// witness signature, a couple at its signer's witness position; the event is then
    /// re-driven. This is keripy's promotion of a witness's couple, which devrandom's receipt
    /// module documents as the host's two-call recipe.
    fn attach(&mut self, message: &'e ReceiptMessage<'e>, said: &str) -> Receipted {
        let candidate = &self.candidates[said];
        let event = self.event(candidate.delivery);
        let receipted = ReceiptedEvent {
            prefix: event.event.prefix(),
            sn: event.event.sn(),
            said: event.event.said(),
            signed_bytes: event.body,
        };
        if let Err(error) = receipted.named_by(message.receipt()) {
            return Receipted::Rejected(format!("{error:?}"));
        }
        let Some((governing, toad)) = self.governing(&event.event) else {
            return Receipted::Held;
        };
        let witnessing = Witnessing::new(&governing, toad);
        let mut wigs = Vec::new();
        for wig in message.wigs() {
            if let Err(error) = witnessing.receipt(event.body, wig) {
                return Receipted::Rejected(format!("{error:?}"));
            }
            wigs.push(wig.clone());
        }
        for couple in message.couples() {
            if let Err(error) = cesr::crypto::verify(
                couple.receiptor().as_matter(),
                event.body,
                couple.signature(),
            ) {
                return Receipted::Rejected(format!("{error:?}"));
            }
            let Some(position) = witnessing.witness_index(couple.receiptor()) else {
                // A verified couple from a non-witness binds to no position; it is kept with
                // the event, as keripy keeps a non-witness receipt.
                continue;
            };
            let promoted = IndexerBuilder::new()
                .with_code(IndexedSigCode::Ed25519)
                .with_index(position.value())
                .and_then(|b| b.with_raw(couple.signature().raw().to_vec()));
            match promoted {
                Ok(indexer) => wigs.push(Siger::new(indexer)),
                Err(error) => return Receipted::Rejected(format!("{error:?}")),
            }
        }
        let candidate = self.candidates.get_mut(said).expect("pending held");
        merge(&mut candidate.wigs, &wigs);
        self.drive(said);
        // A transferable endorsement is judged only against a seen event, so a receipt carrying
        // one stays held, with its witness signatures already attached.
        if message.trans_receipts().is_empty() {
            Receipted::Attached(said.to_string())
        } else {
            Receipted::Held
        }
    }

    /// The reading of message `index` now.
    pub fn reading(&self, index: usize) -> State {
        match &self.items[index] {
            Item::Event(event) => self
                .state(&event.event.said().to_qb64())
                .unwrap_or(State::Rejected),
            Item::Receipt(_) => match &self.receipts[&index] {
                Receipted::Held => State::Pending,
                Receipted::Verified => State::Seen,
                Receipted::Rejected(_) => State::Rejected,
                Receipted::Attached(said) => match self.state(said) {
                    Some(State::Seen) => State::Seen,
                    Some(State::Pending) => State::Pending,
                    _ => State::Rejected,
                },
            },
            Item::Refused(_) => State::Rejected,
        }
    }

    fn reason(&self, index: usize) -> Option<String> {
        let reason = match &self.items[index] {
            Item::Event(event) => self.states.get(&event.event.said().to_qb64())?.1.clone(),
            Item::Receipt(_) => match &self.receipts[&index] {
                Receipted::Rejected(reason) => reason.clone(),
                _ => String::new(),
            },
            Item::Refused(reason) => reason.clone(),
        };
        (!reason.is_empty()).then_some(reason)
    }

    /// Whether message `index` is a key event on its KEL's trunk now.
    pub fn trunk(&self, index: usize) -> bool {
        let Item::Event(event) = &self.items[index] else {
            return false;
        };
        let said = event.event.said().to_qb64();
        self.state(&said) == Some(State::Seen)
            && !self.displaced.contains(&said)
            && self
                .kels
                .get(&ident(event.event.prefix()))
                .is_some_and(|kel| {
                    kel.trunk
                        .iter()
                        .any(|(_, d)| self.event(*d).event.said().to_qb64() == said)
                })
    }

    pub fn key_states(&self) -> Value {
        let mut states = serde_json::Map::new();
        for (prefix, kel) in &self.kels {
            let state = kel.head().view();
            states.insert(
                prefix.clone(),
                json!({
                    "sn": u64::try_from(state.sn().value()).unwrap_or(u64::MAX),
                    "said": state.latest_said().to_qb64(),
                    "keys": state.keys().iter().map(|k| k.to_qb64()).collect::<Vec<_>>(),
                    "kt": threshold(state.threshold()),
                    "ndigs": state.next_keys().iter().map(|d| d.to_qb64()).collect::<Vec<_>>(),
                    "nt": threshold(state.next_threshold()),
                    "wits": state.witnesses().iter().map(|w| w.to_qb64()).collect::<Vec<_>>(),
                    "bt": format!("{:x}", state.witness_threshold().value()),
                    "delegator": state.delegator().map(ident),
                }),
            );
        }
        Value::Object(states)
    }
}

/// A threshold as devrandom holds it: a hex number, or clauses of fractions, one list per clause
/// (a single clause as a flat list).
pub fn threshold(threshold: &SigningThreshold) -> Value {
    match threshold {
        SigningThreshold::Simple(n) => json!(format!("{n:x}")),
        SigningThreshold::Weighted(weighted) => {
            let clauses: Vec<Vec<String>> = weighted
                .clauses()
                .map(|clause| {
                    clause
                        .iter()
                        .map(|(n, d)| {
                            if *d == 1 {
                                format!("{n}")
                            } else {
                                format!("{n}/{d}")
                            }
                        })
                        .collect()
                })
                .collect();
            if clauses.len() == 1 {
                json!(clauses[0])
            } else {
                json!(clauses)
            }
        }
    }
}

pub fn process(messages: &[Vec<u8>]) -> Result<Value, OpError> {
    let items: Vec<Item<'_>> = messages.iter().map(|m| read(m)).collect();
    let mut host = Host::new(&items);
    let mut initial = Vec::with_capacity(items.len());
    for index in 0..items.len() {
        host.deliver(index)?;
        initial.push(host.reading(index));
    }
    let dispositions: Vec<Value> = initial
        .iter()
        .enumerate()
        .map(|(index, first)| {
            let mut entry = json!({
                "initial": first.name(),
                "final": host.reading(index).name(),
                "trunk": host.trunk(index),
            });
            if let Some(reason) = host.reason(index) {
                entry["reason"] = json!(reason);
            }
            entry
        })
        .collect();
    Ok(json!({"dispositions": dispositions, "key_states": host.key_states()}))
}
