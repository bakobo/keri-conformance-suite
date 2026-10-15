//! keri.process on keri-core 0.17.13: deliver each message, in order, to one fresh keriox
//! processor and report keriox's own state after each delivery.
//!
//! Nothing here decides whether an event is acceptable. keri-core's `parse_event_stream` reads
//! each stream, and its `BasicProcessor`, with the escrows `default_escrow_bus` registers,
//! validates, escrows, files as duplicitous or refuses each message. That bus re-drives the
//! escrows synchronously whenever an event is added, so when `process` returns keriox has done
//! everything it will do: there is no timer to trigger. The adapter then reads keri-core's own
//! KEL, escrow and receipt tables. README.md, "keri.process", says which table backs each
//! reported value.

use std::collections::BTreeSet;
use std::sync::Arc;

use keri_core::actor::parse_event_stream;
use keri_core::database::redb::RedbDatabase;
use keri_core::database::{EscrowCreator, EscrowDatabase, EventDatabase, LogDatabase};
use keri_core::event::event_data::EventData;
use keri_core::event_message::signature::{Nontransferable, Transferable};
use keri_core::event_message::signed_event_message::{Message, Notice, SignedEventMessage};
use keri_core::prefix::IdentifierPrefix;
use keri_core::processor::basic_processor::BasicProcessor;
use keri_core::processor::escrow::delegation_escrow::DelegationEscrow;
use keri_core::processor::escrow::duplicitous_events::DuplicitousEvents;
use keri_core::processor::escrow::partially_signed_escrow::PartiallySignedEscrow;
use keri_core::processor::escrow::partially_witnessed_escrow::PartiallyWitnessedEscrow;
use keri_core::processor::escrow::{default_escrow_bus, EscrowConfig};
use keri_core::processor::event_storage::EventStorage;
use keri_core::processor::Processor;
use keri_core::state::IdentifierState;
use said::SelfAddressingIdentifier;
use serde::Serialize;
use serde_json::{json, Value};

use crate::cesr::OpError;

/// keri-core's database lives in a temporary file; creating or reading it failed. A full or
/// unwritable temporary directory causes this, so a retry may succeed.
pub const E_STORAGE: &str = "e.env.io.storage.r";

/// The name keri-core 0.17.13's `MaybeOutOfOrderEscrow::new` gives its escrow table. That escrow
/// keeps its table handle private, so the adapter opens the same table by name to read it.
const OUT_OF_ORDER_TABLE: &str = "out_of_order_escrow";

fn storage_error(what: impl std::fmt::Debug) -> OpError {
    OpError::Harness(format!(
        "{E_STORAGE}: keri-core's database could not be created or read ({what:?}), so the \
         readings cannot be taken. Check that the temporary directory is writable and not full."
    ))
}

/// What keri-core's parser says one delivered stream is: the first message it holds.
enum Ident {
    Event(Box<SignedEventMessage>, SelfAddressingIdentifier),
    Receipt {
        id: IdentifierPrefix,
        sn: u64,
        said: SelfAddressingIdentifier,
        /// Each signature the receipt carries, as keri-core serializes it.
        sigs: Vec<Value>,
        transferable: bool,
    },
}

/// Each element of a list of keri-core values, as keri-core serializes it, so that signatures
/// are compared without the adapter reading their encoding.
fn each<T: Serialize>(values: &[T]) -> Vec<Value> {
    values
        .iter()
        .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
        .collect()
}

/// Each signature of a transferable receipt together with the validator seal it was made under,
/// so that a signature held under one seal does not vouch for a receipt naming another.
fn sealed<S: Serialize, T: Serialize>(seal: &S, sigs: &[T]) -> Vec<Value> {
    sigs.iter()
        .map(|sig| serde_json::to_value((seal, sig)).unwrap_or(Value::Null))
        .collect()
}

fn nontransferable_sigs(sigs: impl IntoIterator<Item = Nontransferable>) -> Vec<Value> {
    sigs.into_iter()
        .flat_map(|n| match n {
            Nontransferable::Indexed(sigs) => each(&sigs),
            Nontransferable::Couplet(couples) => each(&couples),
        })
        .collect()
}

fn identify(stream: &[u8]) -> Option<Ident> {
    let message = parse_event_stream(stream).ok()?.into_iter().next()?;
    let Message::Notice(notice) = message;
    match notice {
        Notice::Event(event) => {
            let said = event.event_message.digest().ok()?;
            Some(Ident::Event(Box::new(event), said))
        }
        Notice::NontransferableRct(rct) => Some(Ident::Receipt {
            id: rct.body.prefix.clone(),
            sn: rct.body.sn,
            said: rct.body.receipted_event_digest.clone(),
            sigs: nontransferable_sigs(rct.signatures),
            transferable: false,
        }),
        Notice::TransferableRct(vrc) => Some(Ident::Receipt {
            id: vrc.body.prefix.clone(),
            sn: vrc.body.sn,
            said: vrc.body.receipted_event_digest.clone(),
            sigs: sealed(&vrc.validator_seal, &vrc.signatures),
            transferable: true,
        }),
    }
}

/// A reading, and the escrow keri-core holds the message in when it is pending.
type Reading = (&'static str, Option<&'static str>);

/// One fresh keriox validator: a redb database in a temporary directory, a `BasicProcessor`, and
/// the escrows keri-core's `default_escrow_bus` registers on it.
struct Validator {
    db: Arc<RedbDatabase>,
    processor: BasicProcessor<RedbDatabase>,
    partially_signed: Arc<PartiallySignedEscrow<RedbDatabase>>,
    partially_witnessed: Arc<PartiallyWitnessedEscrow<RedbDatabase>>,
    delegation: Arc<DelegationEscrow<RedbDatabase>>,
    duplicitous: Arc<DuplicitousEvents<RedbDatabase>>,
    out_of_order: <RedbDatabase as EscrowCreator>::EscrowDatabaseType,
    storage: EventStorage<RedbDatabase>,
    // Declared last, so dropped last: the database file lives in it.
    _dir: tempfile::TempDir,
}

impl Validator {
    fn new() -> Result<Self, OpError> {
        let dir = tempfile::tempdir().map_err(storage_error)?;
        let db = Arc::new(RedbDatabase::new(&dir.path().join("kel.redb")).map_err(storage_error)?);
        let (bus, (_, partially_signed, partially_witnessed, delegation, duplicitous)) =
            default_escrow_bus(db.clone(), EscrowConfig::default());
        Ok(Validator {
            processor: BasicProcessor::new(db.clone(), Some(bus)),
            out_of_order: db.create_escrow_db(OUT_OF_ORDER_TABLE),
            storage: EventStorage::new(db.clone()),
            partially_signed,
            partially_witnessed,
            delegation,
            duplicitous,
            db,
            _dir: dir,
        })
    }

    /// Hand one stream to keri-core unchanged. keri-core refusing it drops it; the first reason
    /// is returned for the disposition's informative `reason`.
    fn deliver(&self, stream: &[u8]) -> Option<String> {
        let messages = match parse_event_stream(stream) {
            Ok(messages) if !messages.is_empty() => messages,
            Ok(_) => return Some("keri-core found no message in the stream".into()),
            Err(e) => return Some(format!("keri-core cannot parse the stream: {e}")),
        };
        let mut refusal = None;
        for message in &messages {
            if let Err(e) = self.processor.process(message) {
                eprintln!("keri-core refused a message: {e}");
                refusal.get_or_insert_with(|| format!("keri-core refused it: {e}"));
            }
        }
        refusal
    }

    fn in_kel(&self, id: &IdentifierPrefix, sn: u64, said: &SelfAddressingIdentifier) -> bool {
        self.storage
            .get_event_at_sn(id, sn)
            .and_then(|e| e.signed_event_message.event_message.digest().ok())
            .as_ref()
            == Some(said)
    }

    /// keri-core's reading of one key event.
    fn event_reading(
        &self,
        event: &SignedEventMessage,
        said: &SelfAddressingIdentifier,
    ) -> Result<Reading, OpError> {
        let id = event.event_message.data.get_prefix();
        let sn = event.event_message.data.get_sn();
        if self.in_kel(&id, sn, said) {
            return Ok(("seen", None));
        }
        let is_it = |e: &SignedEventMessage| e.event_message.digest().ok().as_ref() == Some(said);
        let duplicitous = self.duplicitous.get(&id).map_err(storage_error)?;
        if duplicitous.iter().any(is_it) {
            return Ok(("duplicitous", None));
        }
        let partially_signed = &self.partially_signed.escrowed_partially_signed;
        if self
            .out_of_order
            .contains(&id, sn, said)
            .map_err(storage_error)?
        {
            return Ok(("pending", Some("out of order")));
        }
        if partially_signed
            .contains(&id, sn, said)
            .map_err(storage_error)?
        {
            return Ok(("pending", Some("partially signed")));
        }
        let partially_witnessed = &self.partially_witnessed;
        if partially_witnessed
            .get_event_by_sn_and_digest(sn, &id, said)
            .map_err(storage_error)?
            .is_some()
        {
            return Ok(("pending", Some("partially witnessed")));
        }
        // keri-core keys its delegation escrow by the delegator, which it reads from a dip's own
        // body (DelegationEscrow::notify). Only a dip reaches that escrow: keri-core 0.17.13
        // deserializes every drt body as a plain rotation, because EventData is an untagged enum
        // in which Rot precedes Drt, so it never checks a drt's delegating seal.
        if let EventData::Dip(dip) = &event.event_message.data.event_data {
            let delegator = &dip.delegator;
            let mut held = (self.delegation.delegation_escrow)
                .get_from_sn(delegator, 0)
                .map_err(storage_error)?;
            if held.any(|e| is_it(&e)) {
                return Ok(("pending", Some("awaiting delegation")));
            }
        }
        Ok(("rejected", None))
    }

    /// A receipt is seen when keri-core holds all its signatures for an event in its KEL, and
    /// pending when keri-core holds them for an event it has not accepted.
    fn receipt_reading(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        said: &SelfAddressingIdentifier,
        sigs: &[Value],
        transferable: bool,
    ) -> Result<Reading, OpError> {
        let log = self.db.get_log_db();
        let held: Vec<Value> = if transferable {
            log.get_trans_receipts(said)
                .map_err(storage_error)?
                .flat_map(|Transferable::Seal(seal, sigs)| sealed(&seal, &sigs))
                .collect()
        } else {
            log.get_nontrans_couplets(said)
                .map_err(storage_error)?
                .map(nontransferable_sigs)
                .unwrap_or_default()
        };
        if sigs.is_empty() || !sigs.iter().all(|s| held.contains(s)) {
            return Ok(("rejected", None));
        }
        Ok(if self.in_kel(id, sn, said) {
            ("seen", None)
        } else {
            ("pending", Some("receipt of an event not yet accepted"))
        })
    }

    fn reading(&self, ident: Option<&Ident>) -> Result<Reading, OpError> {
        match ident {
            None => Ok(("rejected", None)),
            Some(Ident::Event(event, said)) => self.event_reading(event, said),
            Some(Ident::Receipt {
                id,
                sn,
                said,
                sigs,
                transferable,
            }) => self.receipt_reading(id, *sn, said, sigs, *transferable),
        }
    }
}

/// The key state keri-core holds, each threshold and list in keri-core's own serialization.
fn key_state(state: &IdentifierState) -> Value {
    let held = serde_json::to_value(state).unwrap_or(Value::Null);
    let field = |k: &str| held.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "sn": state.sn,
        "said": state.last_event_digest.said.to_string(),
        "keys": field("k"),
        "kt": field("kt"),
        "ndigs": field("n"),
        "nt": field("nt"),
        "wits": field("b"),
        "bt": field("bt"),
        "delegator": state.delegator.as_ref().map(|d| d.to_string()),
    })
}

/// A reading with its informative reason: the escrow for a pending message, and keri-core's
/// refusal for a rejected one.
fn with_reason(reading: Reading, refusal: Option<&String>) -> (&'static str, Option<String>) {
    let reason = match reading {
        (_, Some(escrow)) => Some(escrow.to_string()),
        ("rejected", None) => refusal.cloned(),
        _ => None,
    };
    (reading.0, reason)
}

/// Deliver `streams` in order to a fresh keriox validator and report every disposition and the
/// key state of every identifier it holds seen events for.
pub fn process(streams: Vec<Vec<u8>>) -> Result<Value, OpError> {
    let validator = Validator::new()?;
    let idents: Vec<Option<Ident>> = streams.iter().map(|s| identify(s)).collect();
    let mut readings = Vec::with_capacity(streams.len());
    for (stream, ident) in streams.iter().zip(&idents) {
        let refusal = validator.deliver(stream);
        let initial = with_reason(validator.reading(ident.as_ref())?, refusal.as_ref());
        readings.push((initial, refusal));
    }
    let mut dispositions = Vec::with_capacity(streams.len());
    for (((initial, _), refusal), ident) in readings.iter().zip(&idents) {
        let (last, reason) = with_reason(validator.reading(ident.as_ref())?, refusal.as_ref());
        // keri-core has no superseding recovery, so a key event is on the trunk exactly when it
        // is seen; a receipt is never on the trunk.
        let trunk = last == "seen" && matches!(ident, Some(Ident::Event(..)));
        let mut entry = json!({"initial": initial, "final": last, "trunk": trunk});
        if let Some(reason) = reason {
            entry["reason"] = Value::String(reason);
        }
        dispositions.push(entry);
    }
    // The held key state of every identifier any delivered stream names a key event for.
    let mut named = BTreeSet::new();
    let mut key_states = serde_json::Map::new();
    for stream in &streams {
        for Message::Notice(notice) in parse_event_stream(stream).unwrap_or_default() {
            if let Notice::Event(event) = notice {
                let id = event.event_message.data.get_prefix();
                if named.insert(id.to_string()) {
                    if let Some(state) = validator.storage.get_state(&id) {
                        key_states.insert(id.to_string(), key_state(&state));
                    }
                }
            }
        }
    }
    Ok(json!({"dispositions": dispositions, "key_states": key_states}))
}
