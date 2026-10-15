//! KERI 1.x streams for the adapter's tests, built with devrandom's own builders, custodian and
//! encoders, so that every test stream is one devrandom itself emits. Deterministic: every key
//! comes from a fixed salt.

#![allow(dead_code)]

use std::str::FromStr;

use cesr::core::counter::CounterCodeV1;
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{MatterCode, SignatureCode};
use cesr::core::primitives::Siger;
use cesr::crypto::salt::{Salt, Tier};
use cesr_stream::encode::EncodeCount;
use cesr_stream::group::{ControllerIdxSigs, WitnessIdxSigs};
use keri::{Custodian, KeyCommitment, KeySpec, PathConvention, SaltyCustodian, SaltyParams};
use keri_codec::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder, SerializedEvent,
};
use keri_events::{BasicPrefix, Identifier, Said, Seal, SigningThreshold};
use cesr::core::primitives::Number;
use serde_json::{Value, json};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn salt(seed: u8) -> [u8; 16] {
    [seed; 16]
}

pub const fn spec(count: usize, ncount: usize) -> KeySpec {
    KeySpec {
        count,
        ncount,
        transferable: true,
    }
}

pub fn custodian(seed: u8) -> SaltyCustodian {
    SaltyCustodian::new(Salt::from_raw(&salt(seed)).unwrap(), Tier::Low, PathConvention::Keripy)
}

/// A non-transferable witness: one basic prefix that is its own key.
pub struct Witness {
    pub custodian: SaltyCustodian,
    pub prefix: BasicPrefix<'static>,
}

impl Witness {
    pub fn new(seed: u8) -> Self {
        let mut custodian = custodian(seed);
        let commitment = custodian
            .incept(KeySpec {
                count: 1,
                ncount: 0,
                transferable: false,
            })
            .unwrap();
        let prefix = BasicPrefix::from_matter(commitment.verkeys[0].as_matter().clone());
        Self { custodian, prefix }
    }

    /// The witness's signature over `body`, indexed at `position` in the witness set.
    pub fn wig(&self, body: &[u8], position: u32) -> Siger<'static> {
        self.custodian.sign(body, Some(&[position])).unwrap().remove(0)
    }

    /// The witness's unindexed signature over `body`, as qb64.
    pub fn cigar(&self, body: &[u8]) -> String {
        let raw = self.wig(body, 0).raw().to_vec();
        MatterBuilder::new()
            .with_code(SignatureCode::Ed25519Sig)
            .with_raw(raw)
            .unwrap()
            .build()
            .unwrap()
            .to_qb64()
    }
}

/// One controller's KEL under construction.
pub struct Controller {
    pub seed: u8,
    pub custodian: SaltyCustodian,
    pub id: Identifier<'static>,
    pub commitment: KeyCommitment,
    pub last: Said<'static>,
    pub sn: u128,
    pub witnesses: Vec<BasicPrefix<'static>>,
    /// The custodian's derivation state before each rotation, so a test can fork the KEL.
    pub history: Vec<SaltyParams>,
}

pub struct Options {
    pub spec: KeySpec,
    pub threshold: Option<SigningThreshold>,
    pub witnesses: Vec<BasicPrefix<'static>>,
    pub toad: Option<u32>,
    pub delegator: Option<Identifier<'static>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            spec: spec(1, 1),
            threshold: None,
            witnesses: Vec::new(),
            toad: None,
            delegator: None,
        }
    }
}

impl Controller {
    pub fn incept(seed: u8, options: Options) -> (Self, SerializedEvent) {
        let mut custodian = custodian(seed);
        let params = custodian.params();
        let commitment = custodian.incept(options.spec).unwrap();
        let event = match &options.delegator {
            None => {
                let mut b = InceptionBuilder::new()
                    .keys(commitment.verkeys.clone())
                    .next_keys(commitment.next_digests.clone())
                    .witnesses(options.witnesses.clone());
                if let Some(t) = options.threshold.clone() {
                    b = b.threshold(t.clone()).next_threshold(t);
                }
                if let Some(toad) = options.toad {
                    b = b.witness_threshold(toad);
                }
                b.build().unwrap()
            }
            Some(delegator) => {
                let mut b = DelegatedInceptionBuilder::new(delegator.clone())
                    .keys(commitment.verkeys.clone())
                    .next_keys(commitment.next_digests.clone())
                    .witnesses(options.witnesses.clone());
                if let Some(t) = options.threshold.clone() {
                    b = b.threshold(t.clone()).next_threshold(t);
                }
                if let Some(toad) = options.toad {
                    b = b.witness_threshold(toad);
                }
                b.build().unwrap()
            }
        };
        let id = event.identifier().unwrap();
        let controller = Self {
            seed,
            custodian,
            id,
            commitment,
            last: event.said().clone(),
            sn: 0,
            witnesses: options.witnesses,
            history: vec![params],
        };
        (controller, event)
    }

    pub fn prefix(&self) -> String {
        match &self.id {
            Identifier::Basic(b) => b.to_qb64(),
            Identifier::SelfAddressing(s) => s.to_qb64(),
        }
    }

    pub fn ixn(&mut self, anchors: Vec<Seal<'static>>) -> SerializedEvent {
        let event = InteractionBuilder::new()
            .prefix(self.id.clone())
            .prior_event_said(self.last.clone())
            .sn(self.sn + 1)
            .anchors(anchors)
            .build()
            .unwrap();
        self.sn += 1;
        self.last = event.said().clone();
        event
    }

    pub fn rot(&mut self, delegated: bool, anchors: Vec<Seal<'static>>) -> SerializedEvent {
        self.history.push(self.custodian.params());
        let commitment = self.custodian.rotate(spec(1, 1)).unwrap();
        let event = if delegated {
            DelegatedRotationBuilder::new()
                .prefix(self.id.clone())
                .prior_event_said(self.last.clone())
                .keys(commitment.verkeys.clone())
                .prior_witnesses(self.witnesses.clone())
                .sn(self.sn + 1)
                .next_keys(commitment.next_digests.clone())
                .anchors(anchors)
                .build()
                .unwrap()
        } else {
            RotationBuilder::new()
                .prefix(self.id.clone())
                .prior_event_said(self.last.clone())
                .keys(commitment.verkeys.clone())
                .prior_witnesses(self.witnesses.clone())
                .sn(self.sn + 1)
                .next_keys(commitment.next_digests.clone())
                .anchors(anchors)
                .build()
                .unwrap()
        };
        self.commitment = commitment;
        self.sn += 1;
        self.last = event.said().clone();
        event
    }

    /// The controller's indexed signatures over `event`, all of them.
    pub fn sigs(&self, event: &SerializedEvent) -> Vec<Siger<'static>> {
        self.custodian.sign(event.as_bytes(), None).unwrap()
    }

    /// `event` with every controller signature, framed by devrandom (`-V` around `-A`).
    pub fn frame(&self, event: &SerializedEvent) -> Vec<u8> {
        frame(event, &self.sigs(event), &[])
    }

    /// The event seal of this controller's latest event, to anchor it in a delegator's KEL.
    pub fn seal(&self) -> Seal<'static> {
        Seal::Event {
            i: self.id.clone(),
            s: Number::new(self.sn),
            d: self.last.clone(),
        }
    }
}

/// `event` framed by devrandom with these controller and witness signatures.
pub fn frame(event: &SerializedEvent, sigs: &[Siger<'_>], wigs: &[Siger<'_>]) -> Vec<u8> {
    let sigs = ControllerIdxSigs::from_indexed_signatures(sigs).unwrap();
    if wigs.is_empty() {
        event.frame_v1(&sigs, None).unwrap()
    } else {
        let wigs = WitnessIdxSigs::from_indexed_signatures(wigs).unwrap();
        event.frame_v1(&sigs, Some(&wigs)).unwrap()
    }
}

/// `event`'s body followed by these bare (unframed) groups, as keripy 1.x writes them.
pub fn bare(event: &SerializedEvent, groups: &[String]) -> Vec<u8> {
    let mut out = event.as_bytes().to_vec();
    for group in groups {
        out.extend_from_slice(group.as_bytes());
    }
    out
}

pub fn count(code: CounterCodeV1, n: u32) -> String {
    String::from_utf8(code.encode_count(n).unwrap()).unwrap()
}

/// An `-A` group of these signatures.
pub fn sig_group(sigs: &[Siger<'_>]) -> String {
    let mut s = count(CounterCodeV1::ControllerIdxSigs, u32::try_from(sigs.len()).unwrap());
    for sig in sigs {
        s.push_str(&sig.to_qb64());
    }
    s
}

/// A `-B` group of these witness signatures.
pub fn wig_group(wigs: &[Siger<'_>]) -> String {
    let mut s = count(CounterCodeV1::WitnessIdxSigs, u32::try_from(wigs.len()).unwrap());
    for wig in wigs {
        s.push_str(&wig.to_qb64());
    }
    s
}

/// The qb64 of a sequence number primitive (`0A`, 16 raw bytes), as keripy's Seqner writes it.
pub fn seqner(sn: u128) -> String {
    let code = MatterCode::from_str("0A").unwrap();
    MatterBuilder::new()
        .with_code(code)
        .with_raw(sn.to_be_bytes().to_vec())
        .unwrap()
        .build()
        .unwrap()
        .to_qb64()
}

/// A `-G` group of one seal-source couple naming (sn, said).
pub fn seal_group(sn: u128, said: &str) -> String {
    format!("{}{}{said}", count(CounterCodeV1::SealSourceCouples, 1), seqner(sn))
}

/// A `-E` group of one first-seen replay couple.
pub fn first_seen_group(fn_: u128) -> String {
    let dater = "1AAG2020-08-22T17c50c09d988921p00c00";
    format!("{}{}{dater}", count(CounterCodeV1::FirstSeenReplayCouples, 1), seqner(fn_))
}

/// A KERI 1.0 JSON receipt body naming (prefix, sn, said), in keripy's field order.
pub fn receipt_body(prefix: &str, sn: u128, said: &str) -> Vec<u8> {
    let make = |size: usize| {
        format!(
            "{{\"v\":\"KERI10JSON{size:06x}_\",\"t\":\"rct\",\"d\":\"{said}\",\"i\":\"{prefix}\",\"s\":\"{sn:x}\"}}"
        )
    };
    let size = make(0).len();
    make(size).into_bytes()
}

/// A receipt message: a body and these bare groups.
pub fn receipt(prefix: &str, sn: u128, said: &str, groups: &[String]) -> Vec<u8> {
    let mut out = receipt_body(prefix, sn, said);
    for group in groups {
        out.extend_from_slice(group.as_bytes());
    }
    out
}

/// A `-C` group of one non-transferable receipt couple.
pub fn couple_group(witness: &Witness, body: &[u8]) -> String {
    format!(
        "{}{}{}",
        count(CounterCodeV1::NonTransReceiptCouples, 1),
        witness.prefix.to_qb64(),
        witness.cigar(body)
    )
}

pub fn request(messages: &[Vec<u8>]) -> Value {
    json!({
        "id": 3,
        "op": "keri.process",
        "perspective": {"role": "validator"},
        "messages": messages.iter().map(|m| json!({"stream": hex(m), "source": "test"})).collect::<Vec<_>>(),
    })
}

/// Run keri.process over `messages` and return its result.
pub fn process(messages: &[Vec<u8>]) -> Value {
    let request = request(messages);
    let response =
        kcs_adapter_devrandom::protocol::handle_line(&serde_json::to_vec(&request).unwrap());
    assert!(response.get("result").is_some(), "{response}");
    response["result"].clone()
}

/// The (initial, final, trunk) readings of each message.
pub fn readings(result: &Value) -> Vec<(String, String, bool)> {
    result["dispositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["initial"].as_str().unwrap().to_string(),
                d["final"].as_str().unwrap().to_string(),
                d["trunk"].as_bool().unwrap(),
            )
        })
        .collect()
}

pub fn r(initial: &str, last: &str, trunk: bool) -> (String, String, bool) {
    (initial.to_string(), last.to_string(), trunk)
}

/// A `-F` group of one transferable endorsement by `endorser` (its event at `sn` with `said`),
/// signing `body`.
pub fn endorsement_group(endorser: &Controller, sn: u128, said: &str, body: &[u8]) -> String {
    let sigs = endorser.custodian.sign(body, None).unwrap();
    format!(
        "{}{}{}{said}{}",
        count(CounterCodeV1::TransIdxSigGroups, 1),
        endorser.prefix(),
        seqner(sn),
        sig_group(&sigs)
    )
}

/// A registry inception (`vcp`) by `issuer`, signed: a message that is not a key event or receipt.
pub fn registry_inception(issuer: &Controller) -> Vec<u8> {
    use cesr::core::matter::code::NoncerCode;
    let nonce = MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(vec![7u8; 16])
        .unwrap()
        .build()
        .unwrap();
    let vcp = keri_codec::RegistryInceptionBuilder::new(issuer.id.clone(), nonce)
        .build()
        .unwrap();
    frame(&vcp, &issuer.sigs(&vcp), &[])
}
