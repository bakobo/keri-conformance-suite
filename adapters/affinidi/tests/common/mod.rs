//! Builds KERI 1.x and 2.x JSON events for the keri.process tests, from Affinidi's own primitives:
//! its SAID computation, its order-keeping `SadValue`, its Serder for the version string, and its
//! Signer. Nothing here is graded; it only
//! makes inputs, and the tests say which of them Affinidi is expected to accept.

#![allow(dead_code)]

use affinidi_cesr::Matter;
use affinidi_keri_core::sad;
pub use affinidi_keri_core::sad::SadValue;
use affinidi_keri_core::said::compute_said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_crypto::Diger;
pub use affinidi_keri_crypto::Signer;

const DUMMY: &str = "############################################";

/// A deterministic Ed25519 signer from one seed byte.
pub fn signer(seed: u8) -> Signer {
    Signer::new("A", vec![seed; 32]).unwrap()
}

/// A deterministic non-transferable Ed25519 signer, for witnesses.
pub fn witness(seed: u8) -> Signer {
    Signer::new_with_transferable("A", vec![seed; 32], false).unwrap()
}

pub fn key(signer: &Signer) -> String {
    signer.verfer().qb64().unwrap()
}

/// The next-key commitment to a signer's key: the Blake3 digest of its qb64.
pub fn commit(signer: &Signer) -> String {
    Diger::from_data("E", key(signer).as_bytes())
        .unwrap()
        .qb64()
        .unwrap()
}

/// A 1.x version string, which Serder sizes.
pub const V1: &str = "KERI10JSON000000_";
/// A 2.00 version string (protocol 2.0, genus 2.0), which Serder sizes.
pub const V2: &str = "KERICAACAAJSONAAAA.";

/// Finish a 1.x body: a version string of the right size, then its SAID in `d` (and in `i` when
/// `self_addressing`), computed the way Affinidi verifies it.
pub fn finish(sad: SadValue, self_addressing: bool) -> Serder {
    finish_as(V1, sad, self_addressing)
}

/// Finish a body under the given version string, as `finish` does.
pub fn finish_as(version: &str, mut sad: SadValue, self_addressing: bool) -> Serder {
    sad["v"] = version.into();
    sad["d"] = DUMMY.into();
    if self_addressing {
        sad["i"] = DUMMY.into();
    }
    let sized = Serder::new(SerializationKind::Json, sad).unwrap();
    let mut sad = sized.sad().clone();
    compute_said(&mut sad, "d", "E", SerializationKind::Json).unwrap();
    Serder::new(SerializationKind::Json, sad).unwrap()
}

/// A body with a sized version string and nothing else filled in: no SAID is computed.
pub fn bare(mut sad: SadValue) -> Serder {
    sad["v"] = V1.into();
    Serder::new(SerializationKind::Json, sad).unwrap()
}

pub fn said(serder: &Serder) -> String {
    serder.said().unwrap()
}

/// `-A` controller signatures by the signers at the given indexes, each indexed into both the
/// current key list and the prior next-key list (`only` false, keripy's default).
pub fn sigs(serder: &Serder, signers: &[(&Signer, usize)]) -> String {
    format!("-A{}{}", count(signers.len()), indexed(serder, signers))
}

/// The same signatures as a 2.00 `-K` group, which counts quadlets rather than items.
pub fn sigs_v2(serder: &Serder, signers: &[(&Signer, usize)]) -> String {
    let body = indexed(serder, signers);
    format!("-K{}{body}", count(body.len() / 4))
}

fn indexed(serder: &Serder, signers: &[(&Signer, usize)]) -> String {
    let mut out = String::new();
    for (signer, index) in signers {
        out += &signer
            .sign_indexed(serder.raw(), *index, false)
            .unwrap()
            .qb64()
            .unwrap();
    }
    out
}

/// `-B` witness indexed signatures.
pub fn wigs(serder: &Serder, signers: &[(&Signer, usize)]) -> String {
    format!("-B{}{}", count(signers.len()), indexed(serder, signers))
}

/// `-C` non-transferable receipt couples.
pub fn couples(serder: &Serder, witnesses: &[&Signer]) -> String {
    let mut out = format!("-C{}", count(witnesses.len()));
    for w in witnesses {
        out += &key(w);
        out += &w.sign(serder.raw()).unwrap().qb64().unwrap();
    }
    out
}

/// A `-G` seal source couple naming an anchoring event.
pub fn seal_source(sn: u64, said: &str) -> String {
    let mut raw = vec![0u8; 8];
    raw.extend_from_slice(&sn.to_be_bytes());
    format!(
        "-GAB{}{said}",
        Matter::new("0A", raw).unwrap().qb64().unwrap()
    )
}

fn count(n: usize) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    format!("{}{}", B64[n / 64] as char, B64[n % 64] as char)
}

/// The stream of a body with its attachments, as the hex the protocol carries.
pub fn stream(serder: &Serder, attachments: &[String]) -> String {
    let mut bytes = serder.raw().to_vec();
    for a in attachments {
        bytes.extend_from_slice(a.as_bytes());
    }
    hex(&bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Icp<'a> {
    pub keys: &'a [&'a Signer],
    pub kt: SadValue,
    pub next: &'a [&'a Signer],
    pub nt: SadValue,
    pub wits: &'a [&'a Signer],
    pub bt: &'a str,
}

impl<'a> Icp<'a> {
    pub fn single(key: &'a [&'a Signer], next: &'a [&'a Signer]) -> Self {
        Icp {
            keys: key,
            kt: "1".into(),
            next,
            nt: "1".into(),
            wits: &[],
            bt: "0",
        }
    }

    pub fn body(&self, t: &str, delegator: Option<&str>) -> Serder {
        self.body_as(V1, t, delegator, &[])
    }

    /// An inception under the given version string, carrying the given configuration traits.
    pub fn body_as(
        &self,
        version: &str,
        t: &str,
        delegator: Option<&str>,
        traits: &[&str],
    ) -> Serder {
        let mut sad = sad!({
            "v": "", "t": t, "d": "", "i": "", "s": "0",
            "kt": self.kt,
            "k": self.keys.iter().map(|s| key(s)).collect::<Vec<_>>(),
            "nt": self.nt,
            "n": self.next.iter().map(|s| commit(s)).collect::<Vec<_>>(),
            "bt": self.bt,
            "b": self.wits.iter().map(|s| key(s)).collect::<Vec<_>>(),
            "c": traits, "a": []
        });
        if let Some(di) = delegator {
            sad["di"] = di.into();
        }
        finish_as(version, sad, true)
    }

    pub fn icp(&self) -> Serder {
        self.body("icp", None)
    }

    pub fn dip(&self, delegator: &str) -> Serder {
        self.body("dip", Some(delegator))
    }
}

pub fn ixn(pre: &str, sn: u64, prior: &str, anchors: SadValue) -> Serder {
    ixn_as(V1, pre, sn, prior, anchors)
}

pub fn ixn_as(version: &str, pre: &str, sn: u64, prior: &str, anchors: SadValue) -> Serder {
    finish_as(
        version,
        sad!({"v": "", "t": "ixn", "d": "", "i": pre, "s": format!("{sn:x}"), "p": prior,
              "a": anchors}),
        false,
    )
}

/// A 1.x rotation in keripy's form, which has no `c`. With `with_c` true it carries one, the form
/// Affinidi wrote before 0.6.0.
pub fn rot(
    pre: &str,
    sn: u64,
    prior: &str,
    keys: &[&Signer],
    next: &[&Signer],
    with_c: bool,
) -> Serder {
    let mut sad = sad!({
        "v": "", "t": "rot", "d": "", "i": pre, "s": format!("{sn:x}"), "p": prior,
        "kt": "1", "k": keys.iter().map(|s| key(s)).collect::<Vec<_>>(),
        "nt": "1", "n": next.iter().map(|s| commit(s)).collect::<Vec<_>>(),
        "bt": "0", "br": [], "ba": []
    });
    if with_c {
        sad["c"] = SadValue::Array(vec![]);
    }
    sad["a"] = SadValue::Array(vec![]);
    finish(sad, false)
}

/// A 1.x delegated rotation in keripy's form, which names no delegator and has no `c`.
pub fn drt(pre: &str, sn: u64, prior: &str, keys: &[&Signer], next: &[&Signer]) -> Serder {
    finish(
        sad!({
            "v": "", "t": "drt", "d": "", "i": pre, "s": format!("{sn:x}"), "p": prior,
            "kt": "1", "k": keys.iter().map(|s| key(s)).collect::<Vec<_>>(),
            "nt": "1", "n": next.iter().map(|s| commit(s)).collect::<Vec<_>>(),
            "bt": "0", "br": [], "ba": [], "a": []
        }),
        false,
    )
}

/// A non-transferable receipt message for an event, with the witnesses' couples attached.
pub fn rct(event: &Serder, witnesses: &[&Signer]) -> String {
    let body = finish(
        sad!({"v": "", "t": "rct", "d": "", "i": event.prefix().unwrap(),
              "s": format!("{:x}", event.sn().unwrap())}),
        false,
    );
    // keripy's rct carries the receipted event's SAID in d, not its own.
    let mut sad = body.sad().clone();
    sad["d"] = said(event).into();
    let body = Serder::new(SerializationKind::Json, sad).unwrap();
    stream(&body, &[couples(event, witnesses)])
}
