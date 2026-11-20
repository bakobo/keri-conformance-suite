//! What this build offers: the keri-core 0.17.13 line, with cesrox 0.1.8 and said 0.4.3.
//! README.md says why each feature is or is not declared.

use serde_json::Value;

use crate::protocol::OpError;

/// A build's `keri.process`: the streams of one request, delivered in order to a fresh validator.
pub type Process = fn(Vec<Vec<u8>>) -> Result<Value, OpError>;

pub const OPERATIONS: &[&str] = &["cesr.parse", "cesr.encode", "keri.process"];

/// Drawn from profiles/features.json.
pub const FEATURES: &[&str] = &[
    "cesr.genus-1.00",
    "cesr.serialization.json",
    "crypto.ed25519",
    "kel.basic",
    "kel.delegation",
    "kel.multisig.numeric",
    "kel.multisig.weighted",
    "kel.nontransferable",
    "kel.partial-rotation",
    "kel.witness",
    "keri.duplicity",
    "keri.escrow",
    "keri.routing",
    "keri.version-1.x",
];

/// keri-core 0.17.13's own processor (see `kel`).
pub const PROCESS: Option<Process> = Some(crate::kel::process);
