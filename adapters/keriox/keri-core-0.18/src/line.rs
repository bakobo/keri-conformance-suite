//! What this build offers: the keri-core 0.18.0 line, with cesrox 2.0.0-beta.8 and said 0.5.4.
//! ../README.md ("The keri-core 0.18.0 build") says why each feature is or is not declared.

use serde_json::Value;

use crate::protocol::OpError;

/// A build's `keri.process`: the streams of one request, delivered in order to a fresh validator.
pub type Process = fn(Vec<Vec<u8>>) -> Result<Value, OpError>;

pub const OPERATIONS: &[&str] = &["cesr.parse", "cesr.encode"];

/// Drawn from profiles/features.json.
pub const FEATURES: &[&str] = &[
    "cesr.genus-2.00",
    "cesr.serialization.json",
    "keri.version-1.x",
];

/// None: keri-core 0.18.0 reads only KERI 1.x bodies with cesrox 2.0 attachments, a pairing no
/// profile has a keri.process case for, so this build does not offer keri.process.
pub const PROCESS: Option<Process> = None;
