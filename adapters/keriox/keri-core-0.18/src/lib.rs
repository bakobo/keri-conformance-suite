//! The keriox adapter for the KERI conformance suite, keri-core 0.18.0 build. See ../README.md.
//!
//! `protocol` is the 0.17.13 build's file, shared because it touches no keriox API; `cesr` and
//! `line` are this build's own.

pub mod cesr;
pub mod line;
#[path = "../../src/protocol.rs"]
pub mod protocol;
