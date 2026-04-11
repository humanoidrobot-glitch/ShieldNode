//! Shared types and cryptographic utilities for ShieldNode.
//!
//! Consumed by both the relay node (`node/`) and the Tauri client
//! (`client/src-tauri/`). Extracted to eliminate code duplication.

pub mod aead;
pub mod eip712;
pub mod hop_codec;
pub mod kdf;
pub mod sphinx;
