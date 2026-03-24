use std::net::SocketAddr;

use boringtun::noise::{Tunn, TunnResult};
use thiserror::Error;

// ── errors ─────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WireguardError {
    #[error("tunnel creation failed: {0}")]
    TunnelCreation(String),
    #[error("encapsulation failed")]
    EncapsulateFailed,
    #[error("decapsulation failed")]
    DecapsulateFailed,
    #[error("buffer too small")]
    BufferTooSmall,
}

// ── tunnel wrapper ─────────────────────────────────────────────────────

/// Thin wrapper around boringtun's [`Tunn`].
///
/// We accept raw 32-byte arrays on the public API and convert internally
/// to boringtun's `x25519-dalek` types so there is no version-mismatch.
pub struct WireguardTunnel {
    tunnel: Tunn,
    local_public_key: [u8; 32],
}

impl WireguardTunnel {
    pub fn new(
        local_private_key: [u8; 32],
        peer_public_key: [u8; 32],
        _peer_endpoint: Option<SocketAddr>,
    ) -> Self {
        let secret = x25519_dalek::StaticSecret::from(local_private_key);
        let local_public_key = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let peer = x25519_dalek::PublicKey::from(peer_public_key);

        let index: u32 = rand::random();
        let tunnel = Tunn::new(secret, peer, None, None, index, None);

        Self {
            tunnel,
            local_public_key,
        }
    }

    /// Encapsulate an outgoing IP packet into a WireGuard message.
    pub fn handle_outgoing<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a [u8], WireguardError> {
        match self.tunnel.encapsulate(src, dst) {
            TunnResult::Done => Err(WireguardError::EncapsulateFailed),
            TunnResult::WriteToNetwork(data) => Ok(data),
            TunnResult::Err(e) => {
                Err(WireguardError::TunnelCreation(format!("{e:?}")))
            }
            _ => Err(WireguardError::EncapsulateFailed),
        }
    }

    /// Decapsulate an incoming WireGuard message.
    ///
    /// Returns the number of bytes written into `dst`.
    pub fn handle_incoming(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, WireguardError> {
        match self.tunnel.decapsulate(None, src, dst) {
            TunnResult::Done => Ok(0),
            TunnResult::WriteToTunnelV4(data, _)
            | TunnResult::WriteToTunnelV6(data, _) => Ok(data.len()),
            TunnResult::WriteToNetwork(data) => Ok(data.len()),
            TunnResult::Err(e) => {
                Err(WireguardError::TunnelCreation(format!("{e:?}")))
            }
        }
    }

    pub fn local_public_key(&self) -> [u8; 32] {
        self.local_public_key
    }
}

// Tunn contains interior mutable state and is Send but not Sync.
// WireguardTunnel is single-owner (&mut self on all mutation methods)
// so Send is safe. We do not implement Sync.
unsafe impl Send for WireguardTunnel {}
