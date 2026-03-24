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
    /// Raw bytes of our static secret (32 bytes).
    local_private_key: [u8; 32],
    /// Raw bytes of the peer's public key.
    _peer_public_key: [u8; 32],
}

impl WireguardTunnel {
    /// Create a new tunnel instance.
    ///
    /// `local_private_key` is a 32-byte X25519 static secret.
    /// `peer_public_key`   is the remote peer's 32-byte public key.
    pub fn new(
        local_private_key: [u8; 32],
        peer_public_key: [u8; 32],
        _peer_endpoint: Option<SocketAddr>,
    ) -> Self {
        // Convert raw bytes into the types boringtun expects.
        let secret = x25519_dalek::StaticSecret::from(local_private_key);
        let peer = x25519_dalek::PublicKey::from(peer_public_key);

        let preshared_key = None;
        let keep_alive = None;
        let index: u32 = rand::random();

        let tunnel = Tunn::new(secret, peer, preshared_key, keep_alive, index, None);

        Self {
            tunnel,
            local_private_key,
            _peer_public_key: peer_public_key,
        }
    }

    /// Encapsulate an outgoing IP packet into a WireGuard message.
    ///
    /// Returns the WireGuard-encoded bytes written into `dst`.
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

    /// Decapsulate an incoming WireGuard message to recover the inner IP
    /// packet.
    ///
    /// On success returns the plaintext bytes written into `dst`.
    pub fn handle_incoming<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a [u8], WireguardError> {
        match self.tunnel.decapsulate(None, src, dst) {
            TunnResult::Done => Ok(&dst[..0]),
            TunnResult::WriteToTunnelV4(data, _)
            | TunnResult::WriteToTunnelV6(data, _) => Ok(data),
            TunnResult::WriteToNetwork(data) => {
                // Handshake response — caller should send `data` back.
                Ok(data)
            }
            TunnResult::Err(e) => {
                Err(WireguardError::TunnelCreation(format!("{e:?}")))
            }
        }
    }

    /// Obtain the local public key as raw 32 bytes.
    pub fn local_public_key(&self) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(self.local_private_key);
        let public = x25519_dalek::PublicKey::from(&secret);
        public.to_bytes()
    }
}

// Tunn is Send but not Sync (interior mutable state) — fine for our
// single-owner design.
unsafe impl Send for WireguardTunnel {}
